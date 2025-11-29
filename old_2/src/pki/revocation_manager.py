"""
Revocation Manager
Gère la révocation des certificats (CRL et simulation OCSP)
"""

from pathlib import Path
from datetime import timedelta
from typing import Optional, List, Dict, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import config, utils
from .keygen import PrivateKeyTypes
from .database import PKIDatabase


class RevocationManager:
    """
    Gestionnaire de révocation
    Génère des CRL et simule un répondeur OCSP
    """

    def __init__(self, db: Optional[PKIDatabase] = None):
        self.db = db or PKIDatabase()

    # ============================================
    # 📋 GESTION CRL
    # ============================================

    def generate_crl(
            self,
            issuer_cert: x509.Certificate,
            issuer_key: PrivateKeyTypes,
            validity_hours: Optional[int] = None
    ) -> Tuple[x509.CertificateRevocationList, Path]:
        """
        Génère une Certificate Revocation List (CRL)

        Args:
            issuer_cert: Certificat de l'émetteur (CA)
            issuer_key: Clé privée de l'émetteur
            validity_hours: Durée de validité en heures

        Returns:
            tuple: (CRL, chemin_fichier)
        """
        utils.print_header("📋 Génération de la CRL")

        if validity_hours is None:
            validity_hours = config.CRL_VALIDITY_HOURS

        # Récupérer les certificats révoqués
        revoked_certs = self._get_revoked_certificates()

        utils.print_info(f"Certificats révoqués trouvés: {len(revoked_certs)}")

        # Builder CRL
        now = utils.now_utc()
        next_update = now + timedelta(hours=validity_hours)

        crl_builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer_cert.subject)
            .last_update(now)
            .next_update(next_update)
        )

        # Ajouter les certificats révoqués
        for cert_info in revoked_certs:
            serial = int(cert_info['serial_number'], 16)
            revocation_date = utils.parse_datetime(
                cert_info['revoked_at'],
                "%Y-%m-%dT%H:%M:%S.%f%z"
            ) if 'T' in cert_info['revoked_at'] else utils.parse_datetime(
                cert_info['revoked_at'],
                "%Y-%m-%d %H:%M:%S"
            )

            # Mapper la raison
            reason_map = {
                "unspecified": x509.ReasonFlags.unspecified,
                "key_compromise": x509.ReasonFlags.key_compromise,
                "ca_compromise": x509.ReasonFlags.ca_compromise,
                "affiliation_changed": x509.ReasonFlags.affiliation_changed,
                "superseded": x509.ReasonFlags.superseded,
                "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
                "certificate_hold": x509.ReasonFlags.certificate_hold,
                "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
            }

            reason = reason_map.get(
                cert_info.get('revocation_reason', 'unspecified'),
                x509.ReasonFlags.unspecified
            )

            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revocation_date)
                .add_extension(
                    x509.CRLReason(reason),
                    critical=False
                )
                .build()
            )

            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        # Signer la CRL
        crl = crl_builder.sign(issuer_key, hashes.SHA256())

        # Sauvegarder
        crl_path = self._save_crl(crl)

        # Mettre à jour la BDD
        self._mark_crl_published(revoked_certs)

        utils.print_success(f"✅ CRL générée: {len(revoked_certs)} certificats révoqués")
        utils.print_info(f"Valide jusqu'à: {next_update.strftime('%Y-%m-%d %H:%M:%S %Z')}")

        return crl, crl_path

    def _get_revoked_certificates(self) -> List[Dict]:
        """Récupère les certificats révoqués depuis la BDD"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.serial_number, c.revoked_at, c.revocation_reason
                FROM certificates c
                WHERE c.status = 'revoked'
            """)
            return [dict(row) for row in cursor.fetchall()]

    def _save_crl(self, crl: x509.CertificateRevocationList) -> Path:
        """Sauvegarde la CRL"""
        crl_path = config.get_crl_path()
        pem_data = crl.public_bytes(serialization.Encoding.PEM)

        with open(crl_path, 'wb') as f:
            f.write(pem_data)

        utils.set_file_permissions(crl_path, config.CERT_PERMISSIONS)
        file_info = utils.get_file_info(crl_path)
        utils.print_success(f"CRL sauvegardée: {crl_path.name} ({file_info.get('size', 'N/A')})")

        return crl_path

    def _mark_crl_published(self, revoked_certs: List[Dict]):
        """Marque les révocations comme publiées dans la CRL"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            for cert in revoked_certs:
                cursor.execute("""
                    UPDATE revocations
                    SET crl_published = 1
                    WHERE serial_number = ?
                """, (cert['serial_number'],))

    def load_crl(self, crl_path: Optional[Path] = None) -> x509.CertificateRevocationList:
        """Charge une CRL depuis un fichier"""
        if crl_path is None:
            crl_path = config.get_crl_path()

        if not crl_path.exists():
            raise FileNotFoundError(f"CRL introuvable: {crl_path}")

        with open(crl_path, 'rb') as f:
            crl_pem = f.read()

        crl = x509.load_pem_x509_crl(crl_pem)
        utils.print_success(f"CRL chargée: {crl_path.name}")

        return crl

    def check_certificate_in_crl(
            self,
            certificate: x509.Certificate,
            crl: Optional[x509.CertificateRevocationList] = None
    ) -> bool:
        """
        Vérifie si un certificat est dans la CRL

        Returns:
            bool: True si révoqué
        """
        if crl is None:
            try:
                crl = self.load_crl()
            except FileNotFoundError:
                utils.print_warning("CRL non disponible")
                return False

        # Chercher le certificat dans la CRL
        for revoked in crl:
            if revoked.serial_number == certificate.serial_number:
                utils.print_error(f"❌ Certificat RÉVOQUÉ (SN: {certificate.serial_number:X})")
                return True

        utils.print_success(f"✅ Certificat valide (non révoqué)")
        return False

    # ============================================
    # 🔍 SIMULATION OCSP
    # ============================================

    def ocsp_check(self, serial_number: str) -> Dict:
        """
        Simule une vérification OCSP

        Args:
            serial_number: Numéro de série (hex)

        Returns:
            dict: Statut OCSP
        """
        utils.print_info(f"🔍 Vérification OCSP pour SN: {serial_number[:16]}...")

        # Vérifier dans la BDD
        cert = self.db.get_certificate(serial_number)

        if not cert:
            return {
                "status": "unknown",
                "message": "Certificat inconnu",
                "serial_number": serial_number
            }

        if cert['status'] == 'revoked':
            return {
                "status": "revoked",
                "message": "Certificat révoqué",
                "serial_number": serial_number,
                "revocation_time": cert['revoked_at'],
                "revocation_reason": cert['revocation_reason']
            }

        # Vérifier la validité
        now = utils.now_utc()
        not_before = utils.parse_datetime(cert['not_before'], "%Y-%m-%dT%H:%M:%S.%f%z")
        not_after = utils.parse_datetime(cert['not_after'], "%Y-%m-%dT%H:%M:%S.%f%z")

        if now < not_before:
            return {
                "status": "not_yet_valid",
                "message": "Certificat pas encore valide",
                "serial_number": serial_number,
                "valid_from": cert['not_before']
            }

        if now > not_after:
            return {
                "status": "expired",
                "message": "Certificat expiré",
                "serial_number": serial_number,
                "expired_on": cert['not_after']
            }

        return {
            "status": "good",
            "message": "Certificat valide",
            "serial_number": serial_number,
            "valid_until": cert['not_after']
        }

    def display_ocsp_response(self, response: Dict):
        """Affiche une réponse OCSP de manière formatée"""
        status = response['status']

        # Couleur selon le statut
        if status == "good":
            color = "green"
            icon = "✅"
        elif status in ["revoked", "expired"]:
            color = "red"
            icon = "❌"
        else:
            color = "yellow"
            icon = "⚠️"

        table = utils.create_table(
            f"🔍 Réponse OCSP",
            ["Champ", "Valeur"]
        )

        table.add_row("Statut", f"[{color}]{icon} {status.upper()}[/{color}]")
        table.add_row("Message", response['message'])
        table.add_row("Numéro de série", response['serial_number'][:32])

        # Infos supplémentaires selon le statut
        if 'revocation_time' in response:
            table.add_row("Révoqué le", response['revocation_time'])
            table.add_row("Raison", response.get('revocation_reason', 'N/A'))

        if 'valid_until' in response:
            table.add_row("Valide jusqu'à", response['valid_until'])

        if 'expired_on' in response:
            table.add_row("Expiré le", response['expired_on'])

        utils.console.print(table)

    # ============================================
    # 🎯 HELPERS
    # ============================================

    def revoke_certificate(
            self,
            serial_number: str,
            reason: str = "unspecified"
    ) -> bool:
        """
        Révoque un certificat

        Args:
            serial_number: Numéro de série
            reason: Raison de révocation

        Returns:
            bool: True si révoqué
        """
        return self.db.revoke_certificate(serial_number, reason)

    def list_revoked_certificates(self) -> List[Dict]:
        """Liste tous les certificats révoqués"""
        return self._get_revoked_certificates()

    def display_revoked_certificates(self):
        """Affiche les certificats révoqués de manière formatée"""
        revoked = self.list_revoked_certificates()

        if not revoked:
            utils.print_info("Aucun certificat révoqué")
            return

        table = utils.create_table(
            f"🚫 Certificats révoqués ({len(revoked)})",
            ["Numéro de série", "Date révocation", "Raison"]
        )

        for cert in revoked:
            serial_short = utils.truncate_string(cert['serial_number'], 20)
            revoked_date = cert['revoked_at'][:19].replace('T', ' ') if cert['revoked_at'] else 'N/A'
            reason = cert.get('revocation_reason', 'unspecified')

            table.add_row(serial_short, revoked_date, reason)

        utils.console.print(table)


revocation_manager = RevocationManager()

__all__ = ['RevocationManager', 'revocation_manager']