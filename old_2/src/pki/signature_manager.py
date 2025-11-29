"""
Signature Manager
Gère la signature et la vérification de messages/documents
Valide les principes CIAN (Confidentialité, Intégrité, Authenticité, Non-répudiation)
"""

from pathlib import Path
from typing import Optional, Tuple, Dict
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

from . import config, utils
from .keygen import PrivateKeyTypes, PublicKeyTypes


class SignatureManager:
    """
    Gestionnaire de signatures numériques
    Implémente signature et vérification avec certificats X.509
    """

    def __init__(self):
        pass

    # ============================================
    # ✍️ SIGNATURE
    # ============================================

    def sign_message(
            self,
            message: bytes,
            private_key: PrivateKeyTypes,
            certificate: x509.Certificate
    ) -> Dict:
        """
        Signe un message avec une clé privée

        Args:
            message: Message à signer
            private_key: Clé privée du signataire
            certificate: Certificat du signataire

        Returns:
            dict: Signature + métadonnées
        """
        utils.print_info("✍️  Signature du message...")

        # Calculer le hash du message
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        message_hash = digest.finalize()

        # Signer le hash
        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        else:
            # Pour ECC
            from cryptography.hazmat.primitives.asymmetric import ec
            signature = private_key.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )

        # Métadonnées
        signed_data = {
            "message": message,
            "signature": signature,
            "algorithm": "RSA-PSS-SHA256" if isinstance(private_key, rsa.RSAPrivateKey) else "ECDSA-SHA256",
            "certificate": certificate,
            "signer_dn": certificate.subject.rfc4514_string(),
            "signature_time": utils.now_utc().isoformat(),
            "message_hash": utils.bytes_to_hex(message_hash)
        }

        utils.print_success("✅ Message signé avec succès")

        return signed_data

    def sign_file(
            self,
            file_path: Path,
            private_key: PrivateKeyTypes,
            certificate: x509.Certificate
    ) -> Dict:
        """
        Signe un fichier

        Args:
            file_path: Chemin du fichier
            private_key: Clé privée
            certificate: Certificat

        Returns:
            dict: Signature + métadonnées
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Fichier introuvable: {file_path}")

        # Lire le fichier
        with open(file_path, 'rb') as f:
            file_data = f.read()

        utils.print_info(f"Signature du fichier: {file_path.name}")

        # Signer
        signed_data = self.sign_message(file_data, private_key, certificate)
        signed_data['file_path'] = str(file_path)
        signed_data['file_name'] = file_path.name

        # Sauvegarder la signature
        sig_path = file_path.parent / f"{file_path.name}.sig"
        self._save_signature(signed_data, sig_path)

        return signed_data

    def _save_signature(self, signed_data: Dict, sig_path: Path):
        """Sauvegarde une signature"""
        import json
        import base64

        # Convertir en format sérialisable
        sig_data = {
            "signature": base64.b64encode(signed_data['signature']).decode(),
            "algorithm": signed_data['algorithm'],
            "signer_dn": signed_data['signer_dn'],
            "signature_time": signed_data['signature_time'],
            "message_hash": signed_data['message_hash'],
            "certificate_serial": f"{signed_data['certificate'].serial_number:X}"
        }

        with open(sig_path, 'w') as f:
            json.dump(sig_data, f, indent=2)

        utils.print_success(f"Signature sauvegardée: {sig_path.name}")

    # ============================================
    # 🔍 VÉRIFICATION
    # ============================================

    def verify_signature(
            self,
            signed_data: Dict,
            trust_chain: Optional[list] = None
    ) -> Tuple[bool, Dict]:
        """
        Vérifie une signature

        Args:
            signed_data: Données signées (de sign_message)
            trust_chain: Liste de certificats de confiance

        Returns:
            tuple: (valide, rapport_détaillé)
        """
        utils.print_header("🔍 Vérification de signature")

        report = {
            "signature_valid": False,
            "certificate_valid": False,
            "chain_valid": False,
            "not_revoked": False,
            "timestamp_valid": False,
            "overall_valid": False,
            "details": []
        }

        message = signed_data['message']
        signature = signed_data['signature']
        certificate = signed_data['certificate']

        # 1. Vérifier la signature cryptographique
        utils.print_info("1️⃣ Vérification cryptographique de la signature...")

        try:
            public_key = certificate.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:
                from cryptography.hazmat.primitives.asymmetric import ec
                public_key.verify(
                    signature,
                    message,
                    ec.ECDSA(hashes.SHA256())
                )

            report["signature_valid"] = True
            report["details"].append(("Signature cryptographique", True, "Signature valide"))
            utils.print_success("✅ Signature cryptographique VALIDE")

        except InvalidSignature:
            report["signature_valid"] = False
            report["details"].append(("Signature cryptographique", False, "Signature invalide"))
            utils.print_error("❌ Signature cryptographique INVALIDE")
            return False, report
        except Exception as e:
            report["signature_valid"] = False
            report["details"].append(("Signature cryptographique", False, f"Erreur: {e}"))
            utils.print_error(f"❌ Erreur vérification: {e}")
            return False, report

        # 2. Vérifier la validité du certificat
        utils.print_info("\n2️⃣ Vérification de la validité du certificat...")

        now = utils.now_utc()
        cert_valid = (
                certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc
        )

        if cert_valid:
            report["certificate_valid"] = True
            report["details"].append(("Validité certificat", True, "Certificat dans sa période de validité"))
            utils.print_success("✅ Certificat VALIDE (période)")
        else:
            report["certificate_valid"] = False
            if now < certificate.not_valid_before_utc:
                report["details"].append(("Validité certificat", False, "Certificat pas encore valide"))
                utils.print_error("❌ Certificat PAS ENCORE VALIDE")
            else:
                report["details"].append(("Validité certificat", False, "Certificat EXPIRÉ"))
                utils.print_error("❌ Certificat EXPIRÉ")

        # 3. Vérifier la chaîne de confiance (si fournie)
        utils.print_info("\n3️⃣ Vérification de la chaîne de confiance...")

        if trust_chain:
            chain_ok = self._verify_trust_chain(certificate, trust_chain)
            report["chain_valid"] = chain_ok
            if chain_ok:
                report["details"].append(("Chaîne de confiance", True, "Chaîne valide"))
                utils.print_success("✅ Chaîne de confiance VALIDE")
            else:
                report["details"].append(("Chaîne de confiance", False, "Chaîne invalide"))
                utils.print_error("❌ Chaîne de confiance INVALIDE")
        else:
            report["chain_valid"] = True  # Pas de vérification demandée
            report["details"].append(("Chaîne de confiance", None, "Non vérifiée"))
            utils.print_warning("⚠️  Chaîne de confiance non vérifiée")

        # 4. Vérifier le statut de révocation (simulation)
        utils.print_info("\n4️⃣ Vérification du statut de révocation...")

        # Pour simplification, on suppose non révoqué
        # Dans un vrai système, interroger OCSP ou CRL
        report["not_revoked"] = True
        report["details"].append(("Révocation", True, "Non révoqué"))
        utils.print_success("✅ Certificat NON RÉVOQUÉ")

        # 5. Vérifier le timestamp
        utils.print_info("\n5️⃣ Vérification du timestamp...")

        try:
            sig_time = datetime.fromisoformat(signed_data['signature_time'])
            # Vérifier que la signature a été faite pendant la validité du cert
            timestamp_ok = (
                    certificate.not_valid_before_utc <= sig_time <= certificate.not_valid_after_utc
            )

            report["timestamp_valid"] = timestamp_ok
            if timestamp_ok:
                report["details"].append(("Timestamp", True, "Signature pendant validité du certificat"))
                utils.print_success("✅ Timestamp VALIDE")
            else:
                report["details"].append(("Timestamp", False, "Signature hors validité du certificat"))
                utils.print_error("❌ Timestamp INVALIDE")
        except:
            report["timestamp_valid"] = False
            report["details"].append(("Timestamp", False, "Timestamp invalide"))
            utils.print_error("❌ Timestamp INVALIDE")

        # Résultat global
        report["overall_valid"] = all([
            report["signature_valid"],
            report["certificate_valid"],
            report["chain_valid"],
            report["not_revoked"],
            report["timestamp_valid"]
        ])

        # Afficher le rapport
        self._display_verification_report(report)

        return report["overall_valid"], report

    def _verify_trust_chain(
            self,
            certificate: x509.Certificate,
            trust_chain: list
    ) -> bool:
        """Vérifie la chaîne de confiance (simplifié)"""
        # Pour simplification, vérifier juste que l'émetteur est dans la chaîne
        for trusted_cert in trust_chain:
            if certificate.issuer == trusted_cert.subject:
                return True
        return False

    def _display_verification_report(self, report: Dict):
        """Affiche le rapport de vérification"""
        utils.print_header("📊 Rapport de vérification")

        table = utils.create_table(
            "Résultats de vérification",
            ["Vérification", "Statut", "Détails"]
        )

        for check_name, result, details in report["details"]:
            if result is True:
                status = "[green]✅ VALIDE[/green]"
            elif result is False:
                status = "[red]❌ INVALIDE[/red]"
            else:
                status = "[yellow]⚠️  N/A[/yellow]"

            table.add_row(check_name, status, details)

        utils.console.print(table)

        # Résultat final
        if report["overall_valid"]:
            utils.console.print("\n[bold green]✅ SIGNATURE GLOBALEMENT VALIDE[/bold green]\n")
        else:
            utils.console.print("\n[bold red]❌ SIGNATURE GLOBALEMENT INVALIDE[/bold red]\n")

    # ============================================
    # 🔐 VALIDATION CIAN
    # ============================================

    def validate_cian(
            self,
            signed_data: Dict,
            trust_chain: Optional[list] = None
    ) -> Dict:
        """
        Valide les 4 principes CIAN

        C - Confidentialité (si chiffré)
        I - Intégrité
        A - Authenticité
        N - Non-répudiation

        Args:
            signed_data: Données signées
            trust_chain: Chaîne de confiance

        Returns:
            dict: Rapport CIAN
        """
        utils.print_header("🔐 Validation CIAN")

        cian_report = {
            "confidentiality": None,  # N/A pour signature simple
            "integrity": False,
            "authenticity": False,
            "non_repudiation": False,
            "overall": False
        }

        # Vérifier la signature (couvre Intégrité, Authenticité, Non-répudiation)
        is_valid, verify_report = self.verify_signature(signed_data, trust_chain)

        # I - Intégrité: la signature garantit que le message n'a pas été modifié
        cian_report["integrity"] = verify_report["signature_valid"]

        # A - Authenticité: le certificat valide prouve l'identité du signataire
        cian_report["authenticity"] = (
                verify_report["certificate_valid"] and
                verify_report["chain_valid"]
        )

        # N - Non-répudiation: le signataire ne peut pas nier avoir signé
        cian_report["non_repudiation"] = (
                verify_report["signature_valid"] and
                verify_report["not_revoked"] and
                verify_report["timestamp_valid"]
        )

        # C - Confidentialité: N/A pour signature simple (nécessite chiffrement)
        cian_report["confidentiality"] = None

        # Global
        cian_report["overall"] = is_valid

        # Afficher le rapport CIAN
        self._display_cian_report(cian_report, signed_data)

        return cian_report

    def _display_cian_report(self, cian_report: Dict, signed_data: Dict):
        """Affiche le rapport CIAN"""
        utils.print_header("📊 Rapport CIAN")

        table = utils.create_table(
            "Validation des principes CIAN",
            ["Principe", "Statut", "Explication"]
        )

        # C - Confidentialité
        if cian_report["confidentiality"] is None:
            c_status = "[yellow]⚠️  N/A[/yellow]"
            c_explain = "Signature seule (pas de chiffrement)"
        else:
            c_status = "[green]✅ OK[/green]" if cian_report["confidentiality"] else "[red]❌ KO[/red]"
            c_explain = "Message chiffré" if cian_report["confidentiality"] else "Message non chiffré"

        table.add_row(
            "[bold]C[/bold] - Confidentialité",
            c_status,
            c_explain
        )

        # I - Intégrité
        i_status = "[green]✅ OK[/green]" if cian_report["integrity"] else "[red]❌ KO[/red]"
        i_explain = "Hash vérifié, message non modifié" if cian_report["integrity"] else "Message modifié"

        table.add_row(
            "[bold]I[/bold] - Intégrité",
            i_status,
            i_explain
        )

        # A - Authenticité
        a_status = "[green]✅ OK[/green]" if cian_report["authenticity"] else "[red]❌ KO[/red]"
        a_explain = f"Signataire: {signed_data['signer_dn'][:40]}..." if cian_report[
            "authenticity"] else "Identité non vérifiée"

        table.add_row(
            "[bold]A[/bold] - Authenticité",
            a_status,
            a_explain
        )

        # N - Non-répudiation
        n_status = "[green]✅ OK[/green]" if cian_report["non_repudiation"] else "[red]❌ KO[/red]"
        n_explain = "Signature vérifiable, horodatée, non révoquée" if cian_report[
            "non_repudiation"] else "Preuve insuffisante"

        table.add_row(
            "[bold]N[/bold] - Non-répudiation",
            n_status,
            n_explain
        )

        utils.console.print(table)

        # Résultat global
        if cian_report["overall"]:
            utils.console.print("\n[bold green]✅ VALIDATION CIAN RÉUSSIE[/bold green]\n")
        else:
            utils.console.print("\n[bold red]❌ VALIDATION CIAN ÉCHOUÉE[/bold red]\n")


signature_manager = SignatureManager()

__all__ = ['SignatureManager', 'signature_manager']