"""
Registration Authority (RA)
Gère la vérification d'identité et l'approbation des demandes de certificats
"""

from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes

from . import config, utils
from .database import PKIDatabase
from .models import DistinguishedName


class RegistrationAuthority:
    """
    Authority d'Enregistrement (RA)
    Vérifie l'identité et approuve les CSR avant envoi à la CA
    """

    def __init__(self, db: Optional[PKIDatabase] = None):
        self.db = db or PKIDatabase()

    # ============================================
    # 📝 RÉCEPTION CSR
    # ============================================

    def submit_csr(
            self,
            csr: x509.CertificateSigningRequest,
            cert_type: str,
            requestor_info: Optional[Dict] = None
    ) -> str:
        """
        Soumet une demande de certificat (CSR)

        Args:
            csr: Certificate Signing Request
            cert_type: Type de certificat (client, server, etc.)
            requestor_info: Informations supplémentaires du demandeur

        Returns:
            str: ID de la demande
        """
        utils.print_info("📝 Réception d'une nouvelle demande CSR...")

        # Générer un ID unique
        request_id = f"CSR_{utils.generate_serial_number():X}"[:20]

        # Sauvegarder le CSR
        csr_path = self._save_csr(csr, request_id)

        # Extraire le sujet
        subject_dn = csr.subject.rfc4514_string()

        # Enregistrer en BDD
        self.db.add_csr_request(
            request_id=request_id,
            subject_dn=subject_dn,
            cert_type=cert_type,
            csr_path=str(csr_path)
        )

        utils.print_success(f"CSR enregistré: {request_id}")

        # Log audit
        details = f"Type: {cert_type}, Sujet: {subject_dn}"
        if requestor_info:
            details += f", Info: {requestor_info}"

        self.db.add_audit_log(
            action="CSR_SUBMITTED",
            entity_type="csr",
            entity_id=request_id,
            details=details,
            success=True
        )

        return request_id

    def _save_csr(self, csr: x509.CertificateSigningRequest, request_id: str) -> Path:
        """Sauvegarde un CSR"""
        csr_dir = config.DATA_DIR / "csr"
        utils.ensure_directory(csr_dir)

        csr_path = csr_dir / f"{request_id}.csr"
        pem_data = csr.public_bytes(serialization.Encoding.PEM)

        with open(csr_path, 'wb') as f:
            f.write(pem_data)

        return csr_path

    # ============================================
    # 🔍 VÉRIFICATION IDENTITÉ
    # ============================================

    def verify_identity(
            self,
            request_id: str,
            verification_method: str = "manual",
            verification_data: Optional[Dict] = None
    ) -> bool:
        """
        Vérifie l'identité du demandeur

        Args:
            request_id: ID de la demande
            verification_method: Méthode de vérification
            verification_data: Données de vérification

        Returns:
            bool: True si l'identité est vérifiée
        """
        utils.print_info(f"🔍 Vérification d'identité pour {request_id}...")

        # Récupérer la demande
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM csr_requests WHERE request_id = ?",
                (request_id,)
            )
            csr_request = cursor.fetchone()

        if not csr_request:
            utils.print_error(f"CSR introuvable: {request_id}")
            return False

        # Simulation de vérification d'identité
        checks = []

        # 1. Vérifier que le CSR est bien formé
        csr_path = Path(csr_request['csr_path'])
        if csr_path.exists():
            checks.append(("Fichier CSR existe", True))

            # Charger et valider le CSR
            with open(csr_path, 'rb') as f:
                csr_pem = f.read()

            try:
                csr = x509.load_pem_x509_csr(csr_pem)

                # Vérifier la signature du CSR
                if csr.is_signature_valid:
                    checks.append(("Signature CSR valide", True))
                else:
                    checks.append(("Signature CSR valide", False))

                # Vérifier que le sujet n'est pas vide
                if csr.subject:
                    checks.append(("Sujet non vide", True))
                else:
                    checks.append(("Sujet non vide", False))

            except Exception as e:
                checks.append(("CSR valide", False))
                utils.print_error(f"Erreur validation CSR: {e}")
        else:
            checks.append(("Fichier CSR existe", False))

        # 2. Vérification basée sur la méthode
        if verification_method == "manual":
            checks.append(("Vérification manuelle", True))
        elif verification_method == "email":
            email_valid = verification_data and verification_data.get("email_verified", False)
            checks.append(("Email vérifié", email_valid))
        elif verification_method == "document":
            doc_valid = verification_data and verification_data.get("document_verified", False)
            checks.append(("Document vérifié", doc_valid))

        # Afficher résultats
        table = utils.create_table(f"🔍 Vérification identité - {request_id}", ["Check", "Résultat"])
        for check_name, result in checks:
            status = "[green]✓ OK[/green]" if result else "[red]✗ Échec[/red]"
            table.add_row(check_name, status)

        utils.console.print(table)

        all_valid = all(result for _, result in checks)

        if all_valid:
            utils.print_success("✅ Identité vérifiée")
        else:
            utils.print_error("❌ Vérification d'identité échouée")

        return all_valid

    # ============================================
    # ✅ APPROBATION / REJET
    # ============================================

    def approve_csr(self, request_id: str, approver: str = "RA_System") -> bool:
        """
        Approuve une demande CSR

        Args:
            request_id: ID de la demande
            approver: Nom de l'approbateur

        Returns:
            bool: True si approuvé
        """
        utils.print_info(f"✅ Approbation du CSR {request_id}...")

        # Vérifier que la demande existe et est en attente
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT status FROM csr_requests WHERE request_id = ?",
                (request_id,)
            )
            row = cursor.fetchone()

            if not row:
                utils.print_error(f"CSR introuvable: {request_id}")
                return False

            if row['status'] != 'pending':
                utils.print_warning(f"CSR déjà traité: {row['status']}")
                return False

        # Mettre à jour le statut
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE csr_requests
                SET status = 'approved', approved_at = ?
                WHERE request_id = ?
            """, (utils.now_utc().isoformat(), request_id))

        # Log audit
        self.db.add_audit_log(
            action="CSR_APPROVED",
            entity_type="csr",
            entity_id=request_id,
            details=f"Approuvé par: {approver}",
            success=True
        )

        utils.print_success(f"✅ CSR {request_id} approuvé")
        return True

    def reject_csr(self, request_id: str, reason: str, rejector: str = "RA_System") -> bool:
        """
        Rejette une demande CSR

        Args:
            request_id: ID de la demande
            reason: Raison du rejet
            rejector: Nom du rejeteur

        Returns:
            bool: True si rejeté
        """
        utils.print_warning(f"❌ Rejet du CSR {request_id}...")

        # Mettre à jour le statut
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE csr_requests
                SET status = 'rejected', rejected_at = ?, rejection_reason = ?
                WHERE request_id = ?
            """, (utils.now_utc().isoformat(), reason, request_id))

        # Log audit
        self.db.add_audit_log(
            action="CSR_REJECTED",
            entity_type="csr",
            entity_id=request_id,
            details=f"Raison: {reason}, Par: {rejector}",
            success=True
        )

        utils.print_success(f"CSR {request_id} rejeté")
        return True

    # ============================================
    # 📊 GESTION DES DEMANDES
    # ============================================

    def list_pending_requests(self) -> List[Dict]:
        """Liste toutes les demandes en attente"""
        return self.db.list_pending_csrs()

    def get_request_details(self, request_id: str) -> Optional[Dict]:
        """Récupère les détails d'une demande"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM csr_requests WHERE request_id = ?",
                (request_id,)
            )
            row = cursor.fetchone()

            if row:
                return dict(row)
            return None

    def display_pending_requests(self):
        """Affiche les demandes en attente de manière formatée"""
        pending = self.list_pending_requests()

        if not pending:
            utils.print_info("Aucune demande CSR en attente")
            return

        table = utils.create_table(
            f"📋 Demandes CSR en attente ({len(pending)})",
            ["ID", "Sujet", "Type", "Date", "Actions"]
        )

        for req in pending:
            req_id_short = utils.truncate_string(req['request_id'], 15)
            subject_short = utils.truncate_string(req['subject_dn'], 30)
            created = req['created_at'][:19].replace('T', ' ')

            table.add_row(
                req_id_short,
                subject_short,
                req['cert_type'],
                created,
                "[green]Approver[/green] | [red]Rejeter[/red]"
            )

        utils.console.print(table)

    # ============================================
    # 🎯 WORKFLOW COMPLET
    # ============================================

    def process_csr_workflow(
            self,
            csr: x509.CertificateSigningRequest,
            cert_type: str,
            auto_approve: bool = False,
            verification_method: str = "manual"
    ) -> tuple[bool, str]:
        """
        Workflow complet de traitement d'un CSR

        Args:
            csr: Certificate Signing Request
            cert_type: Type de certificat
            auto_approve: Approbation automatique
            verification_method: Méthode de vérification

        Returns:
            tuple: (approuvé, request_id)
        """
        utils.print_header("📝 Workflow RA - Traitement CSR")

        # 1. Soumettre
        request_id = self.submit_csr(csr, cert_type)

        # 2. Vérifier identité
        identity_valid = self.verify_identity(request_id, verification_method)

        if not identity_valid:
            self.reject_csr(request_id, "Échec vérification d'identité")
            return False, request_id

        # 3. Approuver ou rejeter
        if auto_approve:
            self.approve_csr(request_id)
            return True, request_id
        else:
            utils.print_info("\n⏸️  Demande en attente d'approbation manuelle")
            return False, request_id


registration_authority = RegistrationAuthority()

__all__ = ['RegistrationAuthority', 'registration_authority']