"""
Gestion de la base de données SQLite pour le système PKI
"""

import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from datetime import datetime

from . import config
from . import utils


class PKIDatabase:
    """
    Classe pour gérer la base de données SQLite de la PKI
    """

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialise la connexion à la base de données

        Args:
            db_path: Chemin de la base de données (défaut: config.DATABASE_PATH)
        """
        self.db_path = db_path or config.DATABASE_PATH
        utils.ensure_directory(self.db_path.parent)

        # Créer les tables si nécessaire
        self.init_database()

    # ============================================
    # 🔌 GESTION DE LA CONNEXION
    # ============================================

    @contextmanager
    def get_connection(self):
        """
        Context manager pour gérer les connexions à la base de données
        Garantit commit/rollback automatique

        Yields:
            sqlite3.Connection: Connexion à la base
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Permet l'accès par nom de colonne
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            utils.print_error(f"Erreur base de données: {e}")
            raise
        finally:
            conn.close()

    # ============================================
    # 🏗️ INITIALISATION
    # ============================================

    def init_database(self) -> None:
        """
        Crée les tables de la base de données si elles n'existent pas
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Créer chaque table
            for table_name, create_sql in config.DB_TABLES.items():
                cursor.execute(create_sql)

            conn.commit()

        utils.print_success("Base de données initialisée")

    # ============================================
    # 📜 GESTION DES CERTIFICATS
    # ============================================

    def add_certificate(
            self,
            serial_number: str,
            subject_dn: str,
            issuer_dn: str,
            cert_type: str,
            not_before: datetime,
            not_after: datetime,
            cert_path: str,
            public_key_path: Optional[str] = None
    ) -> int:
        """
        Ajoute un certificat dans la base de données

        Args:
            serial_number: Numéro de série (hex)
            subject_dn: Distinguished Name du sujet
            issuer_dn: Distinguished Name de l'émetteur
            cert_type: Type de certificat (root_ca, intermediate_ca, client, server)
            not_before: Date de début de validité
            not_after: Date de fin de validité
            cert_path: Chemin du fichier certificat
            public_key_path: Chemin de la clé publique (optionnel)

        Returns:
            int: ID du certificat inséré
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO certificates (
                    serial_number, subject_dn, issuer_dn, cert_type,
                    not_before, not_after, public_key_path, cert_path, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                serial_number,
                subject_dn,
                issuer_dn,
                cert_type,
                not_before.isoformat(),
                not_after.isoformat(),
                public_key_path,
                cert_path,
                utils.now_utc().isoformat()
            ))

            cert_id = cursor.lastrowid

            # Log d'audit
            self.add_audit_log(
                action="CERTIFICATE_ISSUED",
                entity_type="certificate",
                entity_id=serial_number,
                details=f"Type: {cert_type}, Sujet: {subject_dn}",
                success=True
            )

            return cert_id

    def get_certificate(self, serial_number: str) -> Optional[Dict[str, Any]]:
        """
        Récupère un certificat par son numéro de série

        Args:
            serial_number: Numéro de série (hex)

        Returns:
            dict ou None: Informations du certificat
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM certificates WHERE serial_number = ?", (serial_number,))
            row = cursor.fetchone()

            if row:
                return dict(row)
            return None

    def list_certificates(
            self,
            cert_type: Optional[str] = None,
            status: Optional[str] = None,
            limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Liste les certificats avec filtres optionnels

        Args:
            cert_type: Filtrer par type (root_ca, client, etc.)
            status: Filtrer par statut (active, revoked)
            limit: Nombre maximum de résultats

        Returns:
            list: Liste de certificats
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM certificates WHERE 1=1"
            params = []

            if cert_type:
                query += " AND cert_type = ?"
                params.append(cert_type)

            if status:
                query += " AND status = ?"
                params.append(status)

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

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
            bool: True si révocation réussie
        """
        if reason not in config.REVOCATION_REASONS:
            utils.print_error(f"Raison de révocation invalide: {reason}")
            return False

        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Vérifier que le certificat existe
            cert = self.get_certificate(serial_number)
            if not cert:
                utils.print_error(f"Certificat introuvable: {serial_number}")
                return False

            # Vérifier qu'il n'est pas déjà révoqué
            if cert['status'] == 'revoked':
                utils.print_warning(f"Certificat déjà révoqué: {serial_number}")
                return False

            now = utils.now_utc()

            # Mettre à jour le statut du certificat
            cursor.execute("""
                UPDATE certificates
                SET status = 'revoked', revoked_at = ?, revocation_reason = ?
                WHERE serial_number = ?
            """, (now.isoformat(), reason, serial_number))

            # Ajouter dans la table des révocations
            cursor.execute("""
                INSERT INTO revocations (serial_number, revocation_date, reason)
                VALUES (?, ?, ?)
            """, (serial_number, now.isoformat(), reason))

            # Log d'audit
            self.add_audit_log(
                action="CERTIFICATE_REVOKED",
                entity_type="certificate",
                entity_id=serial_number,
                details=f"Raison: {reason}",
                success=True
            )

            utils.print_success(f"Certificat révoqué: {serial_number[:16]}... (raison: {reason})")
            return True

    # ============================================
    # 📝 GESTION DES CSR
    # ============================================

    def add_csr_request(
            self,
            request_id: str,
            subject_dn: str,
            cert_type: str,
            csr_path: str
    ) -> int:
        """
        Ajoute une demande de certificat (CSR)

        Args:
            request_id: ID unique de la demande
            subject_dn: Distinguished Name du demandeur
            cert_type: Type de certificat demandé
            csr_path: Chemin du fichier CSR

        Returns:
            int: ID de la demande
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO csr_requests (request_id, subject_dn, cert_type, csr_path, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (request_id, subject_dn, cert_type, csr_path, utils.now_utc().isoformat()))

            request_db_id = cursor.lastrowid

            self.add_audit_log(
                action="CSR_SUBMITTED",
                entity_type="csr",
                entity_id=request_id,
                details=f"Type: {cert_type}, Sujet: {subject_dn}",
                success=True
            )

            return request_db_id

    def list_pending_csrs(self) -> List[Dict[str, Any]]:
        """
        Liste toutes les demandes CSR en attente

        Returns:
            list: Liste des CSR en attente
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM csr_requests WHERE status = 'pending' ORDER BY created_at")
            return [dict(row) for row in cursor.fetchall()]

    # ============================================
    # 📊 AUDIT LOG
    # ============================================

    def add_audit_log(
            self,
            action: str,
            entity_type: str,
            entity_id: Optional[str] = None,
            details: Optional[str] = None,
            success: bool = True
    ) -> None:
        """
        Ajoute une entrée dans le journal d'audit

        Args:
            action: Action effectuée
            entity_type: Type d'entité (certificate, csr, key)
            entity_id: ID de l'entité
            details: Détails supplémentaires
            success: Indique si l'action a réussi
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_log (timestamp, action, entity_type, entity_id, details, success)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (utils.now_utc().isoformat(), action, entity_type, entity_id, details, success))

    def get_statistics(self) -> Dict[str, Any]:
        """
        Calcule des statistiques sur la PKI


        Returns:
            dict: Statistiques diverses
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            stats = {}

            # Nombre total de certificats
            cursor.execute("SELECT COUNT(*) FROM certificates")
            stats['total_certificates'] = cursor.fetchone()[0]

            # Certificats actifs
            cursor.execute("SELECT COUNT(*) FROM certificates WHERE status = 'active'")
            stats['active_certificates'] = cursor.fetchone()[0]

            # Certificats révoqués
            cursor.execute("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'")
            stats['revoked_certificates'] = cursor.fetchone()[0]

            # CSR en attente
            cursor.execute("SELECT COUNT(*) FROM csr_requests WHERE status = 'pending'")
            stats['pending_csrs'] = cursor.fetchone()[0]

            # Répartition par type
            cursor.execute("SELECT cert_type, COUNT(*) as count FROM certificates GROUP BY cert_type")
            stats['by_type'] = {row['cert_type']: row['count'] for row in cursor.fetchall()}

            return stats


# ============================================
# 🎯 INSTANCE GLOBALE
# ============================================

# Instance par défaut
pki_db = PKIDatabase()

__all__ = ['PKIDatabase', 'pki_db']