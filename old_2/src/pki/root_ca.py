"""
Root CA (Certificate Authority) Manager
Gère la création et les opérations de l'autorité racine
"""

from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import config, utils
from .keygen import KeyGenerator, PrivateKeyTypes
from .database import PKIDatabase
from .models import DistinguishedName


class RootCAManager:
    """
    Gestionnaire de la Root CA (Autorité de Certification Racine)
    """

    def __init__(self, db: Optional[PKIDatabase] = None):
        """
        Initialise le gestionnaire Root CA

        Args:
            db: Instance de la base de données (optionnel)
        """
        self.db = db or PKIDatabase()
        self.key_gen = KeyGenerator()

    # ============================================
    # 👑 CRÉATION ROOT CA
    # ============================================

    def create_root_ca(
            self,
            dn: DistinguishedName,
            key_size: int = 4096,
            validity_days: Optional[int] = None,
            password: Optional[str] = None
    ) -> tuple[x509.Certificate, PrivateKeyTypes, Path, Path]:
        """
        Crée une Root CA complète (clé + certificat auto-signé)

        Args:
            dn: Distinguished Name de la Root CA
            key_size: Taille de la clé RSA (4096 recommandé pour Root CA)
            validity_days: Durée de validité en jours (défaut: 20 ans)
            password: Mot de passe pour chiffrer la clé privée

        Returns:
            tuple: (certificat, clé_privée, chemin_cert, chemin_clé)
        """
        utils.print_header(f"{config.CLI_SYMBOLS['root']} Création de la Root CA")

        # Valeurs par défaut
        if validity_days is None:
            validity_days = config.VALIDITY_PERIODS["root_ca"]

        # Étape 1: Générer la clé privée RSA
        utils.print_info("Étape 1/4: Génération de la clé privée RSA...")
        private_key, priv_key_path, pub_key_path = self.key_gen.generate_key_pair(
            entity_name="root_ca",
            key_type="rsa",
            key_size=key_size,
            password=password,
            save_keys=True
        )

        # Étape 2: Construire le certificat auto-signé
        utils.print_info("\nÉtape 2/4: Construction du certificat X.509v3...")
        certificate = self._build_root_certificate(
            private_key=private_key,
            dn=dn,
            validity_days=validity_days
        )

        # Étape 3: Sauvegarder le certificat
        utils.print_info("\nÉtape 3/4: Sauvegarde du certificat...")
        cert_path = self._save_certificate(certificate, "root_ca")

        # Étape 4: Enregistrer dans la base de données
        utils.print_info("\nÉtape 4/4: Enregistrement dans la base de données...")
        self._register_in_database(certificate, cert_path)

        # Afficher les informations du certificat
        utils.print_success("\n✨ Root CA créée avec succès!\n")
        utils.display_cert_info(certificate)

        return certificate, private_key, cert_path, priv_key_path

    def _build_root_certificate(
            self,
            private_key: PrivateKeyTypes,
            dn: DistinguishedName,
            validity_days: int
    ) -> x509.Certificate:
        """
        Construit un certificat X.509v3 auto-signé pour la Root CA

        Args:
            private_key: Clé privée pour signer
            dn: Distinguished Name
            validity_days: Durée de validité

        Returns:
            x509.Certificate: Certificat auto-signé
        """
        # Créer le sujet (subject) = émetteur (issuer) pour Root CA
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, dn.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, dn.state or ""),
            x509.NameAttribute(NameOID.LOCALITY_NAME, dn.locality or ""),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, dn.organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, dn.organizational_unit or "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, dn.common_name),
        ])

        # Générer le numéro de série
        serial_number = utils.generate_serial_number()

        # Dates de validité
        not_before = utils.now_utc()
        not_after = not_before + timedelta(days=validity_days)

        # Construire le certificat
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        # Ajouter les extensions X.509v3
        cert_builder = self._add_root_ca_extensions(cert_builder, private_key)

        # Signer le certificat avec la clé privée (auto-signé)
        certificate = cert_builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256()
        )

        utils.print_success(f"Certificat construit (SN: {serial_number:X})")

        return certificate

    def _add_root_ca_extensions(
            self,
            cert_builder: x509.CertificateBuilder,
            private_key: PrivateKeyTypes
    ) -> x509.CertificateBuilder:
        """
        Ajoute les extensions X.509v3 spécifiques à une Root CA

        Args:
            cert_builder: Builder du certificat
            private_key: Clé privée (pour calculer les identifiants)

        Returns:
            CertificateBuilder: Builder avec extensions ajoutées
        """
        # 1. BasicConstraints (CRITIQUE)
        # CA=TRUE, pathLength=1 (peut signer des Intermediate CA)
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True
        )

        # 2. KeyUsage (CRITIQUE)
        # Pour Root CA: signature de certificats et CRL
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,  # Signer des certificats
                crl_sign=True,  # Signer des CRL
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # 3. SubjectKeyIdentifier
        # Identifiant unique de la clé publique
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )

        # 4. AuthorityKeyIdentifier
        # Pour Root CA auto-signée, identique au SubjectKeyIdentifier
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False
        )

        utils.print_success("Extensions X.509v3 ajoutées (BasicConstraints, KeyUsage, SKI, AKI)")

        return cert_builder

    def _save_certificate(self, certificate: x509.Certificate, name: str) -> Path:
        """
        Sauvegarde un certificat au format PEM

        Args:
            certificate: Certificat à sauvegarder
            name: Nom de base pour le fichier

        Returns:
            Path: Chemin du fichier sauvegardé
        """
        cert_path = config.get_cert_path(name)

        # Sérialiser en PEM
        pem_data = certificate.public_bytes(serialization.Encoding.PEM)

        # Écrire le fichier
        with open(cert_path, 'wb') as f:
            f.write(pem_data)

        # Permissions lecture publique
        utils.set_file_permissions(cert_path, config.CERT_PERMISSIONS)

        file_info = utils.get_file_info(cert_path)
        utils.print_success(f"Certificat sauvegardé: {cert_path.name} ({file_info.get('size', 'N/A')})")

        return cert_path

    def _register_in_database(self, certificate: x509.Certificate, cert_path: Path):
        """
        Enregistre le certificat dans la base de données

        Args:
            certificate: Certificat à enregistrer
            cert_path: Chemin du fichier certificat
        """
        serial_hex = f"{certificate.serial_number:X}"
        subject_dn = certificate.subject.rfc4514_string()
        issuer_dn = certificate.issuer.rfc4514_string()

        self.db.add_certificate(
            serial_number=serial_hex,
            subject_dn=subject_dn,
            issuer_dn=issuer_dn,
            cert_type="root_ca",
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            cert_path=str(cert_path)
        )

        utils.print_success(f"Certificat enregistré dans la BDD (SN: {serial_hex[:16]}...)")

    # ============================================
    # 📂 CHARGEMENT ROOT CA
    # ============================================

    def load_root_ca(
            self,
            cert_path: Optional[Path] = None,
            key_path: Optional[Path] = None,
            password: Optional[str] = None
    ) -> tuple[x509.Certificate, Optional[PrivateKeyTypes]]:
        """
        Charge une Root CA existante depuis les fichiers

        Args:
            cert_path: Chemin du certificat (défaut: root_ca_cert.pem)
            key_path: Chemin de la clé privée (défaut: root_ca_key.pem)
            password: Mot de passe de la clé privée

        Returns:
            tuple: (certificat, clé_privée)
        """
        # Chemins par défaut
        if cert_path is None:
            cert_path = config.get_cert_path("root_ca")

        if key_path is None:
            key_path = config.get_key_path("root_ca", "private")

        # Charger le certificat
        if not cert_path.exists():
            raise FileNotFoundError(f"Certificat Root CA introuvable: {cert_path}")

        with open(cert_path, 'rb') as f:
            cert_pem = f.read()

        certificate = x509.load_pem_x509_certificate(cert_pem)
        utils.print_success(f"Certificat Root CA chargé: {cert_path.name}")

        # Charger la clé privée (optionnel)
        private_key = None
        if key_path.exists():
            try:
                private_key = self.key_gen.load_private_key(key_path, password)
            except Exception as e:
                utils.print_warning(f"Impossible de charger la clé privée: {e}")

        return certificate, private_key

    # ============================================
    # 🔍 VALIDATION ROOT CA
    # ============================================

    def validate_root_ca(self, certificate: x509.Certificate) -> bool:
        """
        Valide qu'un certificat est bien une Root CA valide

        Args:
            certificate: Certificat à valider

        Returns:
            bool: True si valide
        """
        utils.print_info("Validation de la Root CA...")

        checks = []

        # 1. Vérifier que subject == issuer (auto-signé)
        is_self_signed = certificate.subject == certificate.issuer
        checks.append(("Auto-signé (subject == issuer)", is_self_signed))

        # 2. Vérifier BasicConstraints CA=True
        try:
            basic_constraints = certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            is_ca = basic_constraints.ca
            checks.append(("BasicConstraints CA=True", is_ca))
        except:
            checks.append(("BasicConstraints CA=True", False))

        # 3. Vérifier KeyUsage
        try:
            key_usage = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            ).value
            has_cert_sign = key_usage.key_cert_sign
            has_crl_sign = key_usage.crl_sign
            checks.append(("KeyUsage: keyCertSign", has_cert_sign))
            checks.append(("KeyUsage: cRLSign", has_crl_sign))
        except:
            checks.append(("KeyUsage correct", False))

        # 4. Vérifier la validité
        now = utils.now_utc()
        is_valid = certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc
        checks.append(("Période de validité", is_valid))

        # Afficher les résultats
        table = utils.create_table("🔍 Validation Root CA", ["Vérification", "Résultat"])
        for check_name, result in checks:
            status = "[green]✓ Valide[/green]" if result else "[red]✗ Invalide[/red]"
            table.add_row(check_name, status)

        utils.console.print(table)

        all_valid = all(result for _, result in checks)

        if all_valid:
            utils.print_success("✅ Root CA valide!")
        else:
            utils.print_error("❌ Root CA invalide!")

        return all_valid


# ============================================
# 🎯 INSTANCE GLOBALE
# ============================================

root_ca_manager = RootCAManager()

__all__ = ['RootCAManager', 'root_ca_manager']