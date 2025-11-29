"""
Intermediate CA Manager
Gère la création et les opérations de l'autorité intermédiaire
"""

from pathlib import Path
from datetime import timedelta
from typing import Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import config, utils
from .keygen import KeyGenerator, PrivateKeyTypes
from .database import PKIDatabase
from .models import DistinguishedName


class IntermediateCAManager:
    """
    Gestionnaire de l'Intermediate CA
    """

    def __init__(self, db: Optional[PKIDatabase] = None):
        self.db = db or PKIDatabase()
        self.key_gen = KeyGenerator()

    def create_intermediate_ca(
            self,
            dn: DistinguishedName,
            root_cert: x509.Certificate,
            root_key: PrivateKeyTypes,
            key_size: int = 3072,
            validity_days: Optional[int] = None,
            password: Optional[str] = None
    ) -> Tuple[x509.Certificate, PrivateKeyTypes, Path, Path]:
        """
        Crée une Intermediate CA signée par la Root CA

        Args:
            dn: Distinguished Name de l'Intermediate CA
            root_cert: Certificat de la Root CA (pour signer)
            root_key: Clé privée de la Root CA
            key_size: Taille de la clé RSA
            validity_days: Durée de validité
            password: Mot de passe pour la clé privée

        Returns:
            tuple: (certificat, clé_privée, chemin_cert, chemin_clé)
        """
        utils.print_header(f"{config.CLI_SYMBOLS['intermediate']} Création de l'Intermediate CA")

        if validity_days is None:
            validity_days = config.VALIDITY_PERIODS["intermediate_ca"]

        # Étape 1: Générer la clé privée
        utils.print_info("Étape 1/5: Génération de la clé privée RSA...")
        private_key, priv_key_path, pub_key_path = self.key_gen.generate_key_pair(
            entity_name="intermediate_ca",
            key_type="rsa",
            key_size=key_size,
            password=password,
            save_keys=True
        )

        # Étape 2: Créer le CSR
        utils.print_info("\nÉtape 2/5: Création du Certificate Signing Request (CSR)...")
        csr = self._build_csr(private_key, dn)

        # Étape 3: Signer par la Root CA
        utils.print_info("\nÉtape 3/5: Signature par la Root CA...")
        certificate = self._sign_intermediate_cert(
            csr=csr,
            root_cert=root_cert,
            root_key=root_key,
            validity_days=validity_days
        )

        # Étape 4: Sauvegarder
        utils.print_info("\nÉtape 4/5: Sauvegarde du certificat...")
        cert_path = self._save_certificate(certificate, "intermediate_ca")

        # Étape 5: Enregistrer en BDD
        utils.print_info("\nÉtape 5/5: Enregistrement dans la base de données...")
        self._register_in_database(certificate, cert_path)

        utils.print_success("\n✨ Intermediate CA créée avec succès!\n")
        utils.display_cert_info(certificate)

        return certificate, private_key, cert_path, priv_key_path

    def _build_csr(
            self,
            private_key: PrivateKeyTypes,
            dn: DistinguishedName
    ) -> x509.CertificateSigningRequest:
        """Construit un CSR pour l'Intermediate CA"""
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, dn.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, dn.state or ""),
            x509.NameAttribute(NameOID.LOCALITY_NAME, dn.locality or ""),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, dn.organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, dn.organizational_unit or "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, dn.common_name),
        ])

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, hashes.SHA256())
        )

        utils.print_success("CSR créé")
        return csr

    def _sign_intermediate_cert(
            self,
            csr: x509.CertificateSigningRequest,
            root_cert: x509.Certificate,
            root_key: PrivateKeyTypes,
            validity_days: int
    ) -> x509.Certificate:
        """Signe le certificat Intermediate avec la Root CA"""
        serial_number = utils.generate_serial_number()
        not_before = utils.now_utc()
        not_after = not_before + timedelta(days=validity_days)

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(root_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        # Extensions Intermediate CA
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )

        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False
        )

        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
            critical=False
        )

        certificate = cert_builder.sign(root_key, hashes.SHA256())
        utils.print_success(f"Certificat signé par Root CA (SN: {serial_number:X})")

        return certificate

    def _save_certificate(self, certificate: x509.Certificate, name: str) -> Path:
        """Sauvegarde le certificat"""
        cert_path = config.get_cert_path(name)
        pem_data = certificate.public_bytes(serialization.Encoding.PEM)

        with open(cert_path, 'wb') as f:
            f.write(pem_data)

        utils.set_file_permissions(cert_path, config.CERT_PERMISSIONS)
        file_info = utils.get_file_info(cert_path)
        utils.print_success(f"Certificat sauvegardé: {cert_path.name} ({file_info.get('size', 'N/A')})")

        return cert_path

    def _register_in_database(self, certificate: x509.Certificate, cert_path: Path):
        """Enregistre dans la BDD"""
        serial_hex = f"{certificate.serial_number:X}"
        subject_dn = certificate.subject.rfc4514_string()
        issuer_dn = certificate.issuer.rfc4514_string()

        self.db.add_certificate(
            serial_number=serial_hex,
            subject_dn=subject_dn,
            issuer_dn=issuer_dn,
            cert_type="intermediate_ca",
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            cert_path=str(cert_path)
        )

        utils.print_success(f"Certificat enregistré dans la BDD")

    def build_cert_chain(
            self,
            intermediate_cert: x509.Certificate,
            root_cert: x509.Certificate
    ) -> bytes:
        """
        Construit la chaîne de certification complète

        Returns:
            bytes: Chaîne PEM (Intermediate + Root)
        """
        chain = intermediate_cert.public_bytes(serialization.Encoding.PEM)
        chain += root_cert.public_bytes(serialization.Encoding.PEM)

        # Sauvegarder la chaîne
        chain_path = config.CERTS_DIR / "ca_chain.pem"
        with open(chain_path, 'wb') as f:
            f.write(chain)

        utils.print_success(f"Chaîne de certification sauvegardée: {chain_path}")
        return chain

    def validate_chain(
            self,
            intermediate_cert: x509.Certificate,
            root_cert: x509.Certificate
    ) -> bool:
        """Valide la chaîne de certification"""
        utils.print_info("Validation de la chaîne de certification...")

        checks = []

        # 1. L'émetteur de l'intermediate doit être le sujet de la root
        issuer_match = intermediate_cert.issuer == root_cert.subject
        checks.append(("Émetteur Intermediate = Sujet Root", issuer_match))

        # 2. Root doit être auto-signée
        root_self_signed = root_cert.subject == root_cert.issuer
        checks.append(("Root auto-signée", root_self_signed))

        # 3. Intermediate CA=True, pathLength=0
        try:
            int_bc = intermediate_cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            int_is_ca = int_bc.ca and int_bc.path_length == 0
            checks.append(("Intermediate CA=True, pathLength=0", int_is_ca))
        except:
            checks.append(("Intermediate BasicConstraints", False))

        # 4. Root CA=True, pathLength>=1
        try:
            root_bc = root_cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            root_is_ca = root_bc.ca and (root_bc.path_length is None or root_bc.path_length >= 1)
            checks.append(("Root CA=True, pathLength>=1", root_is_ca))
        except:
            checks.append(("Root BasicConstraints", False))

        # Afficher résultats
        table = utils.create_table("🔍 Validation chaîne", ["Vérification", "Résultat"])
        for check_name, result in checks:
            status = "[green]✓ Valide[/green]" if result else "[red]✗ Invalide[/red]"
            table.add_row(check_name, status)

        utils.console.print(table)

        all_valid = all(result for _, result in checks)

        if all_valid:
            utils.print_success("✅ Chaîne de certification valide!")
        else:
            utils.print_error("❌ Chaîne de certification invalide!")

        return all_valid


intermediate_ca_manager = IntermediateCAManager()

__all__ = ['IntermediateCAManager', 'intermediate_ca_manager']