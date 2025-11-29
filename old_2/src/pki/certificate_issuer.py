"""
Certificate Issuer
Émet des certificats pour les utilisateurs (client, server, code signing)
"""

from pathlib import Path
from datetime import timedelta
from typing import Optional, Tuple, List
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization

from . import config, utils
from .keygen import KeyGenerator, PrivateKeyTypes
from .database import PKIDatabase
from .models import DistinguishedName


class CertificateIssuer:
    """
    Émetteur de certificats
    Signe les certificats utilisateur/serveur avec l'Intermediate CA
    """

    def __init__(self, db: Optional[PKIDatabase] = None):
        self.db = db or PKIDatabase()
        self.key_gen = KeyGenerator()

    # ============================================
    # 📜 ÉMISSION CERTIFICATS
    # ============================================

    def issue_certificate(
            self,
            dn: DistinguishedName,
            cert_type: str,
            issuer_cert: x509.Certificate,
            issuer_key: PrivateKeyTypes,
            validity_days: Optional[int] = None,
            san_list: Optional[List[str]] = None
    ) -> Tuple[x509.Certificate, Path]:
        """
        Émet un certificat utilisateur/serveur

        Args:
            dn: Distinguished Name du certificat
            cert_type: Type (client, server, code_signing)
            issuer_cert: Certificat de l'Intermediate CA
            issuer_key: Clé privée de l'Intermediate CA
            validity_days: Durée de validité
            san_list: Subject Alternative Names (pour serveurs)

        Returns:
            tuple: (certificat, chemin_fichier)
        """
        utils.print_header(f"{config.CLI_SYMBOLS.get(cert_type, '📜')} Émission certificat {cert_type}")

        if validity_days is None:
            validity_days = config.VALIDITY_PERIODS.get(cert_type, 365)

        # 1. Générer la clé
        utils.print_info("Étape 1/4: Génération de la clé...")
        entity_name = dn.common_name.replace(" ", "_").lower()
        private_key, priv_path, pub_path = self.key_gen.generate_key_pair(
            entity_name=entity_name,
            key_type="rsa",
            key_size=2048,  # 2048 suffisant pour certificats finaux
            save_keys=True
        )

        # 2. Construire le certificat
        utils.print_info("\nÉtape 2/4: Construction du certificat...")
        certificate = self._build_certificate(
            dn=dn,
            public_key=private_key.public_key(),
            cert_type=cert_type,
            issuer_cert=issuer_cert,
            issuer_key=issuer_key,
            validity_days=validity_days,
            san_list=san_list
        )

        # 3. Sauvegarder
        utils.print_info("\nÉtape 3/4: Sauvegarde du certificat...")
        cert_path = self._save_certificate(certificate, entity_name)

        # 4. Enregistrer en BDD
        utils.print_info("\nÉtape 4/4: Enregistrement dans la base de données...")
        self._register_in_database(certificate, cert_path, str(pub_path))

        utils.print_success(f"\n✨ Certificat {cert_type} émis avec succès!\n")
        utils.display_cert_info(certificate)

        return certificate, cert_path

    def _build_certificate(
            self,
            dn: DistinguishedName,
            public_key,
            cert_type: str,
            issuer_cert: x509.Certificate,
            issuer_key: PrivateKeyTypes,
            validity_days: int,
            san_list: Optional[List[str]] = None
    ) -> x509.Certificate:
        """Construit et signe un certificat"""

        # Sujet
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, dn.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, dn.state or ""),
            x509.NameAttribute(NameOID.LOCALITY_NAME, dn.locality or ""),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, dn.organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, dn.organizational_unit or "Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, dn.common_name),
        ])

        # Serial, validité
        serial_number = utils.generate_serial_number()
        not_before = utils.now_utc()
        not_after = not_before + timedelta(days=validity_days)

        # Builder
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_cert.subject)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        # Extensions selon le type
        cert_builder = self._add_extensions(
            cert_builder,
            public_key,
            issuer_cert,
            cert_type,
            san_list
        )

        # Signer
        certificate = cert_builder.sign(issuer_key, hashes.SHA256())
        utils.print_success(f"Certificat construit et signé (SN: {serial_number:X})")

        return certificate

    def _add_extensions(
            self,
            cert_builder: x509.CertificateBuilder,
            public_key,
            issuer_cert: x509.Certificate,
            cert_type: str,
            san_list: Optional[List[str]] = None
    ) -> x509.CertificateBuilder:
        """Ajoute les extensions selon le type de certificat"""

        # BasicConstraints (toujours CA=False pour certificats finaux)
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )

        # KeyUsage selon le type
        if cert_type == "client":
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )

            # ExtendedKeyUsage pour client
            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False
            )

        elif cert_type == "server":
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )

            # ExtendedKeyUsage pour server
            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH  # Souvent utile
                ]),
                critical=False
            )

            # SubjectAlternativeName pour serveurs
            if san_list:
                san_entries = [x509.DNSName(name) for name in san_list]
                cert_builder = cert_builder.add_extension(
                    x509.SubjectAlternativeName(san_entries),
                    critical=False
                )

        elif cert_type == "code_signing":
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )

            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
                critical=False
            )

        # SubjectKeyIdentifier
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )

        # AuthorityKeyIdentifier
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False
        )

        return cert_builder

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

    def _register_in_database(
            self,
            certificate: x509.Certificate,
            cert_path: Path,
            pub_key_path: str
    ):
        """Enregistre dans la BDD"""
        serial_hex = f"{certificate.serial_number:X}"
        subject_dn = certificate.subject.rfc4514_string()
        issuer_dn = certificate.issuer.rfc4514_string()

        # Déterminer le type
        cert_type = "client"  # Par défaut
        try:
            eku = certificate.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            ).value

            if ExtendedKeyUsageOID.SERVER_AUTH in eku:
                cert_type = "server"
            elif ExtendedKeyUsageOID.CODE_SIGNING in eku:
                cert_type = "code_signing"
        except:
            pass

        self.db.add_certificate(
            serial_number=serial_hex,
            subject_dn=subject_dn,
            issuer_dn=issuer_dn,
            cert_type=cert_type,
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            cert_path=str(cert_path),
            public_key_path=pub_key_path
        )

        utils.print_success("Certificat enregistré dans la BDD")

    # ============================================
    # 🎯 HELPERS
    # ============================================

    def issue_client_certificate(
            self,
            user_name: str,
            organization: str,
            issuer_cert: x509.Certificate,
            issuer_key: PrivateKeyTypes,
            email: Optional[str] = None
    ) -> Tuple[x509.Certificate, Path]:
        """Helper pour émettre un certificat client"""

        dn = DistinguishedName(
            common_name=user_name,
            organization=organization,
            organizational_unit="Users",
            country=config.DN_TEMPLATE["country"],
            state=config.DN_TEMPLATE.get("state"),
            locality=config.DN_TEMPLATE.get("locality"),
            email=email
        )

        return self.issue_certificate(
            dn=dn,
            cert_type="client",
            issuer_cert=issuer_cert,
            issuer_key=issuer_key
        )

    def issue_server_certificate(
            self,
            server_name: str,
            organization: str,
            issuer_cert: x509.Certificate,
            issuer_key: PrivateKeyTypes,
            domains: List[str]
    ) -> Tuple[x509.Certificate, Path]:
        """Helper pour émettre un certificat serveur"""

        dn = DistinguishedName(
            common_name=server_name,
            organization=organization,
            organizational_unit="IT",
            country=config.DN_TEMPLATE["country"],
            state=config.DN_TEMPLATE.get("state"),
            locality=config.DN_TEMPLATE.get("locality")
        )

        return self.issue_certificate(
            dn=dn,
            cert_type="server",
            issuer_cert=issuer_cert,
            issuer_key=issuer_key,
            san_list=domains
        )


certificate_issuer = CertificateIssuer()

__all__ = ['CertificateIssuer', 'certificate_issuer']