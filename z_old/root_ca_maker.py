
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os

def generate_root_key(key_size: int = 4096):
    """Génère une clé privée RSA."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    # RSA = Rivest-Shamir-Adleman
    # Pre-built model for generating RSA private keys

def build_root_cert(
    private_key,
    subject_common_name: str = "Artemis",
    country: str = "FR",
    state: str = "Mfoundi",
    locality: str = "Yaounde",
    organization: str = "TestPKI",
    validity_days: int = 2 * 365, # Une validité de deux (02) ans.
    path_length: int = 1,
        # ces attribut regroupent ceux de l'entité à certifier et les spécificités du certificat.
):
    """Construction d'un certificat X.509 auto-signé (Root CA).
    Un certificat X.509 est un certificat numérique standardisé,
    défini par l'Union internationale des télécommunications (UIT),
    qui utilise une infrastructure à clés publiques (PKI).
     Il lie de manière sécurisée une clé publique à une identité
     (telle qu'une personne, une organisation, un appareil ou un site web). Signature. """

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name),
    ])
    # Ici, l'identité d'un sujet est constituée de :
    # son nom, son pays, sa province, sa ville et le nom de l'organization

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cert_builder = x509.CertificateBuilder( # Genérateur de certificats pre-built dans le package Cryptography
        # selon les normes standardisés du x509.
    ).subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - datetime.timedelta(minutes=5)
    ).not_valid_after(
        now + datetime.timedelta(days=validity_days)
    )

    # Extensions essentielles pour une Root CA
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
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
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False
    )

    # Signer (auto-sign)
    cert = cert_builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    return cert

def save_private_key_to_pem(private_key, filepath: str, password: bytes = None):
    """Enregistre la clé privée en PEM. Si password est fourni, la clé est chiffrée."""
    if password:
        enc_algo = serialization.BestAvailableEncryption(password)
    else:
        enc_algo = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1 pour RSA
        encryption_algorithm=enc_algo
    )
    with open(filepath, "wb") as f:
        f.write(pem)
    os.chmod(filepath, 0o600)

def save_cert_to_pem(cert: x509.Certificate, filepath: str):
    """Enregistre le certificat en PEM."""
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(filepath, "wb") as f:
        f.write(pem)
    os.chmod(filepath, 0o644)

def load_private_key_from_pem(pem_path: str, password: bytes = None):
    with open(pem_path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password)

def load_cert_from_pem(pem_path: str):
    with open(pem_path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)

# CLI-like utility usage
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Générer une Root CA (clé privée + certificat auto-signé).")
    parser.add_argument("--out-dir", default="root_ca", help="Répertoire de sortie")
    parser.add_argument("--cn", default="My Test Root CA", help="Common Name du Root CA")
    parser.add_argument("--org", default="MonOrganisation", help="Organization Name")
    parser.add_argument("--days", type=int, default=3650, help="Durée de validité (jours)")
    parser.add_argument("--password", help="Mot de passe pour chiffrer la clé privée (optionnel)")
    parser.add_argument("--key-size", type=int, default=4096, help="Taille clé RSA (bits)")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    key = generate_root_key(key_size=args.key_size)
    cert = build_root_cert(
        key,
        subject_common_name=args.cn,
        organization=args.org,
        validity_days=args.days,
    )

    key_path = os.path.join(args.out_dir, "root_key.pem")
    cert_path = os.path.join(args.out_dir, "root_cert.pem")
    password_bytes = args.password.encode() if args.password else None

    save_private_key_to_pem(key, key_path, password=password_bytes)
    save_cert_to_pem(cert, cert_path)

    print(f"Root CA générée:\n - clé privée: {key_path}\n - certificat: {cert_path}")
    if args.password:
        print("La clé privée est chiffrée avec le mot de passe fourni.")
    else:
        print("La clé privée n'est PAS chiffrée — attention (mode simulation).")
