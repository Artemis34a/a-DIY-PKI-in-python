
import os
import json
import datetime
from typing import Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption

SERIALS_PATH = "pki/serials.json"

def ensure_dirs(path):
    os.makedirs(path, exist_ok=True)

# -------------------------
# Serial management simple
# -------------------------
def _load_serials():
    if not os.path.exists(SERIALS_PATH):
        return {"next_serial": 1}
    with open(SERIALS_PATH, "r") as f:
        return json.load(f)

def _save_serials(d):
    os.makedirs(os.path.dirname(SERIALS_PATH), exist_ok=True)
    with open(SERIALS_PATH, "w") as f:
        json.dump(d, f, indent=2)

def get_next_serial():
    d = _load_serials()
    serial = d.get("next_serial", 1)
    d["next_serial"] = serial + 1
    _save_serials(d)
    return serial

# -------------------------
# Key generation
# -------------------------
def generate_rsa_key(key_size: int = 4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

def generate_ec_key(curve=ec.SECP256R1()):
    return ec.generate_private_key(curve)

def save_private_key(private_key, filepath: str, password: Optional[bytes] = None, rsa_pkcs1: bool = True):
    if password:
        enc = BestAvailableEncryption(password)
    else:
        enc = NoEncryption()
    if isinstance(private_key, rsa.RSAPrivateKey) and rsa_pkcs1:
        fmt = PrivateFormat.TraditionalOpenSSL  # PKCS#1
    else:
        fmt = PrivateFormat.PKCS8
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=fmt,
        encryption_algorithm=enc
    )
    with open(filepath, "wb") as f:
        f.write(pem)
    os.chmod(filepath, 0o600)

def save_pem_cert(cert: x509.Certificate, filepath: str):
    pem = cert.public_bytes(Encoding.PEM)
    with open(filepath, "wb") as f:
        f.write(pem)
    os.chmod(filepath, 0o644)

def load_private_key(path: str, password: Optional[bytes] = None):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password)

def load_cert(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

# -------------------------
# CSR creation for Intermediate
# -------------------------
def build_intermediate_csr(private_key, common_name: str = "My Intermediate CA", country: str = "FR",
                           state: str = "Occitanie", locality: str = "Toulouse", organization: str = "MonOrganisation"):
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    # On peut ajouter ici des extensions au CSR (ex: subjectAltName) si nécessaire
    csr = csr_builder.sign(private_key, hashes.SHA256())
    return csr

# -------------------------
# Root signs CSR -> Intermediate cert
# -------------------------
def sign_intermediate_csr(root_key, root_cert: x509.Certificate, csr: x509.CertificateSigningRequest,
                          validity_days: int = 3650, path_length: int = 0, crl_dp: Optional[str] = None):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    serial = get_next_serial()
    builder = x509.CertificateBuilder(
    ).subject_name(
        csr.subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        serial
    ).not_valid_before(
        now - datetime.timedelta(minutes=5)
    ).not_valid_after(
        now + datetime.timedelta(days=validity_days)
    )

    # Extensions for intermediate CA
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length), critical=True
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
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
        critical=False
    )

    # Optional: CRL Distribution Points
    if crl_dp:
        dp = x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(crl_dp)], relative_name=None,
                                    reasons=None, crl_issuer=None)
        builder = builder.add_extension(x509.CRLDistributionPoints([dp]), critical=False)

    cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())
    return cert

# -------------------------
# End-to-end helper: create and sign intermediate
# -------------------------
def create_intermediate(root_key_path: str, root_cert_path: str, out_dir: str = "pki/intermediate",
                        key_type: str = "rsa", key_size: int = 4096, password: Optional[str] = None,
                        common_name: str = "My Intermediate CA", validity_days: int = 3650,
                        path_length: int = 0, crl_dp: Optional[str] = None):
    ensure_dirs(out_dir)
    # load root
    root_key = load_private_key(root_key_path, password=None)  # si root_key est chiffrée, ajuster
    root_cert = load_cert(root_cert_path)

    # generate intermediate key
    if key_type.lower() == "rsa":
        interm_key = generate_rsa_key(key_size)
    elif key_type.lower() == "ec":
        interm_key = generate_ec_key()
    else:
        raise ValueError("key_type must be 'rsa' or 'ec'")

    # save private key (optionnellement chiffrée)
    key_path = os.path.join(out_dir, "interm_key.pem")
    save_private_key(interm_key, key_path, password=password.encode() if password else None)

    # create CSR
    csr = build_intermediate_csr(interm_key, common_name=common_name)
    csr_path = os.path.join(out_dir, "interm_csr.pem")
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(Encoding.PEM))

    # sign CSR with root -> intermediate cert
    cert = sign_intermediate_csr(root_key, root_cert, csr, validity_days=validity_days,
                                 path_length=path_length, crl_dp=crl_dp)
    cert_path = os.path.join(out_dir, "interm_cert.pem")
    save_pem_cert(cert, cert_path)

    print(f"Intermediate CA créée:\n - clé privée: {key_path}\n - csr: {csr_path}\n - cert signé: {cert_path}")
    return {"key_path": key_path, "csr_path": csr_path, "cert_path": cert_path}

# -------------------------
# CLI usage
# -------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Créer une Intermediate CA signée par la Root (simulation).")
    parser.add_argument("--root-key", default="./root_ca/root_key.pem", help="Chemin vers la clé privée Root")
    parser.add_argument("--root-cert", default="./root_ca/root_cert.pem", help="Chemin vers le certificat Root")
    parser.add_argument("--out-dir", default="pki/intermediate", help="Répertoire de sortie pour l'interm")
    parser.add_argument("--key-type", choices=["rsa", "ec"], default="rsa")
    parser.add_argument("--key-size", type=int, default=4096, help="Taille clé RSA (bits) si rsa")
    parser.add_argument("--password", help="Mot de passe pour chiffrer la clé interm (optionnel)")
    parser.add_argument("--cn", default="My Intermediate CA", help="Common Name")
    parser.add_argument("--days", type=int, default=3650, help="Validité (jours)")
    parser.add_argument("--path-length", type=int, default=0, help="pathLenConstraint pour BasicConstraints")
    parser.add_argument("--crl-dp", help="URL CRL Distribution Point (optionnel)")
    args = parser.parse_args()

    create_intermediate(
        root_key_path=args.root_key,
        root_cert_path=args.root_cert,
        out_dir=args.out_dir,
        key_type=args.key_type,
        key_size=args.key_size,
        password=args.password,
        common_name=args.cn,
        validity_days=args.days,
        path_length=args.path_length,
        crl_dp=args.crl_dp
    )
