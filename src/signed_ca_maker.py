# intermediate_ca.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# load root key and cert (in real life root key stays offline)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
with open("root_key.pem","rb") as f:
    root_key = load_pem_private_key(f.read(), password=b"changeit")
with open("root_cert.pem","rb") as f:
    root_cert = x509.load_pem_x509_certificate(f.read())

# create intermediate key
int_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

int_name = x509.Name([
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Example Org"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"My Intermediate CA"),
])

csr = x509.CertificateSigningRequestBuilder().subject_name(int_name).sign(int_key, hashes.SHA256())

# Build intermediate certificate (signed by root)
int_cert = (
    x509.CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(root_cert.subject)
    .public_key(int_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.KeyUsage(key_cert_sign=True, crl_sign=True,
                                 digital_signature=False, content_commitment=False,
                                 key_encipherment=False, data_encipherment=False,
                                 key_agreement=False, encipher_only=False, decipher_only=False),
                   critical=True)
    .sign(root_key, hashes.SHA256())
)

# save intermediate
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
with open("int_key.pem","wb") as f:
    f.write(int_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
with open("int_cert.pem","wb") as f:
    f.write(int_cert.public_bytes(Encoding.PEM))

print("Intermediate CA created: int_key.pem, int_cert.pem")
