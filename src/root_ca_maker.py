# root_ca.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# generate root private key
root_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

# build subject/issuer (self-signed)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Example Org"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"My Root CA"),
])

root_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(root_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=1))
    .not_valid_after(datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=3650))  # 10 years
    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True,)
    .add_extension(x509.KeyUsage(key_cert_sign=True, crl_sign=True,
                                 digital_signature=False, content_commitment=False,
                                 key_encipherment=False, data_encipherment=False,
                                 key_agreement=False, encipher_only=False, decipher_only=False),
                   critical=True,)
    .sign(root_key, hashes.SHA256())
)

# write to disk (protect these files!)
with open("root_key.pem", "wb") as f:
    f.write(root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL, # or PKCS8
        encryption_algorithm=serialization.BestAvailableEncryption(b"changeit")
    ))

with open("root_cert.pem", "wb") as f:
    f.write(root_cert.public_bytes(serialization.Encoding.PEM))

print("Root CA generated: root_key.pem (encrypted), root_cert.pem")
