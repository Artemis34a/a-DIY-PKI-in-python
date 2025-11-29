# Prérequis: pip install cryptography
import json, base64, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s.encode())

# --- Helpers pour charger clefs/certs PEM (pré-suppose fichiers PEM sur disque) ---
def load_private_key_from_pem(pem_path, password=None):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def load_cert_from_pem(pem_path):
    with open(pem_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

# --- Derive symmetric key using ECDH + HKDF ---
def derive_aes_key(my_priv_ec: ec.EllipticCurvePrivateKey, peer_pub_ec: ec.EllipticCurvePublicKey, length=32):
    shared = my_priv_ec.exchange(ec.ECDH(), peer_pub_ec)  # raw shared secret
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=b"pki-sim-aes-key")
    return hkdf.derive(shared)

# --- Create signed & encrypted message from Alice -> Bob ---
def create_signed_encrypted_message(sender_priv, sender_cert, recipient_cert, plaintext: bytes, aad: bytes = b""):
    # recipient public key (EC)
    recipient_pub = recipient_cert.public_key()
    # derive key via ECDH
    aes_key = derive_aes_key(sender_priv, recipient_pub)
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plaintext, aad)  # returns ciphertext || tag (GCM)
    # sign (iv || ciphertext || aad)
    to_sign = iv + ciphertext + aad
    signature = sender_priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))
    packet = {
        "sender_cert_pem": sender_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "iv": b64(iv),
        "ciphertext": b64(ciphertext),
        "signature": b64(signature),
        "aad": b64(aad)
    }
    return json.dumps(packet)

# --- Verify & decrypt at Bob ---
def verify_and_decrypt(packet_json: str, recipient_priv, ca_chain_callback=None):
    pkt = json.loads(packet_json)
    sender_cert = x509.load_pem_x509_certificate(pkt["sender_cert_pem"].encode())
    # Optional: vérifier la chaîne + OCSP/CRL via ca_chain_callback(sender_cert)
    # derive key
    sender_pub = sender_cert.public_key()
    aes_key = derive_aes_key(recipient_priv, sender_pub)
    iv = unb64(pkt["iv"])
    ciphertext = unb64(pkt["ciphertext"])
    signature = unb64(pkt["signature"])
    aad = unb64(pkt["aad"])
    # verify signature
    to_verify = iv + ciphertext + aad
    try:
        sender_pub.verify(signature, to_verify, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        raise ValueError("Signature invalide") from e
    # decrypt
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, aad)
    return plaintext

# --- Exemple d'utilisation (présuppose fichiers keys/certs: alice_key.pem, alice_cert.pem, bob_key.pem, bob_cert.pem)
if __name__ == "__main__":
    # Charger clés/certs (générés par ta CA)
    alice_priv = load_private_key_from_pem("alice_key.pem")
    alice_cert = load_cert_from_pem("alice_cert.pem")
    bob_priv = load_private_key_from_pem("bob_key.pem")
    bob_cert = load_cert_from_pem("bob_cert.pem")

    msg = b"Salut Bob, voici les donnees secretes."
    aad = b"msg-id:12345;ts:2025-11-25T02:00:00Z"

    packet = create_signed_encrypted_message(alice_priv, alice_cert, bob_cert, msg, aad)
    print("Paquet JSON envoyé:\n", packet)

    # Bob reçoit
    plaintext = verify_and_decrypt(packet, bob_priv)
    print("Bob dechiffre:", plaintext)
