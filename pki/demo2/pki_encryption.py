#!/usr/bin/env python3
"""
Extensions de chiffrement pour le système PKI
Chiffrement hybride RSA + AES
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import os
import base64


def encrypt_message(message: bytes, recipient_cert: x509.Certificate) -> dict:
    """
    Chiffre un message avec chiffrement hybride RSA+AES

    Args:
        message: Message à chiffrer
        recipient_cert: Certificat du destinataire (pour sa clé publique)

    Returns:
        dict: {
            'encrypted_key': clé AES chiffrée avec RSA,
            'encrypted_message': message chiffré avec AES,
            'iv': vecteur d'initialisation
        }
    """
    # 1. Générer une clé AES aléatoire (256 bits)
    aes_key = os.urandom(32)

    # 2. Générer un IV (Initialization Vector)
    iv = os.urandom(16)

    # 3. Chiffrer le message avec AES-CBC
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Padding PKCS7
    padding_length = 16 - (len(message) % 16)
    padded_message = message + bytes([padding_length] * padding_length)

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # 4. Chiffrer la clé AES avec la clé publique RSA du destinataire
    recipient_public_key = recipient_cert.public_key()
    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
        'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }


def decrypt_message(encrypted_data: dict, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Déchiffre un message chiffré avec chiffrement hybride

    Args:
        encrypted_data: Données chiffrées (dict)
        private_key: Clé privée du destinataire

    Returns:
        bytes: Message déchiffré
    """
    # 1. Déchiffrer la clé AES avec la clé privée RSA
    encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
    aes_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 2. Déchiffrer le message avec la clé AES
    encrypted_message = base64.b64decode(encrypted_data['encrypted_message'])
    iv = base64.b64decode(encrypted_data['iv'])

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # 3. Retirer le padding PKCS7
    padding_length = padded_message[-1]
    message = padded_message[:-padding_length]

    return message


def sign_and_encrypt_message(
        message: bytes,
        sender_private_key: rsa.RSAPrivateKey,
        sender_cert: x509.Certificate,
        recipient_cert: x509.Certificate
) -> dict:
    """
    Signe puis chiffre un message

    Args:
        message: Message à envoyer
        sender_private_key: Clé privée de l'émetteur
        sender_cert: Certificat de l'émetteur
        recipient_cert: Certificat du destinataire

    Returns:
        dict: Message signé et chiffré avec métadonnées
    """
    # 1. Signer le message
    signature = sender_private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 2. Chiffrer le message
    encrypted_data = encrypt_message(message, recipient_cert)

    # 3. Retourner tout ensemble
    return {
        'encrypted_message': encrypted_data,
        'signature': base64.b64encode(signature).decode('utf-8'),
        'sender_cert_serial': f"{sender_cert.serial_number:X}",
        'sender_cert': base64.b64encode(
            sender_cert.public_bytes(serialization.Encoding.PEM)
        ).decode('utf-8')
    }


def decrypt_and_verify_message(
        encrypted_data: dict,
        recipient_private_key: rsa.RSAPrivateKey,
        check_revocation_func=None
) -> tuple:
    """
    Déchiffre et vérifie la signature d'un message

    Args:
        encrypted_data: Données chiffrées et signées
        recipient_private_key: Clé privée du destinataire
        check_revocation_func: Fonction pour vérifier la révocation

    Returns:
        tuple: (success: bool, message: bytes or str, sender_serial: str)
    """
    try:
        # 1. Charger le certificat de l'émetteur
        sender_cert_pem = base64.b64decode(encrypted_data['sender_cert'])
        sender_cert = x509.load_pem_x509_certificate(sender_cert_pem)
        sender_serial = encrypted_data['sender_cert_serial']

        # 2. Vérifier la révocation
        if check_revocation_func:
            revocation_status = check_revocation_func(sender_serial)
            if revocation_status['status'] == 'revoked':
                return (
                    False,
                    f"⚠️ CERTIFICAT RÉVOQUÉ: {revocation_status['reason']}",
                    sender_serial
                )

        # 3. Déchiffrer le message
        message = decrypt_message(
            encrypted_data['encrypted_message'],
            recipient_private_key
        )

        # 4. Vérifier la signature
        signature = base64.b64decode(encrypted_data['signature'])
        sender_public_key = sender_cert.public_key()

        sender_public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return (True, message, sender_serial)

    except Exception as e:
        return (False, f"Erreur déchiffrement/vérification: {str(e)}", None)


def export_cert_for_sharing(cert: x509.Certificate) -> str:
    """Exporte un certificat en base64 pour partage"""
    return base64.b64encode(
        cert.public_bytes(serialization.Encoding.PEM)
    ).decode('utf-8')


def import_cert_from_string(cert_b64: str) -> x509.Certificate:
    """Importe un certificat depuis une chaîne base64"""
    cert_pem = base64.b64decode(cert_b64)
    return x509.load_pem_x509_certificate(cert_pem)