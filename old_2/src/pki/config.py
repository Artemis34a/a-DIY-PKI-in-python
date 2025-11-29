"""
Configuration globale du système PKI
Contient toutes les constantes et paramètres du projet
"""

import os
from pathlib import Path
from datetime import timedelta

# ============================================
# 📁 CHEMINS DES RÉPERTOIRES
# ============================================

# Répertoire racine du projet (remonte de src/pki vers la racine)
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Répertoires de données
DATA_DIR = BASE_DIR / "data"
KEYS_DIR = DATA_DIR / "keys"
CERTS_DIR = DATA_DIR / "certs"
CRL_DIR = DATA_DIR / "crl"
DB_DIR = DATA_DIR / "db"
LOGS_DIR = BASE_DIR / "logs"

# Créer les répertoires s'ils n'existent pas
for directory in [DATA_DIR, KEYS_DIR, CERTS_DIR, CRL_DIR, DB_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# ============================================
# 🔐 PARAMÈTRES CRYPTOGRAPHIQUES
# ============================================

# Tailles de clés RSA supportées
RSA_KEY_SIZES = {
    "weak": 2048,  # Pour tests uniquement
    "standard": 3072,  # Recommandé
    "strong": 4096  # Maximum sécurité
}

# Courbes ECC supportées
ECC_CURVES = {
    "secp256r1": "SECP256R1",  # NIST P-256 (recommandé)
    "secp384r1": "SECP384R1",  # NIST P-384
    "secp521r1": "SECP521R1"  # NIST P-521
}

# Algorithme de hachage par défaut
DEFAULT_HASH_ALGORITHM = "SHA256"

# Exposant public RSA (standard)
RSA_PUBLIC_EXPONENT = 65537

# ============================================
# 📜 PARAMÈTRES DES CERTIFICATS X.509
# ============================================

# Durées de validité par défaut (en jours)
VALIDITY_PERIODS = {
    "root_ca": 7300,  # 20 ans
    "intermediate_ca": 3650,  # 10 ans
    "server": 825,  # ~2 ans (conforme aux standards modernes)
    "client": 397,  # ~1 an
    "code_signing": 1095  # 3 ans
}

# Extensions X.509 par type de certificat
EXTENSIONS_CONFIG = {
    "root_ca": {
        "basic_constraints": {"ca": True, "path_length": 1},
        "key_usage": ["key_cert_sign", "crl_sign"],
        "subject_key_identifier": True,
        "authority_key_identifier": True
    },
    "intermediate_ca": {
        "basic_constraints": {"ca": True, "path_length": 0},
        "key_usage": ["key_cert_sign", "crl_sign"],
        "subject_key_identifier": True,
        "authority_key_identifier": True
    },
    "server": {
        "basic_constraints": {"ca": False},
        "key_usage": ["digital_signature", "key_encipherment"],
        "extended_key_usage": ["server_auth"],
        "subject_key_identifier": True,
        "authority_key_identifier": True
    },
    "client": {
        "basic_constraints": {"ca": False},
        "key_usage": ["digital_signature"],
        "extended_key_usage": ["client_auth"],
        "subject_key_identifier": True,
        "authority_key_identifier": True
    }
}

# ============================================
# 🗄️ PARAMÈTRES BASE DE DONNÉES
# ============================================

DATABASE_PATH = DB_DIR / "pki_database.db"

# Schémas des tables
DB_TABLES = {
    "certificates": """
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT UNIQUE NOT NULL,
            subject_dn TEXT NOT NULL,
            issuer_dn TEXT NOT NULL,
            cert_type TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            not_before TEXT NOT NULL,
            not_after TEXT NOT NULL,
            public_key_path TEXT,
            cert_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            revocation_reason TEXT
        )
    """,
    "csr_requests": """
        CREATE TABLE IF NOT EXISTS csr_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE NOT NULL,
            subject_dn TEXT NOT NULL,
            cert_type TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            csr_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            approved_at TEXT,
            rejected_at TEXT,
            rejection_reason TEXT
        )
    """,
    "revocations": """
        CREATE TABLE IF NOT EXISTS revocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT NOT NULL,
            revocation_date TEXT NOT NULL,
            reason TEXT NOT NULL,
            crl_published BOOLEAN DEFAULT 0,
            FOREIGN KEY (serial_number) REFERENCES certificates(serial_number)
        )
    """,
    "audit_log": """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            details TEXT,
            success BOOLEAN NOT NULL
        )
    """
}

# ============================================
# 📋 PARAMÈTRES CRL / OCSP
# ============================================

# Durée de validité d'une CRL (en heures)
CRL_VALIDITY_HOURS = 24

# Intervalle de mise à jour CRL (en heures)
CRL_UPDATE_INTERVAL = 6

# Raisons de révocation valides (RFC 5280)
REVOCATION_REASONS = [
    "unspecified",
    "key_compromise",
    "ca_compromise",
    "affiliation_changed",
    "superseded",
    "cessation_of_operation",
    "certificate_hold",
    "remove_from_crl",
    "privilege_withdrawn"
]

# ============================================
# 🎨 PARAMÈTRES D'AFFICHAGE CLI
# ============================================

# Couleurs pour Rich
CLI_COLORS = {
    "success": "green",
    "error": "red",
    "warning": "yellow",
    "info": "cyan",
    "header": "magenta bold",
    "cert": "blue",
    "key": "yellow"
}

# Symboles pour l'affichage
CLI_SYMBOLS = {
    "success": "✓",
    "error": "✗",
    "warning": "⚠",
    "info": "ℹ",
    "cert": "📜",
    "key": "🔑",
    "root": "👑",
    "intermediate": "🌐",
    "client": "👤",
    "server": "🖥️"
}

# ============================================
# 📊 PARAMÈTRES DE LOGS
# ============================================

LOG_FILE = LOGS_DIR / "pki.log"
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ============================================
# 🔒 SÉCURITÉ
# ============================================

# Permissions des fichiers (Unix)
PRIVATE_KEY_PERMISSIONS = 0o600  # rw------- (propriétaire seulement)
CERT_PERMISSIONS = 0o644  # rw-r--r-- (lecture publique)
DIR_PERMISSIONS = 0o755  # rwxr-xr-x

# Chiffrement des clés privées
ENCRYPT_PRIVATE_KEYS = True
DEFAULT_KEY_ENCRYPTION_ALGORITHM = "AES256"

# ============================================
# 🎯 PARAMÈTRES DE SIMULATION
# ============================================

# Utilisateurs simulés pour les tests Alice/Bob
SIMULATED_USERS = ["alice", "bob", "charlie", "dave"]

# Scénarios de test disponibles
TEST_SCENARIOS = [
    "basic_exchange",
    "revocation_test",
    "chain_validation",
    "signature_verification",
    "cian_validation"
]


# ============================================
# 🛠️ FONCTIONS UTILITAIRES DE CONFIG
# ============================================

def get_key_path(entity_name: str, key_type: str = "private") -> Path:
    """
    Retourne le chemin d'une clé

    Args:
        entity_name: Nom de l'entité (ex: "alice", "root_ca")
        key_type: Type de clé ("private" ou "public")

    Returns:
        Path: Chemin complet vers le fichier de clé
    """
    suffix = "key.pem" if key_type == "private" else "pubkey.pem"
    return KEYS_DIR / f"{entity_name}_{suffix}"


def get_cert_path(entity_name: str) -> Path:
    """
    Retourne le chemin d'un certificat

    Args:
        entity_name: Nom de l'entité

    Returns:
        Path: Chemin complet vers le fichier certificat
    """
    return CERTS_DIR / f"{entity_name}_cert.pem"


def get_crl_path() -> Path:
    """
    Retourne le chemin de la CRL actuelle

    Returns:
        Path: Chemin vers le fichier CRL
    """
    return CRL_DIR / "current.crl"


def get_validity_period(cert_type: str) -> int:
    """
    Retourne la période de validité en jours pour un type de certificat

    Args:
        cert_type: Type de certificat (root_ca, client, server, etc.)

    Returns:
        int: Nombre de jours de validité
    """
    return VALIDITY_PERIODS.get(cert_type, VALIDITY_PERIODS["client"])


# ============================================
# 📝 INFORMATIONS DN (Distinguished Name)
# ============================================

# Template pour les Distinguished Names
DN_TEMPLATE = {
    "country": "CM",  # Cameroun
    "state": "Adamaoua",
    "locality": "Ngaoundéré",
    "organization": "PKI Test Organization",
    "organizational_unit": "IT Security",
    "common_name": None  # À définir par l'utilisateur
}

# ============================================
# 🚀 EXPORTS
# ============================================

__all__ = [
    # Répertoires
    'BASE_DIR', 'DATA_DIR', 'KEYS_DIR', 'CERTS_DIR', 'CRL_DIR', 'DB_DIR', 'LOGS_DIR',

    # Paramètres crypto
    'RSA_KEY_SIZES', 'ECC_CURVES', 'DEFAULT_HASH_ALGORITHM', 'RSA_PUBLIC_EXPONENT',

    # Certificats
    'VALIDITY_PERIODS', 'EXTENSIONS_CONFIG', 'DN_TEMPLATE',

    # Base de données
    'DATABASE_PATH', 'DB_TABLES',

    # Révocations
    'REVOCATION_REASONS', 'CRL_VALIDITY_HOURS', 'CRL_UPDATE_INTERVAL',

    # Interface CLI
    'CLI_COLORS', 'CLI_SYMBOLS',

    # Logs
    'LOG_FILE', 'LOG_LEVEL', 'LOG_FORMAT', 'LOG_DATE_FORMAT',

    # Sécurité
    'PRIVATE_KEY_PERMISSIONS', 'CERT_PERMISSIONS', 'DIR_PERMISSIONS',
    'ENCRYPT_PRIVATE_KEYS', 'DEFAULT_KEY_ENCRYPTION_ALGORITHM',

    # Simulation
    'SIMULATED_USERS', 'TEST_SCENARIOS',

    # Fonctions utilitaires
    'get_key_path', 'get_cert_path', 'get_crl_path', 'get_validity_period'
]