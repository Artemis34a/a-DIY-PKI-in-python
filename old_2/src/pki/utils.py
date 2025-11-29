"""
Fonctions utilitaires pour le système PKI
"""

import os
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from . import config

# Console Rich pour l'affichage
console = Console()


# ============================================
# 🔐 FONCTIONS CRYPTOGRAPHIQUES
# ============================================

def generate_serial_number() -> int:
    """
    Génère un numéro de série unique pour un certificat
    Utilise un générateur cryptographiquement sécurisé (160 bits comme recommandé par RFC 5280)

    Returns:
        int: Numéro de série unique
    """
    return secrets.randbits(100)


def calculate_fingerprint(cert: x509.Certificate, algorithm: str = "sha256") -> str:
    """
    Calcule l'empreinte (fingerprint) d'un certificat

    Args:
        cert: Certificat X.509
        algorithm: Algorithme de hachage ('sha256' ou 'sha1')

    Returns:
        str: Empreinte au format hexadécimal avec séparateurs (ex: "A1:B2:C3:...")
    """
    cert_bytes = cert.public_bytes(serialization.Encoding.DER)

    if algorithm.lower() == "sha256":
        hash_obj = hashlib.sha256(cert_bytes)
    elif algorithm.lower() == "sha1":
        hash_obj = hashlib.sha1(cert_bytes)
    else:
        raise ValueError(f"Algorithme non supporté: {algorithm}")

    # Formater en paires d'octets séparées par ':'
    fingerprint = hash_obj.hexdigest().upper()
    return ':'.join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))


def generate_password(length: int = 32) -> str:
    """
    Génère un mot de passe cryptographiquement sécurisé

    Args:
        length: Longueur du mot de passe

    Returns:
        str: Mot de passe aléatoire
    """
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# ============================================
# 📁 GESTION DES FICHIERS
# ============================================

def ensure_directory(path: Path) -> None:
    """
    Crée un répertoire et ses parents s'ils n'existent pas

    Args:
        path: Chemin du répertoire à créer
    """
    path.mkdir(parents=True, exist_ok=True)


def set_file_permissions(filepath: Path, permissions: int) -> None:
    """
    Définit les permissions d'un fichier (Unix uniquement)
    Sur Windows, cette fonction ne fait rien

    Args:
        filepath: Chemin du fichier
        permissions: Permissions en octal (ex: 0o600 pour rw-------)
    """
    if os.name != 'nt':  # Pas Windows
        try:
            os.chmod(filepath, permissions)
        except Exception as e:
            print_warning(f"Impossible de définir les permissions: {e}")


def secure_delete(filepath: Path, passes: int = 3) -> None:
    """
    Supprime un fichier de manière sécurisée
    Écrase le contenu plusieurs fois avant suppression

    Args:
        filepath: Chemin du fichier à supprimer
        passes: Nombre de passes d'écrasement
    """
    if not filepath.exists():
        return

    try:
        file_size = filepath.stat().st_size

        # Écraser le fichier plusieurs fois
        with open(filepath, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())

        # Supprimer le fichier
        filepath.unlink()

    except Exception as e:
        print_error(f"Erreur lors de la suppression sécurisée: {e}")


# ============================================
# 📅 GESTION DES DATES
# ============================================

def now_utc() -> datetime:
    """
    Retourne la date/heure actuelle en UTC avec timezone

    Returns:
        datetime: Date/heure actuelle en UTC
    """
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> str:
    """
    Formate une date/heure en chaîne

    Args:
        dt: Date/heure à formater
        fmt: Format de sortie (strftime)

    Returns:
        str: Date/heure formatée
    """
    return dt.strftime(fmt)


def parse_datetime(dt_str: str, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> datetime:
    """
    Parse une chaîne de date/heure

    Args:
        dt_str: Chaîne à parser
        fmt: Format d'entrée (strptime)

    Returns:
        datetime: Date/heure parsée
    """
    return datetime.strptime(dt_str, fmt)


# ============================================
# 🎨 AFFICHAGE CLI AVEC RICH
# ============================================

def print_success(message: str) -> None:
    """Affiche un message de succès avec symbole et couleur verte"""
    console.print(f"[green]{config.CLI_SYMBOLS['success']} {message}[/green]")


def print_error(message: str) -> None:
    """Affiche un message d'erreur avec symbole et couleur rouge"""
    console.print(f"[red]{config.CLI_SYMBOLS['error']} {message}[/red]")


def print_warning(message: str) -> None:
    """Affiche un avertissement avec symbole et couleur jaune"""
    console.print(f"[yellow]{config.CLI_SYMBOLS['warning']} {message}[/yellow]")


def print_info(message: str) -> None:
    """Affiche une information avec symbole et couleur cyan"""
    console.print(f"[cyan]{config.CLI_SYMBOLS['info']} {message}[/cyan]")


def print_header(title: str) -> None:
    """
    Affiche un en-tête stylisé avec bordure

    Args:
        title: Titre à afficher
    """
    console.print()
    console.print(Panel.fit(
        f"[bold magenta]{title}[/bold magenta]",
        border_style="magenta",
        box=box.DOUBLE
    ))
    console.print()


def create_table(title: str, columns: list) -> Table:
    """
    Crée une table Rich stylisée prête à être remplie

    Args:
        title: Titre de la table
        columns: Liste des noms de colonnes

    Returns:
        Table: Table Rich
    """
    table = Table(
        title=title,
        title_style="bold cyan",
        border_style="blue",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta"
    )

    for col in columns:
        table.add_column(col)

    return table


def display_cert_info(cert: x509.Certificate) -> None:
    """
    Affiche les informations d'un certificat X.509 de manière formatée

    Args:
        cert: Certificat X.509 à afficher
    """
    table = create_table(f"{config.CLI_SYMBOLS['cert']} Informations du certificat", ["Champ", "Valeur"])

    # Sujet
    subject = cert.subject.rfc4514_string()
    table.add_row("Sujet", f"[cyan]{subject}[/cyan]")

    # Émetteur
    issuer = cert.issuer.rfc4514_string()
    table.add_row("Émetteur", f"[yellow]{issuer}[/yellow]")

    # Numéro de série
    serial = f"{cert.serial_number:X}"
    table.add_row("N° Série", f"[green]{serial}[/green]")

    # Validité
    not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    table.add_row("Valide de", not_before)
    table.add_row("Valide jusqu'à", not_after)

    # Empreinte SHA-256
    fingerprint = calculate_fingerprint(cert, "sha256")
    table.add_row("Empreinte SHA-256", f"[dim]{fingerprint}[/dim]")

    console.print(table)


# ============================================
# 🔍 VALIDATION
# ============================================

def validate_dn(dn_dict: Dict[str, str]) -> bool:
    """
    Valide un Distinguished Name (DN)

    Args:
        dn_dict: Dictionnaire contenant les champs du DN

    Returns:
        bool: True si le DN est valide, False sinon
    """
    required_fields = ["country", "organization", "common_name"]

    # Vérifier les champs requis
    for field in required_fields:
        if field not in dn_dict or not dn_dict[field]:
            print_error(f"Champ requis manquant dans le DN: {field}")
            return False

    # Valider le code pays (2 lettres)
    if len(dn_dict["country"]) != 2:
        print_error("Le code pays doit contenir exactement 2 lettres (ISO 3166-1 alpha-2)")
        return False

    # Valider que les champs ne sont pas vides
    for field, value in dn_dict.items():
        if value and not str(value).strip():
            print_error(f"Le champ '{field}' ne peut pas être vide")
            return False

    return True


def validate_key_size(key_type: str, size: int) -> bool:
    """
    Valide la taille d'une clé cryptographique

    Args:
        key_type: Type de clé ("rsa" ou "ecc")
        size: Taille de la clé en bits

    Returns:
        bool: True si la taille est valide
    """
    if key_type.lower() == "rsa":
        valid_sizes = list(config.RSA_KEY_SIZES.values())
        if size not in valid_sizes:
            print_error(f"Taille RSA invalide: {size}. Valeurs autorisées: {valid_sizes}")
            return False

    elif key_type.lower() == "ecc":
        valid_sizes = [256, 384, 521]  # Tailles des courbes ECC
        if size not in valid_sizes:
            print_error(f"Taille ECC invalide: {size}. Valeurs autorisées: {valid_sizes}")
            return False

    else:
        print_error(f"Type de clé inconnu: {key_type}")
        return False

    return True


# ============================================
# 📊 STATISTIQUES ET FORMATAGE
# ============================================

def format_bytes(bytes_count: int) -> str:
    """
    Formate un nombre d'octets en unité lisible (KB, MB, etc.)

    Args:
        bytes_count: Nombre d'octets

    Returns:
        str: Taille formatée (ex: "1.5 KB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def get_file_info(filepath: Path) -> Dict[str, Any]:
    """
    Récupère les informations sur un fichier

    Args:
        filepath: Chemin du fichier

    Returns:
        dict: Informations (taille, dates, permissions)
    """
    if not filepath.exists():
        return {}

    stat = filepath.stat()

    return {
        "size": format_bytes(stat.st_size),
        "size_bytes": stat.st_size,
        "created": datetime.fromtimestamp(stat.st_ctime),
        "modified": datetime.fromtimestamp(stat.st_mtime),
        "permissions": oct(stat.st_mode)[-3:]
    }


# ============================================
# 🔄 CONVERSION
# ============================================

def bytes_to_hex(data: bytes, separator: str = ":") -> str:
    """
    Convertit des bytes en chaîne hexadécimale

    Args:
        data: Données binaires
        separator: Séparateur entre octets (ex: ":")

    Returns:
        str: Chaîne hexadécimale (ex: "A1:B2:C3")
    """
    hex_str = data.hex().upper()
    if separator:
        return separator.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))
    return hex_str


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convertit une chaîne hexadécimale en bytes

    Args:
        hex_str: Chaîne hexadécimale (avec ou sans séparateurs)

    Returns:
        bytes: Données binaires
    """
    # Retirer les séparateurs courants
    cleaned = hex_str.replace(":", "").replace(" ", "").replace("-", "")
    return bytes.fromhex(cleaned)


# ============================================
# 🎯 HELPERS DIVERS
# ============================================

def truncate_string(s: str, max_length: int = 50, suffix: str = "...") -> str:
    """
    Tronque une chaîne si elle est trop longue

    Args:
        s: Chaîne à tronquer
        max_length: Longueur maximale
        suffix: Suffixe à ajouter si tronqué

    Returns:
        str: Chaîne tronquée
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def confirm_action(message: str, default: bool = False) -> bool:
    """
    Demande confirmation à l'utilisateur via l'entrée console

    Args:
        message: Message à afficher
        default: Réponse par défaut si l'utilisateur appuie sur Entrée

    Returns:
        bool: True si l'utilisateur confirme
    """
    options = "[Y/n]" if default else "[y/N]"
    response = console.input(f"[yellow]{message} {options}:[/yellow] ").strip().lower()

    if not response:
        return default

    return response in ['y', 'yes', 'oui', 'o']


# ============================================
# 🎨 EXPORTS
# ============================================

__all__ = [
    # Crypto
    'generate_serial_number', 'calculate_fingerprint', 'generate_password',

    # Fichiers
    'ensure_directory', 'set_file_permissions', 'secure_delete',

    # Dates
    'now_utc', 'format_datetime', 'parse_datetime',

    # Affichage CLI
    'print_success', 'print_error', 'print_warning', 'print_info', 'print_header',
    'create_table', 'display_cert_info',

    # Validation
    'validate_dn', 'validate_key_size',

    # Stats et formatage
    'format_bytes', 'get_file_info',

    # Conversion
    'bytes_to_hex', 'hex_to_bytes',

    # Helpers
    'truncate_string', 'confirm_action',

    # Console Rich
    'console'
]