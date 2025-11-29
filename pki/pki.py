#!/usr/bin/env python3
"""
PKI Simple - Infrastructure à Clés Publiques
Tout en un seul fichier, sans SQL
"""

import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from tqdm import tqdm
import secrets

console = Console()

# ============================================
# 📁 CONFIGURATION
# ============================================

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
KEYS_DIR = DATA_DIR / "keys"
CERTS_DIR = DATA_DIR / "certs"
REGISTRY_FILE = DATA_DIR / "registry.json"

# Créer les répertoires
for d in [DATA_DIR, KEYS_DIR, CERTS_DIR]:
    d.mkdir(exist_ok=True)


# ============================================
# 📋 REGISTRE JSON (remplace SQL)
# ============================================

def load_registry() -> Dict:
    """Charge le registre JSON"""
    if REGISTRY_FILE.exists():
        with open(REGISTRY_FILE, 'r') as f:
            return json.load(f)
    return {
        "certificates": {},
        "revoked": [],
        "csr_requests": {}
    }


def save_registry(registry: Dict):
    """Sauvegarde le registre JSON"""
    with open(REGISTRY_FILE, 'w') as f:
        json.dump(registry, f, indent=2, default=str)


# ============================================
# 🔑 GÉNÉRATION DE CLÉS
# ============================================

def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Génère une clé RSA"""
    console.print(f"[cyan]🔑 Génération clé RSA {key_size} bits...[/cyan]")

    with tqdm(total=100, desc="Génération", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        pbar.update(100)

    console.print("[green]✓ Clé générée[/green]")
    return key


def save_key(key: rsa.RSAPrivateKey, name: str, password: Optional[str] = None):
    """Sauvegarde une clé privée"""
    key_path = KEYS_DIR / f"{name}_key.pem"

    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )

    key_path.write_bytes(pem)
    console.print(f"[green]✓ Clé sauvegardée: {key_path.name}[/green]")
    return key_path


def load_key(name: str, password: Optional[str] = None) -> rsa.RSAPrivateKey:
    """Charge une clé privée"""
    key_path = KEYS_DIR / f"{name}_key.pem"

    if not key_path.exists():
        raise FileNotFoundError(f"Clé introuvable: {key_path}")

    pem = key_path.read_bytes()
    pwd = password.encode() if password else None

    key = serialization.load_pem_private_key(pem, password=pwd, backend=default_backend())
    console.print(f"[green]✓ Clé chargée: {key_path.name}[/green]")
    return key


# ============================================
# 👑 ROOT CA
# ============================================

def create_root_ca(
        common_name: str = "Root CA",
        organization: str = "PKI Org",
        key_size: int = 4096,
        validity_days: int = 7300,
        password: Optional[str] = None
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Crée une Root CA complète"""

    console.print(Panel.fit(
        "[bold magenta]👑 Création de la Root CA[/bold magenta]",
        border_style="magenta"
    ))

    # 1. Générer la clé
    private_key = generate_rsa_key(key_size)

    # 2. Créer le certificat
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CM"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    serial = secrets.randbits(150)
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True
        )
        .add_extension(
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        .sign(private_key, hashes.SHA256())
    )

    # 3. Sauvegarder
    save_key(private_key, "root_ca", password)
    cert_path = CERTS_DIR / "root_ca_cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # 4. Enregistrer
    registry = load_registry()
    registry["certificates"][f"{serial:X}"] = {
        "type": "root_ca",
        "subject": common_name,
        "serial": f"{serial:X}",
        "not_before": now.isoformat(),
        "not_after": (now + timedelta(days=validity_days)).isoformat(),
        "status": "active",
        "path": str(cert_path)
    }
    save_registry(registry)

    console.print("[green]✓ Root CA créée avec succès![/green]\n")
    display_cert_info(cert)

    return cert, private_key


# ============================================
# 🌐 INTERMEDIATE CA
# ============================================

def create_intermediate_ca(
        common_name: str,
        organization: str,
        root_cert: x509.Certificate,
        root_key: rsa.RSAPrivateKey,
        key_size: int = 3072,
        validity_days: int = 3650,
        password: Optional[str] = None
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Crée une Intermediate CA"""

    console.print(Panel.fit(
        "[bold cyan]🌐 Création de l'Intermediate CA[/bold cyan]",
        border_style="cyan"
    ))

    # 1. Générer la clé
    private_key = generate_rsa_key(key_size)

    # 2. Créer le certificat
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CM"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    serial = secrets.randbits(150)
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        .add_extension(
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
            critical=False
        )
        .sign(root_key, hashes.SHA256())
    )

    # 3. Sauvegarder
    save_key(private_key, "intermediate_ca", password)
    cert_path = CERTS_DIR / "intermediate_ca_cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # 4. Enregistrer
    registry = load_registry()
    registry["certificates"][f"{serial:X}"] = {
        "type": "intermediate_ca",
        "subject": common_name,
        "serial": f"{serial:X}",
        "not_before": now.isoformat(),
        "not_after": (now + timedelta(days=validity_days)).isoformat(),
        "status": "active",
        "path": str(cert_path)
    }
    save_registry(registry)

    console.print("[green]✓ Intermediate CA créée![/green]\n")
    display_cert_info(cert)

    return cert, private_key


# ============================================
# 📜 ÉMISSION CERTIFICATS
# ============================================

def issue_certificate(
        common_name: str,
        cert_type: str,  # "client" ou "server"
        issuer_cert: x509.Certificate,
        issuer_key: rsa.RSAPrivateKey,
        organization: str = "PKI Org",
        validity_days: int = 365,
        domains: Optional[List[str]] = None
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Émet un certificat client ou serveur"""

    icon = "👤" if cert_type == "client" else "🖥️"
    console.print(Panel.fit(
        f"[bold blue]{icon} Émission certificat {cert_type}[/bold blue]",
        border_style="blue"
    ))

    # 1. Générer la clé
    private_key = generate_rsa_key(2048)

    # 2. Créer le certificat
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CM"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    serial = secrets.randbits(150)
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False
        )
    )

    # Extensions selon le type
    if cert_type == "client":
        builder = builder.add_extension(
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
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )

    elif cert_type == "server":
        builder = builder.add_extension(
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
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )

        # SAN pour serveurs
        if domains:
            san = [x509.DNSName(d) for d in domains]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san),
                critical=False
            )

    cert = builder.sign(issuer_key, hashes.SHA256())

    # 3. Sauvegarder
    name = common_name.lower().replace(" ", "_")
    save_key(private_key, name)
    cert_path = CERTS_DIR / f"{name}_cert.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    # 4. Enregistrer
    registry = load_registry()
    registry["certificates"][f"{serial:X}"] = {
        "type": cert_type,
        "subject": common_name,
        "serial": f"{serial:X}",
        "not_before": now.isoformat(),
        "not_after": (now + timedelta(days=validity_days)).isoformat(),
        "status": "active",
        "path": str(cert_path)
    }
    save_registry(registry)

    console.print(f"[green]✓ Certificat {cert_type} émis![/green]\n")
    display_cert_info(cert)

    return cert, private_key


# ============================================
# 🚫 RÉVOCATION
# ============================================

def revoke_certificate(serial: str, reason: str = "unspecified"):
    """Révoque un certificat"""
    console.print(f"[yellow]🚫 Révocation du certificat {serial[:16]}...[/yellow]")

    registry = load_registry()

    if serial not in registry["certificates"]:
        console.print("[red]✗ Certificat introuvable![/red]")
        return False

    cert_info = registry["certificates"][serial]

    if cert_info["status"] == "revoked":
        console.print("[yellow]⚠ Certificat déjà révoqué[/yellow]")
        return False

    # Révoquer
    cert_info["status"] = "revoked"
    cert_info["revoked_at"] = datetime.now(timezone.utc).isoformat()
    cert_info["revocation_reason"] = reason

    registry["revoked"].append({
        "serial": serial,
        "revoked_at": cert_info["revoked_at"],
        "reason": reason
    })

    save_registry(registry)
    console.print(f"[green]✓ Certificat révoqué (raison: {reason})[/green]")
    return True


def check_revocation(serial: str) -> Dict:
    """Vérifie le statut de révocation (simulation OCSP)"""
    registry = load_registry()

    if serial not in registry["certificates"]:
        return {"status": "unknown", "message": "Certificat inconnu"}

    cert_info = registry["certificates"][serial]

    if cert_info["status"] == "revoked":
        return {
            "status": "revoked",
            "message": "Certificat RÉVOQUÉ",
            "revoked_at": cert_info.get("revoked_at"),
            "reason": cert_info.get("revocation_reason")
        }

    return {"status": "good", "message": "Certificat valide"}


# ============================================
# ✍️ SIGNATURE
# ============================================

def sign_message(
        message: bytes,
        private_key: rsa.RSAPrivateKey,
        certificate: x509.Certificate
) -> Dict:
    """Signe un message"""
    console.print("[cyan]✍️  Signature du message...[/cyan]")

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signed_data = {
        "message": message,
        "signature": signature,
        "certificate": certificate,
        "signer": certificate.subject.rfc4514_string(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    console.print("[green]✓ Message signé[/green]")
    return signed_data


def verify_signature(signed_data: Dict) -> Tuple[bool, str]:
    """Vérifie une signature"""
    console.print("[cyan]🔍 Vérification de la signature...[/cyan]")

    try:
        cert = signed_data["certificate"]
        public_key = cert.public_key()

        public_key.verify(
            signed_data["signature"],
            signed_data["message"],
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Vérifier la validité du certificat
        now = datetime.now(timezone.utc)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            return False, "Certificat expiré"

        # Vérifier révocation
        serial = f"{cert.serial_number:X}"
        revocation_status = check_revocation(serial)

        if revocation_status["status"] == "revoked":
            return False, f"Certificat révoqué: {revocation_status['reason']}"

        console.print("[green]✓ Signature VALIDE[/green]")
        return True, "Signature valide"

    except Exception as e:
        console.print(f"[red]✗ Signature INVALIDE: {e}[/red]")
        return False, f"Signature invalide: {e}"


# ============================================
# 📊 AFFICHAGE
# ============================================

def display_cert_info(cert: x509.Certificate):
    """Affiche les infos d'un certificat"""
    table = Table(title="📜 Informations du certificat", border_style="blue")
    table.add_column("Champ", style="cyan")
    table.add_column("Valeur", style="yellow")

    table.add_row("Sujet", cert.subject.rfc4514_string())
    table.add_row("Émetteur", cert.issuer.rfc4514_string())
    table.add_row("N° Série", f"{cert.serial_number:X}")
    table.add_row("Valide de", cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC"))
    table.add_row("Valide jusqu'à", cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC"))

    console.print(table)


def display_registry():
    """Affiche le contenu du registre"""
    registry = load_registry()

    table = Table(title="📋 Registre des certificats", border_style="green")
    table.add_column("Type", style="cyan")
    table.add_column("Sujet", style="yellow")
    table.add_column("Numéro de série", style="magenta")
    table.add_column("Statut", style="green")

    for serial, info in registry["certificates"].items():
        status = "✓ Actif" if info["status"] == "active" else "✗ Révoqué"
        color = "green" if info["status"] == "active" else "red"
        table.add_row(
            info["type"],
            info["subject"],
            serial[:16] + "...",
            f"[{color}]{status}[/{color}]"
        )

    console.print(table)

    # Statistiques
    total = len(registry["certificates"])
    active = sum(1 for c in registry["certificates"].values() if c["status"] == "active")
    revoked = sum(1 for c in registry["certificates"].values() if c["status"] == "revoked")

    console.print(f"\n[cyan]Total: {total} | Actifs: [green]{active}[/green] | Révoqués: [red]{revoked}[/red][/cyan]")


# ============================================
# 🎯 HELPERS
# ============================================

def load_cert(name: str) -> x509.Certificate:
    """Charge un certificat"""
    cert_path = CERTS_DIR / f"{name}_cert.pem"
    if not cert_path.exists():
        raise FileNotFoundError(f"Certificat introuvable: {cert_path}")

    pem = cert_path.read_bytes()
    return x509.load_pem_x509_certificate(pem)


def reset_pki():
    """Réinitialise complètement la PKI"""
    if console.input("[yellow]⚠️  Supprimer toutes les données ? (oui/non): [/yellow]").lower() == "oui":
        import shutil
        shutil.rmtree(DATA_DIR)
        DATA_DIR.mkdir()
        KEYS_DIR.mkdir()
        CERTS_DIR.mkdir()
        console.print("[green]✓ PKI réinitialisée[/green]")