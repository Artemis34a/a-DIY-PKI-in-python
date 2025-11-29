"""
Générateur de clés cryptographiques (RSA et ECC)
Supporte la génération, la sauvegarde et le chargement sécurisés
"""

from pathlib import Path
from typing import Optional, Tuple, Union
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm
import time

from . import config
from . import utils

# Types de clés supportés
PrivateKeyTypes = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
PublicKeyTypes = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]


class KeyGenerator:
    """
    Classe pour générer et gérer les clés cryptographiques RSA et ECC
    """

    def __init__(self):
        """Initialise le générateur avec le backend cryptographique par défaut"""
        self.backend = default_backend()

    # ============================================
    # 🔐 GÉNÉRATION DE CLÉS RSA
    # ============================================

    def generate_rsa_key(self, key_size: int = 3072, show_progress: bool = True) -> rsa.RSAPrivateKey:
        """
        Génère une paire de clés RSA

        Args:
            key_size: Taille de la clé en bits (2048, 3072, 4096)
            show_progress: Afficher une barre de progression

        Returns:
            RSAPrivateKey: Clé privée RSA générée

        Raises:
            ValueError: Si la taille de clé n'est pas supportée
        """
        # Validation de la taille
        if key_size not in config.RSA_KEY_SIZES.values():
            raise ValueError(
                f"Taille de clé RSA non supportée: {key_size}. "
                f"Valeurs autorisées: {list(config.RSA_KEY_SIZES.values())}"
            )

        utils.print_info(f"Génération d'une clé RSA de {key_size} bits...")

        # Barre de progression (simulation car génération rapide)
        if show_progress:
            with tqdm(total=100, desc=f"RSA {key_size}", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
                for _ in range(5):
                    time.sleep(0.1)
                    pbar.update(20)

        # Génération de la clé RSA
        private_key = rsa.generate_private_key(
            public_exponent=config.RSA_PUBLIC_EXPONENT,
            key_size=key_size,
            backend=self.backend
        )

        utils.print_success(f"Clé RSA {key_size} bits générée avec succès")
        return private_key

    # ============================================
    # 🔐 GÉNÉRATION DE CLÉS ECC
    # ============================================

    def generate_ecc_key(self, curve_name: str = "secp256r1", show_progress: bool = True) -> ec.EllipticCurvePrivateKey:
        """
        Génère une paire de clés ECC (Elliptic Curve Cryptography)

        Args:
            curve_name: Nom de la courbe elliptique (secp256r1, secp384r1, secp521r1)
            show_progress: Afficher une barre de progression

        Returns:
            EllipticCurvePrivateKey: Clé privée ECC générée

        Raises:
            ValueError: Si la courbe n'est pas supportée
        """
        # Validation de la courbe
        if curve_name not in config.ECC_CURVES:
            raise ValueError(
                f"Courbe ECC non supportée: {curve_name}. "
                f"Courbes autorisées: {list(config.ECC_CURVES.keys())}"
            )

        utils.print_info(f"Génération d'une clé ECC (courbe {curve_name})...")

        # Sélection de la courbe
        curve_map = {
            "secp256r1": ec.SECP256R1(),
            "secp384r1": ec.SECP384R1(),
            "secp521r1": ec.SECP521R1()
        }
        curve = curve_map[curve_name]

        # Barre de progression
        if show_progress:
            with tqdm(total=100, desc=f"ECC {curve_name}", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
                for _ in range(4):
                    time.sleep(0.05)
                    pbar.update(25)

        # Génération de la clé ECC
        private_key = ec.generate_private_key(curve, self.backend)

        utils.print_success(f"Clé ECC ({curve_name}) générée avec succès")
        return private_key

    # ============================================
    # 💾 SAUVEGARDE DES CLÉS
    # ============================================

    def save_private_key(
            self,
            private_key: PrivateKeyTypes,
            filepath: Path,
            password: Optional[str] = None
    ) -> None:
        """
        Sauvegarde une clé privée au format PEM avec chiffrement optionnel

        Args:
            private_key: Clé privée à sauvegarder (RSA ou ECC)
            filepath: Chemin du fichier de sortie
            password: Mot de passe pour chiffrer la clé (optionnel mais recommandé)
        """
        utils.ensure_directory(filepath.parent)

        # Configuration du chiffrement
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
            utils.print_info("Clé privée chiffrée avec mot de passe (AES-256)")
        else:
            encryption = serialization.NoEncryption()
            utils.print_warning("⚠️  Clé privée NON chiffrée (pas de mot de passe)")

        # Sérialisation en PEM (format PKCS#8)
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

        # Écriture du fichier
        with open(filepath, 'wb') as f:
            f.write(pem_data)

        # Permissions restrictives (600 = rw-------)
        utils.set_file_permissions(filepath, config.PRIVATE_KEY_PERMISSIONS)

        # Affichage des infos
        file_info = utils.get_file_info(filepath)
        utils.print_success(f"Clé privée sauvegardée: {filepath.name} ({file_info.get('size', 'N/A')})")

    def save_public_key(
            self,
            private_key: PrivateKeyTypes,
            filepath: Path
    ) -> None:
        """
        Sauvegarde la clé publique correspondante au format PEM

        Args:
            private_key: Clé privée (pour extraire la clé publique)
            filepath: Chemin du fichier de sortie
        """
        utils.ensure_directory(filepath.parent)

        # Extraction de la clé publique
        public_key = private_key.public_key()

        # Sérialisation en PEM (format SubjectPublicKeyInfo)
        pem_data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Écriture du fichier
        with open(filepath, 'wb') as f:
            f.write(pem_data)

        # Permissions lecture publique (644 = rw-r--r--)
        utils.set_file_permissions(filepath, config.CERT_PERMISSIONS)

        # Affichage des infos
        file_info = utils.get_file_info(filepath)
        utils.print_success(f"Clé publique sauvegardée: {filepath.name} ({file_info.get('size', 'N/A')})")

    # ============================================
    # 📂 CHARGEMENT DES CLÉS
    # ============================================

    def load_private_key(
            self,
            filepath: Path,
            password: Optional[str] = None
    ) -> PrivateKeyTypes:
        """
        Charge une clé privée depuis un fichier PEM

        Args:
            filepath: Chemin du fichier PEM
            password: Mot de passe si la clé est chiffrée

        Returns:
            Clé privée (RSA ou ECC)

        Raises:
            FileNotFoundError: Si le fichier n'existe pas
            ValueError: Si le mot de passe est incorrect ou la clé invalide
        """
        if not filepath.exists():
            raise FileNotFoundError(f"Fichier de clé introuvable: {filepath}")

        # Lecture du fichier
        with open(filepath, 'rb') as f:
            pem_data = f.read()

        # Préparation du mot de passe
        password_bytes = password.encode() if password else None

        try:
            private_key = serialization.load_pem_private_key(
                pem_data,
                password=password_bytes,
                backend=self.backend
            )
            utils.print_success(f"Clé privée chargée: {filepath.name}")
            return private_key

        except ValueError as e:
            error_msg = str(e).lower()
            if "password" in error_msg or "decrypt" in error_msg:
                raise ValueError("Mot de passe incorrect ou clé corrompue")
            raise ValueError(f"Erreur lors du chargement de la clé: {e}")

    def load_public_key(self, filepath: Path) -> PublicKeyTypes:
        """
        Charge une clé publique depuis un fichier PEM

        Args:
            filepath: Chemin du fichier PEM

        Returns:
            Clé publique (RSA ou ECC)

        Raises:
            FileNotFoundError: Si le fichier n'existe pas
        """
        if not filepath.exists():
            raise FileNotFoundError(f"Fichier de clé introuvable: {filepath}")

        # Lecture du fichier
        with open(filepath, 'rb') as f:
            pem_data = f.read()

        public_key = serialization.load_pem_public_key(pem_data, backend=self.backend)
        utils.print_success(f"Clé publique chargée: {filepath.name}")
        return public_key

    # ============================================
    # 🔍 INFORMATIONS SUR LES CLÉS
    # ============================================

    def get_key_info(self, private_key: PrivateKeyTypes) -> dict:
        """
        Récupère les informations détaillées sur une clé

        Args:
            private_key: Clé privée à analyser

        Returns:
            dict: Informations (type, taille, courbe, etc.)
        """
        info = {}

        if isinstance(private_key, rsa.RSAPrivateKey):
            info['type'] = 'RSA'
            info['size'] = private_key.key_size
            info['public_exponent'] = private_key.public_key().public_numbers().e
            info['format'] = 'PKCS#8'

        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            info['type'] = 'ECC'
            curve = private_key.curve
            info['curve'] = curve.name
            info['key_size'] = curve.key_size
            info['format'] = 'PKCS#8'

        return info

    def display_key_info(self, private_key: PrivateKeyTypes) -> None:
        """
        Affiche les informations d'une clé de manière formatée avec Rich

        Args:
            private_key: Clé privée à afficher
        """
        info = self.get_key_info(private_key)

        table = utils.create_table(
            f"{config.CLI_SYMBOLS['key']} Informations de la clé",
            ["Propriété", "Valeur"]
        )

        for key, value in info.items():
            table.add_row(key.replace('_', ' ').title(), str(value))

        utils.console.print(table)

    # ============================================
    # 🎯 HELPER: GÉNÉRATION COMPLÈTE
    # ============================================

    def generate_key_pair(
            self,
            entity_name: str,
            key_type: str = "rsa",
            key_size: int = 3072,
            curve_name: str = "secp256r1",
            password: Optional[str] = None,
            save_keys: bool = True
    ) -> Tuple[PrivateKeyTypes, Optional[Path], Optional[Path]]:
        """
        Génère une paire de clés complète (privée + publique) et la sauvegarde

        Args:
            entity_name: Nom de l'entité (ex: "alice", "root_ca")
            key_type: Type de clé ("rsa" ou "ecc")
            key_size: Taille pour RSA (2048, 3072, 4096)
            curve_name: Courbe pour ECC (secp256r1, secp384r1, secp521r1)
            password: Mot de passe pour chiffrer la clé privée
            save_keys: Sauvegarder les clés sur disque

        Returns:
            tuple: (clé_privée, chemin_clé_privée, chemin_clé_publique)

        Raises:
            ValueError: Si le type de clé est invalide
        """
        utils.print_header(f"{config.CLI_SYMBOLS['key']} Génération de clés pour: {entity_name}")

        # Génération selon le type
        if key_type.lower() == "rsa":
            private_key = self.generate_rsa_key(key_size)
        elif key_type.lower() == "ecc":
            private_key = self.generate_ecc_key(curve_name)
        else:
            raise ValueError(f"Type de clé non supporté: {key_type}. Utilisez 'rsa' ou 'ecc'.")

        # Affichage des informations
        self.display_key_info(private_key)

        # Sauvegarde optionnelle
        private_key_path = None
        public_key_path = None

        if save_keys:
            private_key_path = config.get_key_path(entity_name, "private")
            public_key_path = config.get_key_path(entity_name, "public")

            self.save_private_key(private_key, private_key_path, password)
            self.save_public_key(private_key, public_key_path)

        return private_key, private_key_path, public_key_path


# ============================================
# 🎯 INSTANCE GLOBALE
# ============================================

# Instance par défaut pour utilisation directe
keygen = KeyGenerator()

# ============================================
# 🎨 EXPORTS
# ============================================

__all__ = [
    'KeyGenerator',
    'keygen',
    'PrivateKeyTypes',
    'PublicKeyTypes'
]