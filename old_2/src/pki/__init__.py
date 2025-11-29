"""
PKI Project - Infrastructure à Clés Publiques
==============================================

Un système PKI complet implémenté en Python avec:
- Génération de clés RSA et ECC
- Certificats X.509 (Root CA, Intermediate CA, Client, Server)
- Révocation (CRL/OCSP)
- Signature et vérification
- Simulation Alice & Bob

Modules principaux:
- config: Configuration globale
- utils: Fonctions utilitaires
- keygen: Génération de clés cryptographiques
- database: Gestion de la base de données
- root_ca: Gestion de la Root CA

Auteur: PKI Project Team
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "PKI Project Team"

# Imports principaux
from . import config
from . import utils
from .keygen import KeyGenerator, keygen
from .database import PKIDatabase, pki_db
from .models import Certificate, CSRRequest, Revocation, AuditLog, DistinguishedName

# Exports
__all__ = [
    'config',
    'utils',
    'KeyGenerator',
    'keygen',
    'PKIDatabase',
    'pki_db',
    'Certificate',
    'CSRRequest',
    'Revocation',
    'AuditLog',
    'DistinguishedName',
]