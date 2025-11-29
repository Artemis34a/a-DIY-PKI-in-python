"""
Modèles de données pour le système PKI
Classes représentant les entités du système
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
from pathlib import Path


@dataclass
class Certificate:
    """
    Représente un certificat X.509 dans la base de données
    """
    serial_number: str
    subject_dn: str
    issuer_dn: str
    cert_type: str
    not_before: datetime
    not_after: datetime
    cert_path: str
    status: str = "active"
    public_key_path: Optional[str] = None
    created_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    id: Optional[int] = None


@dataclass
class CSRRequest:
    """
    Représente une demande de certificat (Certificate Signing Request)
    """
    request_id: str
    subject_dn: str
    cert_type: str
    csr_path: str
    status: str = "pending"
    created_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    rejected_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    id: Optional[int] = None


@dataclass
class Revocation:
    """
    Représente une révocation de certificat
    """
    serial_number: str
    revocation_date: datetime
    reason: str
    crl_published: bool = False
    id: Optional[int] = None


@dataclass
class AuditLog:
    """
    Représente une entrée dans le journal d'audit
    """
    timestamp: datetime
    action: str
    entity_type: str
    success: bool
    entity_id: Optional[str] = None
    details: Optional[str] = None
    id: Optional[int] = None


@dataclass
class DistinguishedName:
    """
    Représente un Distinguished Name (DN) X.509
    """
    common_name: str
    organization: str
    country: str
    state: Optional[str] = None
    locality: Optional[str] = None
    organizational_unit: Optional[str] = None
    email: Optional[str] = None

    def to_string(self) -> str:
        """Convertit le DN en chaîne RFC4514"""
        parts = [f"CN={self.common_name}"]

        if self.organizational_unit:
            parts.append(f"OU={self.organizational_unit}")

        parts.append(f"O={self.organization}")

        if self.locality:
            parts.append(f"L={self.locality}")

        if self.state:
            parts.append(f"ST={self.state}")

        parts.append(f"C={self.country}")

        return ",".join(parts)


__all__ = [
    'Certificate',
    'CSRRequest',
    'Revocation',
    'AuditLog',
    'DistinguishedName'
]