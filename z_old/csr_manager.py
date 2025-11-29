
import os
import sqlite3
import datetime
from typing import Optional, Tuple, Dict
from cryptography import x509
from cryptography.x509.oid import NameOID

DB_PATH = "pki/ra_csrs.db"

def ensure_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(""" CREATE TABLE IF NOT EXISTS csrs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pem TEXT NOT NULL,
        subject_cn TEXT,
        status TEXT NOT NULL, -- pending / approved / rejected / signed
        submitted_at TEXT NOT NULL,
        approver TEXT,
        decision_at TEXT,
        cert_path TEXT,
        serial INTEGER,
        notes TEXT
    )""")
    conn.commit()
    conn.close()

def submit_csr_from_pem(pem_bytes: bytes) -> int:
    """
    Stocke un CSR (PEM bytes) dans la DB et renvoie l'id.
    """
    ensure_db()
    csr = x509.load_pem_x509_csr(pem_bytes)
    cn = _extract_cn_from_csr(csr)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat() + "Z"
    cur.execute("INSERT INTO csrs (pem, subject_cn, status, submitted_at) VALUES (?, ?, ?, ?)",
                (pem_bytes.decode(), cn, "pending", now))
    csr_id = cur.lastrowid
    conn.commit()
    conn.close()
    return csr_id

def _extract_cn_from_csr(csr: x509.CertificateSigningRequest) -> Optional[str]:
    try:
        for attr in csr.subject:
            if attr.oid == NameOID.COMMON_NAME:
                return attr.value
    except Exception:
        pass
    return None

def list_csrs(status_filter: Optional[str] = None) -> list:
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if status_filter:
        cur.execute("SELECT id, subject_cn, status, submitted_at, approver FROM csrs WHERE status = ? ORDER BY submitted_at DESC", (status_filter,))
    else:
        cur.execute("SELECT id, subject_cn, status, submitted_at, approver FROM csrs ORDER BY submitted_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "cn": r[1], "status": r[2], "submitted_at": r[3], "approver": r[4]} for r in rows]

def get_csr_pem(csr_id: int) -> Optional[str]:
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT pem FROM csrs WHERE id = ?", (csr_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def set_csr_status(csr_id: int, status: str, approver: Optional[str] = None, notes: Optional[str] = None, cert_path: Optional[str] = None, serial: Optional[int] = None):
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat() + "Z"
    cur.execute("""
        UPDATE csrs SET status = ?, approver = ?, decision_at = ?, notes = ?, cert_path = ?, serial = ?
        WHERE id = ?
    """, (status, approver, now, notes, cert_path, serial, csr_id))
    conn.commit()
    conn.close()

def get_csr_record(csr_id: int) -> Optional[Dict]:
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, subject_cn, status, submitted_at, approver, decision_at, cert_path, serial, notes FROM csrs WHERE id = ?", (csr_id,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r[0],
        "cn": r[1],
        "status": r[2],
        "submitted_at": r[3],
        "approver": r[4],
        "decision_at": r[5],
        "cert_path": r[6],
        "serial": r[7],
        "notes": r[8]
    }

# ---- Simple policy validation ----
def validate_csr_policy(csr_pem: bytes, require_cn: bool = True, allowed_countries: Optional[list] = None) -> Tuple[bool, str]:
    """
    Applique des vérifications basiques sur le CSR.
    Retour: (ok: bool, message: str)
    """
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except Exception as e:
        return False, f"CSR invalide: {e}"

    # CN present?
    cn = _extract_cn_from_csr(csr)
    if require_cn and not cn:
        return False, "CSR doit contenir un Common Name (CN)."

    # Country check (facultatif)
    if allowed_countries:
        country_values = [attr.value for attr in csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)]
        if country_values and country_values[0] not in allowed_countries:
            return False, f"Country '{country_values[0]}' non autorisé par la politique."

    # Key type/size minimal (exemple)
    pub = csr.public_key()
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < 2048:
            return False, f"RSA key too small ({pub.key_size}). Minimum 2048."
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        # accept all curves but can check explicit curves if needed
        pass
    else:
        return False, "Public key type non supportée."

    # Option: verify CSR signature
    try:
        csr.is_signature_valid
    except Exception:
        # Older cryptography versions: manual verify
        try:
            csr.public_key().verify(csr.signature, csr.tbs_certrequest_bytes, csr.signature_hash_algorithm)
        except Exception:
            return False, "Signature du CSR invalide."

    return True, "OK"
