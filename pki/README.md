# 🔐 PKI Simple - Infrastructure à Clés Publiques

> Version ultra-simplifiée : 1 fichier, pas de SQL, facile à comprendre

## 🎯 Philosophie

- **Simple** : Tout le code dans `pki.py` (~500 lignes)
- **Pas de SQL** : Juste un fichier JSON (`registry.json`)
- **Éducatif** : Code clair et commenté
- **Fonctionnel** : PKI complète et conforme aux standards

---

## 📦 Installation

```bash
# Cloner ou télécharger le projet
cd pki_simple

# Installer les dépendances
pip install -r requirements.txt
```

**C'est tout !** Pas besoin de base de données, pas de configuration compliquée.

---

## 🚀 Utilisation

### Démonstration complète

```bash
python demo.py
```

Cette démonstration va :
1. ✅ Créer une Root CA
2. ✅ Créer une Intermediate CA
3. ✅ Émettre des certificats pour Alice et Bob
4. ✅ Alice signe un message pour Bob
5. ✅ Bob vérifie la signature
6. ✅ Révoquer le certificat d'Alice
7. ✅ Bob envoie un message à Alice

### Utilisation manuelle



````python
    from pki import *
    
    # 1. Créer une Root CA
    root_cert, root_key = create_root_ca(
        common_name="My Root CA",
        organization="My Org",
        password="secret123"
    )
    
    # 2. Créer une Intermediate CA
    int_cert, int_key = create_intermediate_ca(
        common_name="My Intermediate CA",
        organization="My Org",
        root_cert=root_cert,
        root_key=root_key,
        password="secret456"
    )
    
    # 3. Émettre un certificat pour Alice
    alice_cert, alice_key = issue_certificate(
        common_name="Alice",
        cert_type="client",
        issuer_cert=int_cert,
        issuer_key=int_key
    )
    
    # 4. Alice signe un message
    message = b"Bonjour!"
    signed = sign_message(message, alice_key, alice_cert)
    
    # 5. Bob vérifie la signature
    is_valid, msg = verify_signature(signed)
    print(f"Signature valide? {is_valid} - {msg}")
    
    # 6. Révoquer un certificat
    serial = f"{alice_cert.serial_number:X}"
    revoke_certificate(serial, reason="key_compromise")
    
    # 7. Vérifier le statut de révocation
    status = check_revocation(serial)
    print(status)
    
    # 8. Afficher le registre
    display_registry()
````

---

## 📁 Structure

```
pki_simple/
├── pki.py              # TOUT le code PKI (500 lignes)
├── demo.py             # Démonstration Alice & Bob
├── requirements.txt    # 3 dépendances seulement
├── README.md           # Ce fichier
└── data/               # Créé automatiquement
    ├── keys/          # Clés privées (.pem)
    ├── certs/         # Certificats (.pem)
    └── registry.json  # Registre (remplace SQL)
```

---

## 🔑 Fonctionnalités

### ✅ Génération de clés
- RSA 2048, 3072, 4096 bits
- Sauvegarde PEM chiffrée (AES-256)
- Protection par mot de passe optionnelle

### ✅ Root CA
- Certificat X.509v3 auto-signé
- Extensions conformes (BasicConstraints, KeyUsage)
- Validité configurable (défaut: 20 ans)

### ✅ Intermediate CA
- Signée par la Root CA
- Chaîne de certification valide
- pathLength=0 (ne peut pas signer d'autres CA)

### ✅ Certificats clients/serveurs
- Types: `client` ou `server`
- Extensions adaptées (ExtendedKeyUsage)
- SAN (Subject Alternative Names) pour serveurs
- Validité configurable (défaut: 1 an)

### ✅ Révocation
- Révocation avec raison
- Simulation OCSP (vérification du statut)
- Stockage dans `registry.json`

### ✅ Signature numérique
- Signature RSA-PSS avec SHA-256
- Vérification complète (signature + validité + révocation)
- Métadonnées (timestamp, émetteur)

### ✅ Registre JSON
- Remplace complètement SQL
- Stocke tous les certificats
- Historique des révocations
- Facile à inspecter/modifier

---

## 📋 Exemples

### Créer une PKI complète

```python
from pki import *

# Root CA (offline, sécurisée)
root_cert, root_key = create_root_ca(
    common_name="ACME Root CA",
    organization="ACME Corporation",
    key_size=4096,
    validity_days=7300,  # 20 ans
    password="RootPassword123!"
)

# Intermediate CA (en ligne)
int_cert, int_key = create_intermediate_ca(
    common_name="ACME Intermediate CA",
    organization="ACME Corporation",
    root_cert=root_cert,
    root_key=root_key,
    key_size=3072,
    validity_days=3650,  # 10 ans
    password="IntPassword456!"
)

# Certificat serveur
server_cert, server_key = issue_certificate(
    common_name="www.example.com",
    cert_type="server",
    issuer_cert=int_cert,
    issuer_key=int_key,
    domains=["www.example.com", "example.com", "*.example.com"]
)

print("✅ PKI créée!")
```

### Signature et vérification

```python
# Alice signe
alice_cert, alice_key = issue_certificate(
    common_name="Alice",
    cert_type="client",
    issuer_cert=int_cert,
    issuer_key=int_key
)

message = b"Message secret d'Alice"
signed = sign_message(message, alice_key, alice_cert)

# Bob vérifie
is_valid, msg = verify_signature(signed)

if is_valid:
    print(f"✅ {msg}")
    print(f"Message: {message.decode()}")
else:
    print(f"❌ {msg}")
```

### Révocation

```python
# Révoquer le certificat d'Alice
serial = f"{alice_cert.serial_number:X}"
revoke_certificate(serial, reason="key_compromise")

# Vérifier le statut (OCSP)
status = check_revocation(serial)
print(f"Statut: {status['status']}")  # "revoked"
print(f"Raison: {status['reason']}")  # "key_compromise"

# La vérification échouera maintenant
is_valid, msg = verify_signature(signed)
print(f"{msg}")  # "Certificat révoqué: key_compromise"
```

### Charger des certificats existants

```python
# Charger depuis les fichiers
root_cert = load_cert("root_ca")
int_cert = load_cert("intermediate_ca")
alice_cert = load_cert("alice")

# Charger une clé privée
alice_key = load_key("alice", password=None)

# Utiliser
display_cert_info(alice_cert)
```

---

## 🔒 Sécurité

### Points forts

- ✅ Clés RSA 4096 bits pour Root CA
- ✅ Chiffrement AES-256 des clés privées
- ✅ Signatures RSA-PSS (meilleur que PKCS#1 v1.5)
- ✅ SHA-256 pour tous les hachages
- ✅ Vérification de révocation avant validation
- ✅ Vérification de la période de validité

### Limitations (version simplifiée)

- ⚠️ Pas de vraie CRL (juste simulation)
- ⚠️ Pas de vrai serveur OCSP (juste local)
- ⚠️ Registry JSON non chiffré
- ⚠️ Pas de HSM (Hardware Security Module)

**Pour la production**, utilisez :
- Un vrai serveur OCSP
- Une vraie CRL publiée
- Un HSM pour la Root CA
- Une base de données sécurisée

---

## 📊 Registre JSON

Le fichier `data/registry.json` remplace SQL :

```json
{
  "certificates": {
    "ABC123...": {
      "type": "root_ca",
      "subject": "Root CA",
      "serial": "ABC123...",
      "not_before": "2024-01-15T10:00:00+00:00",
      "not_after": "2044-01-15T10:00:00+00:00",
      "status": "active",
      "path": "data/certs/root_ca_cert.pem"
    },
    "DEF456...": {
      "type": "client",
      "subject": "Alice",
      "serial": "DEF456...",
      "status": "revoked",
      "revoked_at": "2024-01-16T15:30:00+00:00",
      "revocation_reason": "key_compromise"
    }
  },
  "revoked": [
    {
      "serial": "DEF456...",
      "revoked_at": "2024-01-16T15:30:00+00:00",
      "reason": "key_compromise"
    }
  ]
}
```

---

## 🧪 Test manuel

```python
from pki import *

# Créer une PKI de test
root_cert, root_key = create_root_ca("Test Root", "Test")
int_cert, int_key = create_intermediate_ca("Test Int", "Test", root_cert, root_key)

# Émettre 2 certificats
alice_cert, alice_key = issue_certificate("Alice", "client", int_cert, int_key)
bob_cert, bob_key = issue_certificate("Bob", "client", int_cert, int_key)

# Test signature
msg = b"Test message"
signed = sign_message(msg, alice_key, alice_cert)
is_valid, result = verify_signature(signed)
assert is_valid, f"Signature invalide: {result}"

# Test révocation
serial = f"{alice_cert.serial_number:X}"
revoke_certificate(serial, "test")
is_valid, result = verify_signature(signed)
assert not is_valid, "Devrait être invalide (révoqué)"

print("✅ Tous les tests passent!")
```

---

## 🎓 Ce que vous apprenez

1. **Cryptographie** : RSA, signatures, hachages
2. **PKI** : Hiérarchie CA, chaînes de confiance
3. **X.509** : Certificats numériques, extensions
4. **Sécurité** : Révocation, vérification, non-répudiation

---

## 📚 Ressources

- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) - X.509 PKI
- [cryptography.io](https://cryptography.io/) - Bibliothèque Python
- [X.509 sur Wikipedia](https://en.wikipedia.org/wiki/X.509)

---

## ✅ Checklist

Avant d'utiliser :

- [ ] Python 3.8+ installé
- [ ] Dépendances installées (`pip install -r requirements.txt`)
- [ ] Lancé `python demo.py` avec succès
- [ ] Compris le code de `pki.py`
- [ ] Inspecté `data/registry.json`

---

## 🤝 Contribution

Vous voulez améliorer ce projet ?

1. Fork le repo
2. Créez une branche
3. Faites vos modifications
4. Pull request

---

## 📝 License

MIT License - Libre d'utilisation

---

**🎉 Profitez de votre PKI simplifiée ! 🎉**

Pour toute question : lisez le code, il fait ~500 lignes et est bien commenté !