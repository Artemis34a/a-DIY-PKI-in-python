# 🔐 Système de Messagerie Sécurisée PKI

## 📋 Vue d'ensemble

Système de messagerie sécurisée utilisant une infrastructure à clés publiques (PKI) avec:
- **Chiffrement hybride** (RSA + AES-256)
- **Signatures numériques** (RSA-PSS + SHA-256)
- **Révocation de certificats** en temps réel
- **Architecture multi-threads** avec 4 consoles indépendantes

## 🏗️ Architecture

```
┌─────────────┐
│   Serveur   │  ← Gère les communications
└──────┬──────┘
       │
    ┌──┴──┬──────┬────────┐
    │     │      │        │
┌───▼───┐ │  ┌───▼───┐  ┌▼─────┐
│ Alice │ │  │  Bob  │  │Admin │
└───────┘ │  └───────┘  └──────┘
          │
    Intermediate CA
          │
       Root CA
```

## 📦 Installation

```bash
# 1. Naviguer dans le dossier
cd pki

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Vérifier que tous les fichiers sont présents
ls *.py
# Doit afficher:
# - pki.py
# - pki_encryption.py
# - messaging_server.py
# - client_alice.py
# - client_bob.py
# - admin_console.py
# - setup.py
```

## 🚀 Démarrage rapide

### Étape 1: Configuration de la PKI

**Mode interactif** (recommandé pour la première fois):
```bash
python setup.py
```

Vous serez guidé à travers:
1. Nom de l'organisation
2. Création de la Root CA (avec mot de passe)
3. Création de l'Intermediate CA (avec mot de passe)
4. Certificats pour Alice
5. Certificats pour Bob

**Mode automatique** (valeurs par défaut):
```bash
python setup.py --auto
```

### Étape 2: Lancer le système

**Important**: Ouvrez 4 terminaux/consoles différents!

**Terminal 1 - Serveur** (à lancer en premier):
```bash
python messaging_server.py
```
Attendez le message: `🚀 Serveur démarré sur localhost:5555`

**Terminal 2 - Alice**:
```bash
python client_alice.py
```

**Terminal 3 - Bob**:
```bash
python client_bob.py
```

**Terminal 4 - Admin**:
```bash
python admin_console.py
```

## 💬 Utilisation

### Console Alice

```
┌─────────────────────────────────────────┐
│   👤 CONSOLE ALICE                      │
└─────────────────────────────────────────┘

Alice> Bonjour Bob!
✓ Message envoyé et chiffré

📨 NOUVEAU MESSAGE
De: bob
✓ Signature valide
Message: Salut Alice, ça va?
```

**Commandes disponibles**:
- Tapez un message → envoyé à Bob automatiquement
- `status` → voir l'état du certificat
- `quit` ou `exit` → quitter

### Console Bob

Identique à Alice, mais communique avec Alice.

```
Bob> Salut Alice, ça va?
✓ Message envoyé et chiffré
```

### Console Admin

```
┌─────────────────────────────────────────┐
│   🔐 CONSOLE ADMIN                      │
└─────────────────────────────────────────┘

📡 FLUX EN TEMPS RÉEL
[14:30:15] alice → bob
[14:30:22] bob → alice
[14:30:45] alice → bob
```

**Commandes disponibles**:
- `revoke` → révoquer un certificat (Alice ou Bob)
- `stats` → voir les statistiques des messages
- `registry` → afficher tous les certificats
- `feed` → réafficher le flux en temps réel
- `help` → aide
- `quit` → quitter

#### Révoquer un certificat

```
Admin> revoke

Quel utilisateur voulez-vous révoquer? [alice/bob/annuler]: alice
Êtes-vous sûr de vouloir révoquer le certificat de alice? [y/N]: y

Raisons de révocation:
  1. key_compromise (Clé compromise)
  2. affiliation_changed (Changement d'affiliation)
  3. superseded (Remplacé)
  4. cessation_of_operation (Cessation d'opération)
  5. privilege_withdrawn (Privilège retiré)

Raison [1]: 1

✓ Certificat de alice révoqué avec succès
Tous les clients ont été notifiés
```

### Que se passe-t-il après révocation?

**Sur la console d'Alice**:
```
⚠️ VOTRE CERTIFICAT A ÉTÉ RÉVOQUÉ!
Raison: key_compromise
Vous ne pouvez plus envoyer de messages sécurisés.
```

**Sur la console de Bob**:
```
⚠️ Le certificat d'Alice a été révoqué (key_compromise)
```

**Si Bob essaie d'envoyer à Alice**:
```
Bob> Tu es là?
⚠️ ATTENTION: Le certificat d'Alice est révoqué!
Raison: key_compromise
Alice n'est pas fiable. Message non envoyé.
```

## 🔒 Sécurité

### Chiffrement hybride

1. **Message** : Chiffré avec AES-256-CBC
2. **Clé AES** : Chiffrée avec RSA-OAEP (clé publique du destinataire)
3. **Signature** : RSA-PSS avec SHA-256

```
[Message] → AES-256 → [Chiffré]
[Clé AES] → RSA-4096 → [Clé chiffrée]
[Message] → SHA-256 → RSA-PSS → [Signature]

Envoi: [Chiffré + Clé chiffrée + Signature + Certificat]
```

### Vérifications effectuées

À chaque message reçu:
1. ✅ Déchiffrement du message
2. ✅ Vérification de la signature
3. ✅ Validation de la période de validité
4. ✅ Vérification de la révocation (OCSP simulé)

## 📂 Structure des fichiers

```
pki/
├── pki.py                    # Module PKI principal
├── pki_encryption.py         # Extensions de chiffrement
├── messaging_server.py       # Serveur de messagerie
├── client_alice.py           # Client Alice
├── client_bob.py             # Client Bob
├── admin_console.py          # Console admin
├── setup.py                  # Configuration initiale
├── requirements.txt          # Dépendances
├── README_MESSAGING.md       # Ce fichier
└── data/                     # Créé automatiquement
    ├── keys/                 # Clés privées (.pem)
    │   ├── root_ca_key.pem
    │   ├── intermediate_ca_key.pem
    │   ├── alice_key.pem
    │   └── bob_key.pem
    ├── certs/                # Certificats (.pem)
    │   ├── root_ca_cert.pem
    │   ├── intermediate_ca_cert.pem
    │   ├── alice_cert.pem
    │   └── bob_cert.pem
    └── registry.json         # Registre des certificats
```

## 🧪 Scénarios de test

### Scénario 1: Communication normale

1. Lancer tous les composants
2. Alice envoie: "Bonjour Bob"
3. Bob répond: "Salut Alice!"
4. Vérifier que les messages sont bien reçus et déchiffrés

### Scénario 2: Révocation d'Alice

1. Communication normale entre Alice et Bob
2. Admin révoque Alice (raison: key_compromise)
3. Alice reçoit la notification
4. Bob essaie d'envoyer à Alice → refusé
5. Alice ne peut plus envoyer de messages

### Scénario 3: Révocation de Bob

1. Communication normale
2. Admin révoque Bob
3. Alice essaie d'envoyer à Bob → refusé
4. Vérifier le message d'avertissement

## 🔍 Dépannage

### "Erreur de connexion"
- Vérifiez que le serveur est lancé en premier
- Vérifiez le port 5555 (changez-le si nécessaire dans tous les fichiers)

### "Erreur chargement identifiants"
- Exécutez `python setup.py` d'abord
- Vérifiez que le dossier `data/` existe

### "Certificat introuvable"
- Relancez `python setup.py --auto`
- Vérifiez les fichiers dans `data/certs/` et `data/keys/`

### Le serveur ne démarre pas
```bash
# Vérifier si le port est déjà utilisé
lsof -i :5555          # Linux/Mac
netstat -ano | find "5555"  # Windows

# Tuer le processus si nécessaire
kill -9 <PID>          # Linux/Mac
taskkill /PID <PID> /F # Windows
```

## 📚 Concepts démontrés

1. **PKI** : Hiérarchie de certification (Root → Intermediate → End-entity)
2. **X.509** : Certificats numériques conformes
3. **Chiffrement asymétrique** : RSA-4096 pour l'échange de clés
4. **Chiffrement symétrique** : AES-256-CBC pour les données
5. **Signatures numériques** : RSA-PSS + SHA-256
6. **Révocation** : Simulation OCSP en temps réel
7. **Non-répudiation** : Signatures vérifiables
8. **Confidentialité** : Chiffrement de bout en bout
9. **Intégrité** : Détection de toute modification
10. **Authentification** : Vérification de l'identité

## 🎓 Exercices suggérés

1. **Modifier le timeout de connexion**
2. **Ajouter un troisième utilisateur (Charlie)**
3. **Implémenter un historique de chat sauvegardé**
4. **Ajouter des groupes de discussion**
5. **Implémenter une vraie CRL (Certificate Revocation List)**
6. **Ajouter l'horodatage TSA (Time Stamping Authority)**
7. **Chiffrer les communications serveur ↔ clients (TLS)**

## 🐛 Problèmes connus

- Le serveur doit être redémarré si un client crash
- Pas de reconnexion automatique
- Les messages ne sont pas sauvegardés (volatils)
- Pas d'authentification forte des clients

## 📝 Notes importantes

⚠️ **ATTENTION**: Ceci est un projet éducatif!

**NE PAS utiliser en production** sans :
- Authentification forte des clients
- Vérification des certificats côté serveur
- Vraie infrastructure OCSP/CRL
- HSM pour les clés CA
- Audit et logs sécurisés
- Tests de sécurité approfondis

## 📖 Références

- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) - X.509 PKI
- [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986) - PKCS#10 CSR
- [RFC 3447](https://www.rfc-editor.org/rfc/rfc3447) - RSA PKCS#1
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) - OCSP

## ✅ Checklist avant démonstration

- [ ] Python 3.8+ installé
- [ ] Dépendances installées (`pip install -r requirements.txt`)
- [ ] PKI configurée (`python setup.py`)
- [ ] 4 terminaux ouverts
- [ ] Serveur lancé en premier
- [ ] Les 3 clients connectés
- [ ] Testé l'envoi de messages
- [ ] Testé la révocation
- [ ] Vérifié les avertissements post-révocation

---

**Bon apprentissage! 🎓🔐**