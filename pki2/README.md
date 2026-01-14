# 🔐 Secure PKI Messaging System

A production-ready secure messaging system demonstrating Public Key Infrastructure (PKI) with end-to-end encryption, digital signatures, and certificate revocation.

## 🎯 Features

- **Hybrid Encryption**: RSA-4096 + AES-256-CBC
- **Digital Signatures**: RSA-PSS with SHA-256
- **Real-time Certificate Revocation**: Simulated OCSP
- **Multi-threaded Architecture**: Concurrent client handling
- **Admin Supervision**: Live message monitoring and certificate management

## 📋 Requirements

- Python 3.8 or higher
- pip (Python package manager)

## 🚀 Quick Start

### 1. Installation

```bash
# Clone or download the project
cd pki

# Install dependencies
pip install -r requirements.txt
```

**Required packages:**
```
cryptography>=41.0.0
rich>=13.0.0
```

### 2. Initial Setup

Configure the PKI (first time only):

```bash
# Interactive setup (recommended)
python setup.py

# Or automatic setup with defaults
python setup.py --auto
```

This creates:
- Root Certificate Authority (CA)
- Intermediate CA
- User certificates for Alice and Bob
- Private keys and registry

### 3. Launch System

**You need 4 separate terminals/command prompts!**

#### Terminal 1: Server (must start first)
```bash
python messaging_server.py
```
Wait for: `🚀 Server started on localhost:5555`

#### Terminal 2: Alice
```bash
python client_base.py alice
```

#### Terminal 3: Bob
```bash
python client_base.py bob
```

#### Terminal 4: Admin
```bash
python admin.py
```

## 📖 Usage Guide

### Alice/Bob Commands

```
Alice> Hello Bob!
✓ Message sent and encrypted

Commands:
  • Type any message → sends to other user
  • status → view certificate status
  • quit → exit
```

### Admin Commands

```
Admin> revoke
Admin> stats
Admin> registry
Admin> help
Admin> quit

Functions:
  • revoke   - Revoke user certificate
  • stats    - View message statistics
  • registry - Display all certificates
  • help     - Show commands
  • quit     - Exit
```

## 🧪 Testing Scenarios

### Test 1: Normal Communication ✅

**Objective**: Verify encrypted messaging works

**Steps:**
1. Launch all 4 components
2. In Alice's terminal, type: `Hello Bob!`
3. In Bob's terminal, type: `Hi Alice!`

**Expected Results:**
- ✅ Alice receives Bob's message decrypted
- ✅ Bob receives Alice's message decrypted
- ✅ Admin sees message events in real-time
- ✅ Both show "✓ Valid signature"

**Pass Criteria**: Messages are exchanged successfully

---

### Test 2: Certificate Revocation - Alice ⚠️

**Objective**: Verify revocation mechanism

**Steps:**
1. Establish normal communication (send 2-3 messages)
2. In Admin terminal, type: `revoke`
3. Select: `alice`
4. Confirm: `y`
5. Choose reason: `1` (key_compromise)
6. Try to send message from Bob to Alice
7. Try to send message from Alice to Bob

**Expected Results:**
- ✅ Alice sees: "⚠️ YOUR CERTIFICATE HAS BEEN REVOKED!"
- ✅ Bob sees: "⚠️ alice's certificate revoked"
- ✅ Bob's message to Alice is **blocked** with warning
- ✅ Alice **cannot send** messages

**Pass Criteria**: All revocation warnings appear, messaging blocked

---

### Test 3: Certificate Revocation - Bob 🚫

**Objective**: Test revocation from other side

**Steps:**
1. Reset PKI: `python setup.py --auto`
2. Restart all components
3. In Admin, revoke Bob
4. Try communication

**Expected Results:**
- ✅ Bob cannot send messages
- ✅ Alice's messages to Bob are blocked
- ✅ Proper warnings displayed

**Pass Criteria**: Symmetric to Test 2

---

### Test 4: Message Integrity 🔒

**Objective**: Verify signature validation

**Steps:**
1. Send message from Alice to Bob
2. Observe "✓ Valid signature" message

**Expected Results:**
- ✅ Signature verified successfully
- ✅ Message content intact
- ✅ No tampering warnings

**Pass Criteria**: All signatures valid

---

### Test 5: Admin Monitoring 📊

**Objective**: Test admin capabilities

**Steps:**
1. Send 5 messages from Alice
2. Send 3 messages from Bob
3. In Admin, type: `stats`

**Expected Results:**
```
Messages exchanged
┌───────┬────────────────┐
│ User  │ Messages sent  │
├───────┼────────────────┤
│ Alice │ 5              │
│ Bob   │ 3              │
│ Total │ 8              │
└───────┴────────────────┘
```

**Pass Criteria**: Statistics match actual messages sent

---

### Test 6: PKI Registry Inspection 📋

**Objective**: Verify certificate management

**Steps:**
1. In Admin, type: `registry`

**Expected Results:**
```
Certificate Registry:
- Root CA, Intermediate CA
- Alice (active/revoked)
- Bob (active/revoked)
```

**Pass Criteria**: All certificates listed with correct status

---

### Test 7: Multiple Revocations 🔄

**Objective**: Test sequential revocations

**Steps:**
1. Revoke Alice
2. Verify Alice blocked
3. Revoke Bob
4. Verify Bob blocked
5. Check both cannot communicate

**Expected Results:**
- ✅ Both users revoked
- ✅ All messaging blocked
- ✅ System stable

**Pass Criteria**: System handles multiple revocations

---

### Test 8: Server Resilience 💪

**Objective**: Test server stability

**Steps:**
1. Start server, Alice, Bob
2. Close Alice (Ctrl+C)
3. Send message from Bob
4. Reconnect Alice
5. Send messages

**Expected Results:**
- ✅ Server detects disconnection
- ✅ Bob's message queued/handled gracefully
- ✅ Alice can reconnect
- ✅ Normal operation resumes

**Pass Criteria**: No server crash, graceful handling

---

### Test 9: Concurrent Messaging 🚀

**Objective**: Test simultaneous messages

**Steps:**
1. Alice and Bob send messages at same time
2. Rapidly send 10 messages each

**Expected Results:**
- ✅ All messages delivered
- ✅ Correct order maintained
- ✅ No message loss
- ✅ All signatures valid

**Pass Criteria**: 100% message delivery rate

---

### Test 10: Status Check ℹ️

**Objective**: Verify status command

**Steps:**
1. In Alice terminal, type: `status`
2. Revoke Alice
3. Type: `status` again

**Expected Results:**
```
Before: Certificate status: ACTIVE (green)
After:  Certificate status: REVOKED (red)
```

**Pass Criteria**: Status accurately reflects certificate state

---

## 📊 Test Results Template

Use this template to document your tests:

```
Test #: ___  Date: __________  Tester: __________

Test Name: _________________________________

Steps Performed:
[ ] Step 1
[ ] Step 2
[ ] Step 3

Results:
✅ Expected behavior 1
✅ Expected behavior 2
⚠️ Unexpected behavior (describe)

Pass/Fail: ______

Notes:
_____________________________________________
```

## 🐛 Troubleshooting

### "Connection refused"
**Cause**: Server not running  
**Fix**: Start `messaging_server.py` first

### "Error loading credentials"
**Cause**: PKI not configured  
**Fix**: Run `python setup.py --auto`

### Port already in use
**Cause**: Previous server still running  
**Fix**: 
```bash
# Linux/Mac
lsof -i :5555
kill -9 <PID>

# Windows
netstat -ano | findstr :5555
taskkill /PID <PID> /F
```

### "Certificate not found"
**Cause**: Missing certificate files  
**Fix**: Re-run setup
```bash
python setup.py --auto
```

### Messages not received
**Cause**: Recipient not connected  
**Fix**: Ensure all 4 terminals are running

## 📁 File Structure

```
pki/
├── messaging_server.py      # Message routing server
├── client_base.py            # Unified client (Alice/Bob)
├── admin.py                  # Admin console
├── setup.py                  # PKI initialization
├── pki.py                    # PKI core functions
├── pki_encryption.py         # Encryption/signing
├── requirements.txt          # Dependencies
├── README.md                 # This file
└── data/                     # Generated by setup
    ├── keys/                 # Private keys
    │   ├── root_ca_key.pem
    │   ├── intermediate_ca_key.pem
    │   ├── alice_key.pem
    │   └── bob_key.pem
    ├── certs/                # Certificates
    │   ├── root_ca_cert.pem
    │   ├── intermediate_ca_cert.pem
    │   ├── alice_cert.pem
    │   └── bob_cert.pem
    └── registry.json         # Certificate registry
```

## 🔒 Security Architecture

```
Message Flow:
1. Alice types message
2. Message encrypted with AES-256
3. AES key encrypted with Bob's RSA public key
4. Message signed with Alice's RSA private key
5. Sent via server
6. Bob verifies signature
7. Bob decrypts message
8. Admin logs event
```

**Cryptographic Stack:**
- **Asymmetric**: RSA-4096 (OAEP padding)
- **Symmetric**: AES-256-CBC (PKCS7 padding)
- **Signature**: RSA-PSS + SHA-256
- **Key Derivation**: SHA-256

## 📚 Concepts Demonstrated

1. ✅ **Public Key Infrastructure (PKI)**
2. ✅ **Certificate Hierarchy** (Root → Intermediate → End-entity)
3. ✅ **X.509 Certificates**
4. ✅ **Hybrid Encryption**
5. ✅ **Digital Signatures**
6. ✅ **Non-repudiation**
7. ✅ **Certificate Revocation**
8. ✅ **End-to-End Encryption**
9. ✅ **Message Integrity**
10. ✅ **Authentication**

## ⚠️ Production Warning

**This is an educational project!**

For production use, implement:
- [ ] Mutual TLS authentication
- [ ] Real OCSP responder
- [ ] Hardware Security Module (HSM)
- [ ] Certificate Revocation Lists (CRL)
- [ ] Message persistence
- [ ] Audit logging
- [ ] Rate limiting
- [ ] Input validation
- [ ] Penetration testing

## 📖 References

- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) - X.509 PKI
- [RFC 3447](https://www.rfc-editor.org/rfc/rfc3447) - RSA Cryptography
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) - OCSP
- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) - Key Management

## 🎓 Learning Objectives

After completing all tests, you should understand:

- ✅ How PKI hierarchies work
- ✅ Symmetric vs asymmetric encryption
- ✅ Digital signature verification
- ✅ Certificate lifecycle management
- ✅ Revocation mechanisms
- ✅ Secure communication protocols
- ✅ Thread-safe programming
- ✅ Network socket programming

## 📝 Test Checklist

Before submission/demo:

- [ ] All 10 tests completed
- [ ] Test results documented
- [ ] Screenshots taken
- [ ] Error scenarios tested
- [ ] Code reviewed
- [ ] Dependencies listed
- [ ] Setup instructions verified
- [ ] Troubleshooting section complete

## 🤝 Contributing

To extend this project:

1. **Add user Charlie**: Modify setup.py and client_base.py
2. **Implement CRL**: Create certificate revocation list
3. **Add GUI**: Use tkinter or PyQt
4. **Database storage**: Persist messages
5. **Group chat**: Multi-party encryption
6. **File transfer**: Encrypted file sharing

## 📧 Support

For issues:
1. Check troubleshooting section
2. Verify all dependencies installed
3. Ensure Python 3.8+
4. Review test scenarios

## 📄 License

Educational use only. Not for production deployment.

---

**Happy Testing! 🎉🔐**

*Last Updated: January 2026*