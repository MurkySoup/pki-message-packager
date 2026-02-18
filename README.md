# ECC PKI Message Packager

A command-line utility for securely packaging arbitrary message data using modern elliptic-curve cryptography.

---

## Description

The tool implements an ECIES-style hybrid encryption scheme using:

* X25519 key agreement
* HKDF-SHA256 key derivation
* AES-256-GCM authenticated encryption

It produces a compact, self-contained binary package suitable for storage or later delivery. The utility intentionally avoids certificates and communication management. It focuses exclusively on secure data packaging and recovery.

NOTE: This program is barely more than "proof-of-concept", and should not be used as a production-ready tool. Additional testing and review is required.

---

## Features

* X25519 keypair generation from CLI
* Hybrid encryption for arbitrary message sizes
* Authenticated encryption with tamper detection
* Forward-secrecy capable design (ephemeral keys)
* Minimal binary package format
* No certificates or X.509 overhead
* File, string, or stdin message input
* Base64 encoding option
* Python 3.11+ compatible
* Production-quality code structure

---

## Cryptographic Design

### Encryption Workflow

1. Generate ephemeral X25519 keypair
2. Compute shared secret with recipient public key
3. Derive symmetric key using HKDF-SHA256
4. Encrypt message using AES-256-GCM
5. Package ephemeral public key + parameters + ciphertext

### Security Properties

* Confidentiality of message data
* Integrity and tamper detection
* Strong modern primitives
* Small keys and minimal metadata
* Compromise containment via ephemeral keys

---

## Installation

### Requirements

* Python 3.11+
* `cryptography` library

Install dependency:

```bash
pip install cryptography
```

---

## Command-Line Usage

### Generate Keypair

```bash
python pki-message-packager-ecies-hydrid.py keygen \
  --private private.pem \
  --public public.pem
```

---

### Encrypt a Message

#### From string

```bash
python pki-message-packager-ecies-hydrid.py encrypt \
  --key public.pem \
  --message "Hello world" \
  --output message.eci
```

#### From file

```bash
python pki-message-packager-ecies-hydrid.py encrypt \
  --key public.pem \
  --input input.bin \
  --output message.eci
```

#### From stdin

```bash
cat large_file.bin | python pki-message-packager-ecies-hydrid.py encrypt --key public.pem > pkg.bin
```

#### Base64 output

```bash
python pki-message-packager-ecies-hydrid.py encrypt \
  --key public.pem \
  --input input.bin \
  --base64 \
  --output message.txt
```

---

### Decrypt a Package

```bash
python pki-message-packager-ecies-hydrid.py decrypt \
  --key private.pem \
  --input message.eci
```

Base64 input:

```bash
python pki-message-packager-ecies-hydrid.py decrypt \
  --key private.pem \
  --input message.txt \
  --base64
```

---

## Package Format Specification

Binary structure:

```
[ magic 4 bytes ]        b'ECI1'
[ ephemeral public key ] 32 bytes
[ salt length 1 byte ]
[ salt ]
[ nonce length 1 byte ]
[ nonce ]
[ ciphertext length 8 bytes ]
[ AES-GCM ciphertext + tag ]
```

Properties:

* Deterministic parsing
* Versioned header
* No serialization ambiguity
* Minimal metadata exposure

---

## Key Format

Keys are stored in PEM encoding:

| Key Type | Format               |
| -------- | -------------------- |
| Private  | PKCS#8               |
| Public   | SubjectPublicKeyInfo |

Certificates are intentionally not used.

---

## Error Handling Behavior

The utility fails fast on:

* Invalid package format
* Wrong private key
* Corrupted ciphertext
* Authentication failure
* Tampering detection

AES-GCM ensures integrity verification during decryption.

---

## Security Considerations

Recommended practices:

* Protect private keys using filesystem permissions
* Maintain secure key distribution procedures
* Do not reuse ciphertext as plaintext input
* Validate public key provenance before use
* Consider passphrase-protected private keys in production environments

Not provided by this utility:

* Identity verification
* Key distribution
* Certificate infrastructure
* Secure communication channels
* Logging infrastructure

---

## Design Rationale

| Decision                  | Rationale                                          |
| ------------------------- | -------------------------------------------------- |
| X25519 key agreement      | Modern, safe-by-default elliptic-curve primitive   |
| HKDF-SHA256               | Cryptographically sound key derivation             |
| AES-256-GCM               | Authenticated encryption with integrity protection |
| ECIES-style hybrid design | Efficient and secure for arbitrary message size    |
| Ephemeral keys            | Enables compromise containment                     |
| No certificates           | Avoid unnecessary metadata                         |
| Binary format             | Efficient and deterministic                        |
| CLI-only interface        | Scriptability and simplicity                       |

---

## Performance Characteristics

* Constant-time elliptic-curve operations
* Small fixed-size keys
* Linear scaling with message size
* Suitable for large files and streaming input

---

## Exit Codes

| Code | Meaning                   |
| ---- | ------------------------- |
| 0    | Success                   |
| 1    | Argument or runtime error |

---

## requirements.txt

```
cryptography>=42.0.0,<44.0.0
```

---

## Future Enhancements

Potential extensions:

* Optional Ed25519 signatures
* Streaming encryption for very large files
* Multi-recipient packaging
* Deterministic test vectors
* Formal package specification
* Hardware token integration
* Secure key storage helpers

---

# License

This tool is released under the Apache 2.0 license. See the LICENSE file in this repo for details.

# Built With

* [Python](https://www.python.org) designed by Guido van Rossum

## Author

**Rick Pelletier**
