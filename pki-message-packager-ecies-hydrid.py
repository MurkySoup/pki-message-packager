#!/usr/bin/env python3


"""
pki-message-packager-ecies-hydrid.py
Protocol: ECI1

PKI message packaging utility using ECIES-style hybrid encryption:
X25519 + HKDF + AES-256-GCM.

Note: Messages/files should be kept to 1 gbyte or less

Python 3.11+

Linter: ruff check pki-message-packager-ecies-hydrid.py --extend-select F,B,UP
"""

from __future__ import annotations
import argparse
import base64
import os
import struct
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MAGIC = b"ECI1"
AES_KEY_SIZE = 32
NONCE_SIZE = 12
EPHEMERAL_KEY_SIZE = 32


class PKIError(Exception):
    """Base exception for ECC PKI packaging errors."""


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate X25519 keypair in PEM format."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def load_public_key(path: Path) -> x25519.X25519PublicKey:
    """Load X25519 public key."""
    return serialization.load_pem_public_key(path.read_bytes())


def load_private_key(path: Path) -> x25519.X25519PrivateKey:
    """Load X25519 private key."""
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


# ---------------------------------------------------------------------------
# Cryptographic Core
# ---------------------------------------------------------------------------

def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive AES key from shared secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=b"ECC-PKI-PACKAGE",
    )
    return hkdf.derive(shared_secret)


def encrypt_message(public_key: x25519.X25519PublicKey, message: bytes) -> bytes:
    """Encrypt message using ECIES-style hybrid encryption."""
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    shared_secret = ephemeral_private.exchange(public_key)

    salt = os.urandom(16)
    aes_key = derive_key(shared_secret, salt)

    nonce = os.urandom(NONCE_SIZE)
    aes = AESGCM(aes_key)
    ciphertext = aes.encrypt(nonce, message, None)

    eph_bytes = ephemeral_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    return _pack(eph_bytes, salt, nonce, ciphertext)


def decrypt_message(private_key: x25519.X25519PrivateKey, package: bytes) -> bytes:
    """Decrypt ECIES package."""
    eph_bytes, salt, nonce, ciphertext = _unpack(package)

    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(eph_bytes)
    shared_secret = private_key.exchange(ephemeral_public)

    aes_key = derive_key(shared_secret, salt)

    aes = AESGCM(aes_key)
    return aes.decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# Binary Format
# ---------------------------------------------------------------------------

def _pack(eph_key: bytes, salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Create binary package."""
    return b"".join(
        [
            MAGIC,
            eph_key,
            struct.pack(">B", len(salt)),
            salt,
            struct.pack(">B", len(nonce)),
            nonce,
            struct.pack(">Q", len(ciphertext)),
            ciphertext,
        ]
    )


def _unpack(data: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Parse binary package."""
    if not data.startswith(MAGIC):
        raise PKIError("Invalid package format")

    offset = len(MAGIC)

    eph_key = data[offset:offset + EPHEMERAL_KEY_SIZE]
    offset += EPHEMERAL_KEY_SIZE

    salt_len = data[offset]
    offset += 1

    salt = data[offset:offset + salt_len]
    offset += salt_len

    nonce_len = data[offset]
    offset += 1

    nonce = data[offset:offset + nonce_len]
    offset += nonce_len

    ct_len = struct.unpack(">Q", data[offset:offset + 8])[0]
    offset += 8

    ciphertext = data[offset:offset + ct_len]

    return eph_key, salt, nonce, ciphertext


# ---------------------------------------------------------------------------
# CLI Helpers
# ---------------------------------------------------------------------------

def read_message(args: argparse.Namespace) -> bytes:
    """Read message from CLI input."""
    if args.message:
        return args.message.encode()

    if args.input:
        return Path(args.input).read_bytes()

    return sys.stdin.buffer.read()


def write_output(data: bytes, args: argparse.Namespace) -> None:
    """Write output to file or stdout."""
    if args.output:
        Path(args.output).write_bytes(data)
    else:
        sys.stdout.buffer.write(data)


# ---------------------------------------------------------------------------
# CLI Commands
# ---------------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> None:
    private_pem, public_pem = generate_keypair()
    Path(args.private).write_bytes(private_pem)
    Path(args.public).write_bytes(public_pem)


def cmd_encrypt(args: argparse.Namespace) -> None:
    public_key = load_public_key(Path(args.key))
    message = read_message(args)
    package = encrypt_message(public_key, message)

    if args.base64:
        package = base64.b64encode(package)

    write_output(package, args)


def cmd_decrypt(args: argparse.Namespace) -> None:
    private_key = load_private_key(Path(args.key))
    package = read_message(args)

    if args.base64:
        package = base64.b64decode(package)

    plaintext = decrypt_message(private_key, package)
    write_output(plaintext, args)


# ---------------------------------------------------------------------------
# CLI Definition
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ECC PKI Message Packager")

    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("keygen", help="generate X25519 keypair")
    p.add_argument("--private", required=True, help="private key filename")
    p.add_argument("--public", required=True, help="public key filename")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("encrypt", help="encrypt message")
    p.add_argument("--key", required=True, help="recipient public key filename")
    p.add_argument("--message", help="message string to encrypt")
    p.add_argument("--input", help="input file name")
    p.add_argument("--output", help="output filename")
    p.add_argument("--base64", action="store_true", help="force base64 output")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="decrypt message")
    p.add_argument("--key", required=True, help="recipient private key filename")
    p.add_argument("--message", help="message string to decrypt")
    p.add_argument("--input", help="input filename")
    p.add_argument("--output", help="output filename")
    p.add_argument("--base64", action="store_true", help="force base64 input")
    p.set_defaults(func=cmd_decrypt)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

# end of script
