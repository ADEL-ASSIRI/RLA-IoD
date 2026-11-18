"""Thin wrappers around OpenSSL (via the `cryptography` package) for the
primitives used by RLA-IoD: NIST P-256 ECDH/ECDSA, HKDF-SHA-256, HMAC-SHA-256.

Wire encodings (all fixed-length, so message sizes are exact):
  * EC point   : 33 B, SEC1 compressed
  * signature  : 64 B, raw r || s
  * MAC tag    : 16 B, HMAC-SHA-256 truncated to 128 bit
"""
from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

CURVE = ec.SECP256R1()
POINT_LEN = 33
SIG_LEN = 64
TAG_LEN = 16


class CryptoError(Exception):
    """Raised when a cryptographic check fails (bad point, signature, ...)."""


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------
def gen_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(CURVE)


def pub_bytes(priv_or_pub) -> bytes:
    pub = priv_or_pub.public_key() if hasattr(priv_or_pub, "public_key") else priv_or_pub
    return pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )


def load_pub(data: bytes) -> ec.EllipticCurvePublicKey:
    """Decode *and validate* a compressed point (must lie on P-256)."""
    if len(data) != POINT_LEN:
        raise CryptoError("bad point length")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)
    except Exception as exc:  # noqa: BLE001 - library raises ValueError
        raise CryptoError("invalid curve point") from exc


# --------------------------------------------------------------------------
# ECDH / ECDSA
# --------------------------------------------------------------------------
def ecdh(priv: ec.EllipticCurvePrivateKey, peer_pub: ec.EllipticCurvePublicKey) -> bytes:
    return priv.exchange(ec.ECDH(), peer_pub)


def sign(priv: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    r, s = decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(pub: ec.EllipticCurvePublicKey, sig: bytes, msg: bytes) -> bool:
    if len(sig) != SIG_LEN:
        return False
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------
# Hash / MAC / KDF
# --------------------------------------------------------------------------
def H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.digest(key, msg, "sha256")


def mac16(key: bytes, msg: bytes) -> bytes:
    return hmac.digest(key, msg, "sha256")[:TAG_LEN]


def ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.digest(salt if salt else b"\x00" * 32, ikm, "sha256")


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.digest(prk, t + info + bytes([i]), "sha256")
        out += t
        i += 1
    return out[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)
