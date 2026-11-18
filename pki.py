"""Trusted authority (TA), GCS credentials and per-pseudonym certificates.

Certificate layout (Section 4.1 of the manuscript), all fixed length:

    Cert_G = ID_G(16) || pk_G(33) || exp(4) || sigma_TA(64)  = 117 B
    Cert_j = PID_j(16) || pk_j(33) || exp(4) || sigma_TA(64) = 117 B

    PID_j = HMAC_MSK(ID_i || epoch || j)[0:16]                    (Eq. 1)

Every pseudonym gets an *independent* key pair, so reusing a key cannot link
pseudonyms.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from . import crypto as C

ID_LEN = 16
EXP_LEN = 4
CERT_BODY_LEN = ID_LEN + C.POINT_LEN + EXP_LEN  # 53
CERT_LEN = CERT_BODY_LEN + C.SIG_LEN  # 117


@dataclass
class Cert:
    ident: bytes  # ID_G or PID_j
    pk: bytes  # compressed point
    exp: int  # unix seconds (uint32)
    sig: bytes  # TA signature over ident||pk||exp

    def body(self) -> bytes:
        return self.ident + self.pk + struct.pack(">I", self.exp)

    def encode(self) -> bytes:
        return self.body() + self.sig

    @staticmethod
    def decode(raw: bytes) -> "Cert":
        if len(raw) != CERT_LEN:
            raise C.CryptoError("malformed certificate")
        ident = raw[:ID_LEN]
        pk = raw[ID_LEN : ID_LEN + C.POINT_LEN]
        (exp,) = struct.unpack(">I", raw[ID_LEN + C.POINT_LEN : CERT_BODY_LEN])
        return Cert(ident, pk, exp, raw[CERT_BODY_LEN:])


@dataclass
class Pseudonym:
    pid: bytes
    sk: object  # EC private key
    cert: Cert

    def storage_bytes(self) -> int:
        return 32 + CERT_LEN  # 32-byte scalar + certificate = 149 B


@dataclass
class GCSCredentials:
    ident: bytes
    sk: object
    cert: Cert


class TrustedAuthority:
    def __init__(self) -> None:
        self.sk = C.gen_keypair()
        self.pk = C.pub_bytes(self.sk)
        self.msk = os.urandom(32)
        self.registry: dict[bytes, bytes] = {}  # PID -> real ID (accountability)

    # -- certificates -------------------------------------------------------
    def _issue(self, ident: bytes, pk: bytes, exp: int) -> Cert:
        body = ident + pk + struct.pack(">I", exp)
        return Cert(ident, pk, exp, C.sign(self.sk, b"CERT" + body))

    def provision_gcs(self, ident: bytes, exp: int) -> GCSCredentials:
        sk = C.gen_keypair()
        return GCSCredentials(ident, sk, self._issue(ident, C.pub_bytes(sk), exp))

    def provision_drone(self, real_id: bytes, k: int, exp: int, epoch: int = 0) -> list[Pseudonym]:
        pool = []
        for j in range(k):
            pid = C.hmac_sha256(self.msk, real_id + struct.pack(">II", epoch, j))[:ID_LEN]
            sk = C.gen_keypair()
            cert = self._issue(pid, C.pub_bytes(sk), exp)
            self.registry[pid] = real_id
            pool.append(Pseudonym(pid, sk, cert))
        return pool

    def resolve(self, pid: bytes) -> bytes | None:
        """Only the TA can map a pseudonym to a real identity."""
        return self.registry.get(pid)


def verify_cert(
    cert_raw: bytes, pk_ta: bytes, now: int, revoked: frozenset[bytes] | set[bytes] = frozenset()
) -> Cert:
    """Validate a certificate. Raises CryptoError with a *stage* label."""
    try:
        cert = Cert.decode(cert_raw)
    except C.CryptoError:
        raise C.CryptoError("malformed certificate")
    if not C.verify(C.load_pub(pk_ta), cert.sig, b"CERT" + cert.body()):
        raise C.CryptoError("cert signature")
    if cert.exp < now:
        raise C.CryptoError("cert expired")
    if cert.ident in revoked:
        raise C.CryptoError("cert revoked")
    try:
        C.load_pub(cert.pk)
    except C.CryptoError:
        raise C.CryptoError("cert signature")
    return cert


@dataclass
class DroneState:
    """What the on-board unit persists (Table 8)."""

    pool: list[Pseudonym]
    pk_ta: bytes
    cached_gcs_cert: Cert | None = None
    next_index: int = 0
    _extra: dict = field(default_factory=dict)

    def next_pseudonym(self) -> Pseudonym:
        ps = self.pool[self.next_index % len(self.pool)]
        self.next_index += 1
        return ps


# Persistent storage accounting (Table 8): pool + PK_TA(33) + one cached GCS
# certificate (117) + a 4-byte pool index / device serial.
def persistent_storage_bytes(k: int) -> tuple[int, int]:
    pool = k * (32 + CERT_LEN)
    return pool, pool + C.POINT_LEN + CERT_LEN + 4
