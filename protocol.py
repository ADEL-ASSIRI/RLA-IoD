"""RLA-IoD three-message authenticated key agreement (Section 4.2) plus the two
baselines used in Table 6 (pre-shared-key HMAC, and static-ECDH).

All messages are real byte strings. Failures raise ``CryptoError`` whose
message is the *stage* at which the check failed (used by the attack harness).

  M1 = X(33) || T(4) || n_D(16) || cid(8) [|| cookie(16)]
  M2 = Y(33) || n_G(16) || sigma_G(64) || tau_G(16) || (Cert_G(117) | cid(8))
  M3 = Cert_j(117) || sigma_D(64) || tau_D(16)
"""
from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass
from typing import Callable

from . import crypto as C
from .pki import (
    CERT_LEN,
    Cert,
    DroneState,
    GCSCredentials,
    ID_LEN,
    verify_cert,
)

DELTA_T = 5  # seconds, timestamp acceptance window
NONCE_LEN = 16
CID_LEN = 8
COOKIE_LEN = 16
COOKIE_REPLY_TAG = b"\xc0"

M1_LEN = C.POINT_LEN + 4 + NONCE_LEN + CID_LEN  # 61
M3_LEN = CERT_LEN + C.SIG_LEN + C.TAG_LEN  # 197


def cid_of(cert_raw: bytes) -> bytes:
    return C.H(b"cid", cert_raw)[:CID_LEN]


@dataclass
class SessionKeys:
    K_m: bytes
    K_s: bytes
    CK: bytes
    th: bytes


def transcript_hash(X: bytes, Y: bytes, nD: bytes, nG: bytes, T: bytes) -> bytes:
    return C.H(b"RLA-TH", X, Y, nD, nG, T)  # Eq. (2)


def derive_keys(Z: bytes, nD: bytes, nG: bytes, th: bytes) -> SessionKeys:
    prk = C.hkdf_extract(nD + nG, Z)  # Eq. (3)
    return SessionKeys(  # Eq. (4): one label per key
        K_m=C.hkdf_expand(prk, b"K_m" + th),
        K_s=C.hkdf_expand(prk, b"K_s" + th),
        CK=C.hkdf_expand(prk, b"CK" + th),
        th=th,
    )


def _now_default() -> int:
    return int(time.time())


# =============================================================================
# GCS
# =============================================================================
@dataclass
class _Pending:
    keys: SessionKeys
    X: bytes
    Y: bytes
    nD: bytes
    nG: bytes
    T: bytes


class GCS:
    def __init__(
        self,
        creds: GCSCredentials,
        pk_ta: bytes,
        revoked: set[bytes] | None = None,
        clock: Callable[[], int] = _now_default,
    ) -> None:
        self.creds = creds
        self.pk_ta = pk_ta
        self.revoked = revoked if revoked is not None else set()
        self.clock = clock
        self.require_cookie = False
        self._Kc = os.urandom(32)

    # -- cookie (Section 4.7) ---------------------------------------------
    def _cookie(self, T: bytes) -> bytes:
        return C.mac16(self._Kc, T)

    # -- M1 -> M2 ---------------------------------------------------------
    def handle_m1(self, m1: bytes) -> tuple[bytes, _Pending | None]:
        """Returns (reply, pending). `pending` is None for a cookie challenge."""
        if len(m1) not in (M1_LEN, M1_LEN + COOKIE_LEN):
            raise C.CryptoError("malformed M1")
        T = m1[33:37]
        if abs(self.clock() - struct.unpack(">I", T)[0]) > DELTA_T:
            raise C.CryptoError("stale timestamp")
        if self.require_cookie:
            if len(m1) != M1_LEN + COOKIE_LEN:
                return COOKIE_REPLY_TAG + self._cookie(T), None
            if not C.ct_eq(m1[M1_LEN:], self._cookie(T)):
                raise C.CryptoError("bad cookie")  # one HMAC, nothing else
            m1 = m1[:M1_LEN]
        X, nD, cid = m1[:33], m1[37:53], m1[53:61]
        Xpub = C.load_pub(X)  # validates the point
        y = C.gen_keypair()
        Y = C.pub_bytes(y)
        nG = os.urandom(NONCE_LEN)
        th = transcript_hash(X, Y, nD, nG, T)
        keys = derive_keys(C.ecdh(y, Xpub), nD, nG, th)
        IDG = self.creds.ident
        sigG = C.sign(self.creds.sk, b"RLA-G" + th + IDG)  # Eq. (5)
        tauG = C.mac16(keys.K_m, b"G" + IDG)
        cert_raw = self.creds.cert.encode()
        tail = cid_of(cert_raw) if cid == cid_of(cert_raw) else cert_raw
        m2 = Y + nG + sigG + tauG + tail
        return m2, _Pending(keys, X, Y, nD, nG, T)

    # -- M3 -> finish -----------------------------------------------------
    def handle_m3(self, m3: bytes, pending: _Pending) -> tuple[SessionKeys, bytes]:
        """Returns (keys, pid) once the drone is authenticated."""
        if len(m3) != M3_LEN:
            raise C.CryptoError("malformed M3")
        cert = verify_cert(m3[:CERT_LEN], self.pk_ta, self.clock(), self.revoked)
        sigD = m3[CERT_LEN : CERT_LEN + C.SIG_LEN]
        tauD = m3[CERT_LEN + C.SIG_LEN :]
        if not C.verify(C.load_pub(cert.pk), sigD, b"RLA-D" + pending.keys.th + cert.ident):
            raise C.CryptoError("drone signature")
        if not C.ct_eq(tauD, C.mac16(pending.keys.K_m, b"D" + cert.ident)):
            raise C.CryptoError("drone MAC")
        return pending.keys, cert.ident


# =============================================================================
# Drone
# =============================================================================
class Drone:
    def __init__(self, state: DroneState, clock: Callable[[], int] = _now_default) -> None:
        self.state = state
        self.clock = clock
        self._x = None
        self._pre = None  # precomputed ephemeral key (Table 7, "+ precomputed")

    def precompute(self) -> None:
        self._pre = C.gen_keypair()

    def start(self) -> bytes:
        """M1 = X || T || n_D || cid  (no identity)."""
        self._x = self._pre or C.gen_keypair()
        self._pre = None
        self._X = C.pub_bytes(self._x)
        self._nD = os.urandom(NONCE_LEN)
        self._T = struct.pack(">I", self.clock())
        cc = self.state.cached_gcs_cert
        cid = cid_of(cc.encode()) if cc is not None else b"\x00" * CID_LEN
        self._m1 = self._X + self._T + self._nD + cid
        return self._m1

    def retry_with_cookie(self, reply: bytes) -> bytes:
        if not (len(reply) == 1 + COOKIE_LEN and reply[:1] == COOKIE_REPLY_TAG):
            raise C.CryptoError("not a cookie reply")
        return self._m1 + reply[1:]

    def handle_m2(self, m2: bytes) -> tuple[bytes, SessionKeys]:
        """Verify the GCS, pick the next pseudonym, return (M3, keys)."""
        fixed = C.POINT_LEN + NONCE_LEN + C.SIG_LEN + C.TAG_LEN  # 129
        if len(m2) not in (fixed + CERT_LEN, fixed + CID_LEN):
            raise C.CryptoError("malformed M2")
        Y, nG = m2[:33], m2[33:49]
        sigG, tauG = m2[49:113], m2[113:129]
        tail = m2[129:]
        if len(tail) == CERT_LEN:
            cert = verify_cert(tail, self.state.pk_ta, self.clock())
            self.state.cached_gcs_cert = cert
        else:
            cc = self.state.cached_gcs_cert
            if cc is None or tail != cid_of(cc.encode()):
                raise C.CryptoError("unknown cid")
            cert = cc
        Ypub = C.load_pub(Y)
        th = transcript_hash(self._X, Y, self._nD, nG, self._T)
        if not C.verify(C.load_pub(cert.pk), sigG, b"RLA-G" + th + cert.ident):
            raise C.CryptoError("GCS signature")
        keys = derive_keys(C.ecdh(self._x, Ypub), self._nD, nG, th)
        if not C.ct_eq(tauG, C.mac16(keys.K_m, b"G" + cert.ident)):
            raise C.CryptoError("GCS MAC")
        ps = self.state.next_pseudonym()  # pseudonym disclosed only now
        sigD = C.sign(ps.sk, b"RLA-D" + th + ps.pid)
        tauD = C.mac16(keys.K_m, b"D" + ps.pid)
        self._x = None  # D erases x
        return ps.cert.encode() + sigD + tauD, keys


# =============================================================================
# Baseline 1: pre-shared key, HMAC only (2 messages, 104 B)
# =============================================================================
class PSKScheme:
    def __init__(self, psk: bytes, drone_id: bytes, gcs_id: bytes, clock=_now_default) -> None:
        self.psk, self.did, self.gid, self.clock = psk, drone_id, gcs_id, clock

    def drone_start(self) -> bytes:
        self._nD = os.urandom(NONCE_LEN)
        self._T = struct.pack(">I", self.clock())
        body = self.did + self._T + self._nD
        return body + C.mac16(self.psk, b"M1" + body)

    def gcs_handle(self, m1: bytes) -> tuple[bytes, bytes]:
        body, tag = m1[:36], m1[36:]
        if not C.ct_eq(tag, C.mac16(self.psk, b"M1" + body)):
            raise C.CryptoError("psk mac")
        T = body[16:20]
        if abs(self.clock() - struct.unpack(">I", T)[0]) > DELTA_T:
            raise C.CryptoError("stale timestamp")
        nD = body[20:36]
        nG = os.urandom(NONCE_LEN)
        out = self.gid + T + nG
        m2 = out + C.mac16(self.psk, b"M2" + out + nD)
        return m2, C.hkdf(self.psk, nD + nG, b"psk-session")

    def drone_finish(self, m2: bytes) -> bytes:
        body, tag = m2[:36], m2[36:]
        nG = body[20:36]
        if not C.ct_eq(tag, C.mac16(self.psk, b"M2" + body + self._nD)):
            raise C.CryptoError("psk mac")
        return C.hkdf(self.psk, self._nD + nG, b"psk-session")


# =============================================================================
# Baseline 2: static-ECDH design (2 messages, 301 B)
#   K = HKDF(ECDH(sk_G, pk_i), salt = n_D || n_G); drone identity travels in clear.
# =============================================================================
class StaticECDH:
    def __init__(
        self,
        drone_id: bytes,
        drone_sk,
        gcs: GCSCredentials,
        pk_ta: bytes,
        drone_pk_registry: dict[bytes, bytes],
        clock=_now_default,
    ) -> None:
        self.did, self.dsk = drone_id, drone_sk
        self.gcs, self.pk_ta, self.registry, self.clock = gcs, pk_ta, drone_pk_registry, clock

    def drone_start(self) -> bytes:
        self._nD = os.urandom(NONCE_LEN)
        self._T = struct.pack(">I", self.clock())
        body = self.did + self._T + self._nD
        return body + C.sign(self.dsk, b"S-D" + body)

    def gcs_handle(self, m1: bytes) -> tuple[bytes, bytes]:
        body, sig = m1[:36], m1[36:]
        did, T, nD = body[:16], body[16:20], body[20:36]
        if abs(self.clock() - struct.unpack(">I", T)[0]) > DELTA_T:
            raise C.CryptoError("stale timestamp")
        pk_i = self.registry[did]
        if not C.verify(C.load_pub(pk_i), sig, b"S-D" + body):
            raise C.CryptoError("drone signature")
        nG = os.urandom(NONCE_LEN)
        sigG = C.sign(self.gcs.sk, b"S-G" + nD + nG + T + did)
        Z = C.ecdh(self.gcs.sk, C.load_pub(pk_i))
        m2 = T + self.gcs.cert.encode() + nG + sigG
        return m2, C.hkdf(Z, nD + nG, b"static-session")

    def drone_finish(self, m2: bytes) -> bytes:
        T, cert_raw, nG, sigG = m2[:4], m2[4:4 + CERT_LEN], m2[4 + CERT_LEN : 20 + CERT_LEN], m2[20 + CERT_LEN :]
        cert = verify_cert(cert_raw, self.pk_ta, self.clock())
        if not C.verify(C.load_pub(cert.pk), sigG, b"S-G" + self._nD + nG + T + self.did):
            raise C.CryptoError("GCS signature")
        Z = C.ecdh(self.dsk, C.load_pub(cert.pk))
        return C.hkdf(Z, self._nD + nG, b"static-session")
