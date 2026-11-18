"""Session layer (Section 4.3): per-message hash ratchet (Level 1) and
authenticated DH ratchet (Level 2). Level 3 is simply a fresh handshake.

Each direction runs Eq. (6)  mk_t = H(0x02||ck_t),  ck_{t+1} = H(0x01||ck_t)
with its own chain seeded from CK. Frame = seq(4) || payload || MAC16(mk_t, seq||payload).
Payload byte 0 is a type: 0x00 data, 0x01 DH-ratchet request (X'), 0x02 response (Y').

Assumptions (stated in the manuscript's limitations): in-order delivery, and
the DH-ratchet request/response pair is exchanged with no data frames in flight.
"""
from __future__ import annotations

import struct

from . import crypto as C
from .protocol import SessionKeys

T_DATA, T_REQ, T_RSP = 0x00, 0x01, 0x02


def _step(ck: bytes) -> tuple[bytes, bytes]:
    """Return (mk_t, ck_{t+1})."""
    return C.H(b"\x02", ck), C.H(b"\x01", ck)


class FrameError(C.CryptoError):
    pass


class Session:
    def __init__(self, role: str, keys: SessionKeys) -> None:
        assert role in ("D", "G")
        self.role = role
        self.K_s = keys.K_s
        d2g = C.H(b"RLA-CK-d2g", keys.CK)
        g2d = C.H(b"RLA-CK-g2d", keys.CK)
        self.ck_send, self.ck_recv = (d2g, g2d) if role == "D" else (g2d, d2g)
        self.seq_send = 0
        self.seq_recv = 0
        self._x = None
        self.messages_since_dh = 0

    # -- Level 1 ------------------------------------------------------------
    def _seal(self, payload: bytes) -> bytes:
        mk, self.ck_send = _step(self.ck_send)  # old chain key is overwritten
        hdr = struct.pack(">I", self.seq_send)
        self.seq_send += 1
        self.messages_since_dh += 1
        return hdr + payload + C.mac16(mk, hdr + payload)

    def send(self, data: bytes) -> bytes:
        return self._seal(bytes([T_DATA]) + data)

    def _open(self, frame: bytes) -> bytes:
        if len(frame) < 4 + 1 + C.TAG_LEN:
            raise FrameError("malformed frame")
        (seq,) = struct.unpack(">I", frame[:4])
        if seq != self.seq_recv:
            raise FrameError("sequence")  # replay (seq < expected) or gap/reorder
        mk, nxt = _step(self.ck_recv)
        body, tag = frame[:-C.TAG_LEN], frame[-C.TAG_LEN :]
        if not C.ct_eq(tag, C.mac16(mk, body)):
            raise FrameError("frame MAC")  # state is NOT advanced on failure
        self.ck_recv = nxt
        self.seq_recv += 1
        self.messages_since_dh += 1
        return body[4:]

    def recv(self, frame: bytes) -> bytes:
        p = self._open(frame)
        if p[0] != T_DATA:
            raise FrameError("unexpected control frame")
        return p[1:]

    # -- Level 2: authenticated DH ratchet (Eq. 7) ---------------------------
    def _apply_dh(self, shared: bytes) -> None:
        self.ck_send = C.hkdf(shared, self.ck_send, b"dh-ratchet-" + (b"d2g" if self.role == "D" else b"g2d"))
        self.ck_recv = C.hkdf(shared, self.ck_recv, b"dh-ratchet-" + (b"g2d" if self.role == "D" else b"d2g"))
        self.messages_since_dh = 0

    def dh_request(self) -> bytes:
        self._x = C.gen_keypair()
        return self._seal(bytes([T_REQ]) + C.pub_bytes(self._x))

    def dh_respond(self, req_frame: bytes) -> bytes:
        p = self._open(req_frame)
        if p[0] != T_REQ:
            raise FrameError("expected DH request")
        y = C.gen_keypair()
        shared = C.ecdh(y, C.load_pub(p[1:]))
        rsp = self._seal(bytes([T_RSP]) + C.pub_bytes(y))
        self._apply_dh(shared)
        return rsp

    def dh_finish(self, rsp_frame: bytes) -> None:
        p = self._open(rsp_frame)
        if p[0] != T_RSP or self._x is None:
            raise FrameError("expected DH response")
        shared = C.ecdh(self._x, C.load_pub(p[1:]))
        self._x = None
        self._apply_dh(shared)

    # -- helpers for tests / analysis ---------------------------------------
    def export_state(self) -> dict:
        """What a one-off state disclosure (memory dump) would reveal."""
        return {"ck_send": self.ck_send, "ck_recv": self.ck_recv,
                "seq_send": self.seq_send, "seq_recv": self.seq_recv}
