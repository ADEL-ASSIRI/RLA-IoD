"""Executable adversary harness (Section 5.5, Table 3).

Every attack acts on the *real byte strings* produced by the implementation.
``accepted == True`` means the attack SUCCEEDED (a party accepted something it
must not have, or the adversary recovered a key). ``stage`` names the check that
rejected the attack (taken from the CryptoError message).
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Callable

from . import crypto as C
from .pki import CERT_LEN, DroneState, Pseudonym, TrustedAuthority
from .protocol import GCS, Drone, StaticECDH, derive_keys, transcript_hash
from .session import Session
from .testbed import Clock, World, make_world, run_handshake


@dataclass
class Outcome:
    accepted: bool
    stage: str = "-"


def _attempt(fn: Callable[[], object]) -> Outcome:
    """Run `fn`; if a check rejects it, report the stage, otherwise the attack worked."""
    try:
        fn()
        return Outcome(True)
    except C.CryptoError as exc:
        return Outcome(False, str(exc))


def _flip(b: bytes, rng: random.Random) -> bytes:
    i = rng.randrange(len(b))
    return b[:i] + bytes([b[i] ^ (1 << rng.randrange(8))]) + b[i + 1 :]


# ---------------------------------------------------------------- control
def honest(rng):
    w = make_world()
    *_, dk, gk, _pid, _p = run_handshake(w)
    ok = dk.K_s == gk.K_s and dk.CK == gk.CK
    return Outcome(ok, "-")  # "accepted" here means *the honest run succeeded*


# ---------------------------------------------------------------- handshake attacks
def stale_m1(rng):
    w = make_world()
    m1 = w.drone.start()
    w.clock.t += 60  # replayed one minute later
    return _attempt(lambda: w.gcs.handle_m1(m1))


def replay_m3(rng):
    w = make_world()
    _, _, m3_old, *_ = run_handshake(w)          # attacker records M3 of session 1
    m1 = w.drone.start()                          # session 2 (fresh nonces)
    _m2, pending = w.gcs.handle_m1(m1)
    return _attempt(lambda: w.gcs.handle_m3(m3_old, pending))


def mitm_Y(rng):
    w = make_world()
    m1 = w.drone.start()
    m2, _ = w.gcs.handle_m1(m1)
    Ya = C.pub_bytes(C.gen_keypair())
    return _attempt(lambda: w.drone.handle_m2(Ya + m2[33:]))


def mitm_X(rng):
    w = make_world()
    m1 = w.drone.start()
    Xa = C.pub_bytes(C.gen_keypair())
    m2, _ = w.gcs.handle_m1(Xa + m1[33:])        # GCS answers the attacker's X
    return _attempt(lambda: w.drone.handle_m2(m2))


def flip_m2(rng):
    w = make_world()
    m2, _ = w.gcs.handle_m1(w.drone.start())
    return _attempt(lambda: w.drone.handle_m2(_flip(m2, rng)))


def flip_m3(rng):
    w = make_world()
    m2, pending = w.gcs.handle_m1(w.drone.start())
    m3, _ = w.drone.handle_m2(m2)
    return _attempt(lambda: w.gcs.handle_m3(_flip(m3, rng), pending))


def rogue_gcs(rng):
    w = make_world()
    foreign = TrustedAuthority()
    rogue = GCS(foreign.provision_gcs(os.urandom(16), w.clock() + 86400), foreign.pk, clock=w.clock)
    m2, _ = rogue.handle_m1(w.drone.start())
    return _attempt(lambda: w.drone.handle_m2(m2))


def impersonate_drone(rng):
    w = make_world()
    foreign = TrustedAuthority()
    pool = foreign.provision_drone(os.urandom(16), 2, w.clock() + 86400)
    atk = Drone(DroneState(pool=pool, pk_ta=w.ta.pk), clock=w.clock)  # trusts real TA key to get through M2
    m2, pending = w.gcs.handle_m1(atk.start())
    m3, _ = atk.handle_m2(m2)
    return _attempt(lambda: w.gcs.handle_m3(m3, pending))


def stolen_cert(rng):
    w = make_world()
    victim = w.drone.state.pool[0]
    fake = Pseudonym(victim.pid, C.gen_keypair(), victim.cert)  # real cert, wrong private key
    atk = Drone(DroneState(pool=[fake], pk_ta=w.ta.pk), clock=w.clock)
    m2, pending = w.gcs.handle_m1(atk.start())
    m3, _ = atk.handle_m2(m2)
    return _attempt(lambda: w.gcs.handle_m3(m3, pending))


def revoked(rng):
    w = make_world()
    w.gcs.revoked.add(w.drone.state.pool[0].pid)
    m2, pending = w.gcs.handle_m1(w.drone.start())
    m3, _ = w.drone.handle_m2(m2)
    return _attempt(lambda: w.gcs.handle_m3(m3, pending))


def expired(rng):
    w = make_world()
    pool = w.ta.provision_drone(os.urandom(16), 1, w.clock() + 100)  # short-lived pseudonym
    drone = Drone(DroneState(pool=pool, pk_ta=w.ta.pk), clock=w.clock)
    m2, pending = w.gcs.handle_m1(drone.start())
    m3, _ = drone.handle_m2(m2)
    w.clock.t += 200
    return _attempt(lambda: w.gcs.handle_m3(m3, pending))


def reflection(rng):
    w = make_world()
    m2, pending = w.gcs.handle_m1(w.drone.start())
    return _attempt(lambda: w.gcs.handle_m3(m2, pending))   # M2 returned as M3


# ---------------------------------------------------------------- session-layer attacks
def _sessions():
    w = make_world()
    *_, dk, gk, _pid, _p = run_handshake(w)
    return Session("D", dk), Session("G", gk)


def replay_frame(rng):
    d, g = _sessions()
    f = d.send(b"telemetry")
    g.recv(f)
    return _attempt(lambda: g.recv(f))


def tamper_frame(rng):
    d, g = _sessions()
    f = d.send(b"telemetry-payload")
    i = 5 + rng.randrange(len(f) - 4 - 1 - 16)  # inside the payload, after seq and type
    bad = f[:i] + bytes([f[i] ^ 1]) + f[i + 1 :]
    return _attempt(lambda: g.recv(bad))


def delete_reorder(rng):
    d, g = _sessions()
    d.send(b"one")                      # dropped by the attacker
    f2 = d.send(b"two")
    return _attempt(lambda: g.recv(f2))


# ---------------------------------------------------------------- long-term key leak
def leaked_keys_rla(rng):
    """Adversary records a session, later obtains sk_G and every pseudonym key,
    and tries every ECDH combination it can form as the premaster secret."""
    w = make_world()
    m1, m2, m3, dk, gk, _pid, _p = run_handshake(w)
    X, T, nD = m1[:33], m1[33:37], m1[37:53]
    Y, nG = m2[:33], m2[33:49]
    th = transcript_hash(X, Y, nD, nG, T)
    tauG = m2[113:129]
    leaked = [w.gcs.creds.sk] + [p.sk for p in w.drone.state.pool]
    for sk in leaked:
        for pt in (X, Y):
            cand = derive_keys(C.ecdh(sk, C.load_pub(pt)), nD, nG, th)
            if C.ct_eq(tauG, C.mac16(cand.K_m, b"G" + w.gcs.creds.ident)) or cand.K_s == dk.K_s:
                return Outcome(True)
    return Outcome(False, "session key not recoverable")


def leaked_key_static(rng):
    w = make_world()
    drone_sk = C.gen_keypair()
    did = os.urandom(16)
    scheme = StaticECDH(did, drone_sk, w.gcs.creds, w.ta.pk, {did: C.pub_bytes(drone_sk)}, clock=w.clock)
    m1 = scheme.drone_start()
    m2, k_gcs = scheme.gcs_handle(m1)
    k_drone = scheme.drone_finish(m2)
    assert k_gcs == k_drone
    nD, nG = m1[20:36], m2[4 + CERT_LEN : 20 + CERT_LEN]
    # later: sk_G leaks; pk_i is public in the registry/certificate
    Z = C.ecdh(w.gcs.creds.sk, C.load_pub(C.pub_bytes(drone_sk)))
    return Outcome(C.hkdf(Z, nD + nG, b"static-session") == k_drone)


ATTACKS: list[tuple[str, Callable]] = [
    ("Honest session (control)", honest),
    ("Replay of stale M1 (60 s old)", stale_m1),
    ("Replay of recorded M3 in a new session", replay_m3),
    ("MitM substitutes GCS ephemeral key Y", mitm_Y),
    ("MitM substitutes drone ephemeral key X", mitm_X),
    ("Random bit-flip in M2", flip_m2),
    ("Random bit-flip in M3", flip_m3),
    ("Rogue GCS (certificate from foreign TA)", rogue_gcs),
    ("Impersonating drone (foreign-TA pseudonym cert)", impersonate_drone),
    ("Stolen pseudonym certificate without its key", stolen_cert),
    ("Revoked pseudonym presented", revoked),
    ("Expired pseudonym certificate", expired),
    ("Reflection (M2 returned as M3)", reflection),
    ("Replay of an in-session frame", replay_frame),
    ("Tampering with an in-session frame", tamper_frame),
    ("Frame deletion / re-ordering (gap)", delete_reorder),
    ("Leaked long-term keys, RLA-IoD", leaked_keys_rla),
    ("Leaked long-term key, static-ECDH design", leaked_key_static),
]
