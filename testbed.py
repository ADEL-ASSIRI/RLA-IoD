"""Convenience builders shared by tests and experiments."""
from __future__ import annotations

import os
from dataclasses import dataclass

from .pki import DroneState, TrustedAuthority
from .protocol import GCS, Drone


class Clock:
    """Controllable clock so stale/expired tests are deterministic."""

    def __init__(self, t: int = 1_800_000_000) -> None:
        self.t = t

    def __call__(self) -> int:
        return self.t


@dataclass
class World:
    ta: TrustedAuthority
    gcs: GCS
    drone: Drone
    real_id: bytes
    clock: Clock


def make_world(k: int = 3, ttl: int = 86_400, cached: bool = False, ta: TrustedAuthority | None = None) -> World:
    clock = Clock()
    ta = ta or TrustedAuthority()
    gcs_creds = ta.provision_gcs(os.urandom(16), clock() + ttl)
    real_id = os.urandom(16)
    pool = ta.provision_drone(real_id, k, clock() + ttl)
    state = DroneState(pool=pool, pk_ta=ta.pk)
    if cached:
        state.cached_gcs_cert = gcs_creds.cert
    return World(ta, GCS(gcs_creds, ta.pk, clock=clock), Drone(state, clock=clock), real_id, clock)


def run_handshake(w: World, require_cookie: bool = False):
    """Honest three-message run. Returns (m1, m2, m3, drone_keys, gcs_keys, pid, pending)."""
    w.gcs.require_cookie = require_cookie
    m1 = w.drone.start()
    m2, pending = w.gcs.handle_m1(m1)
    if pending is None:  # cookie round trip
        m1 = w.drone.retry_with_cookie(m2)
        m2, pending = w.gcs.handle_m1(m1)
    m3, dkeys = w.drone.handle_m2(m2)
    gkeys, pid = w.gcs.handle_m3(m3, pending)
    return m1, m2, m3, dkeys, gkeys, pid, pending
