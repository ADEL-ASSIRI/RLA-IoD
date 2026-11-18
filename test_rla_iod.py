import os, random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import numpy as np
from rla_iod import crypto as C
from rla_iod.attacks import ATTACKS
from rla_iod.controller import Params, RiskController, objective, optimal_span, regret
from rla_iod.costmodel import OPS
from rla_iod.pki import persistent_storage_bytes
from rla_iod.session import Session
from rla_iod.testbed import make_world, run_handshake
from rla_iod import spansim as S


def test_handshake_agrees_and_sizes():
    w = make_world(); m1, m2, m3, dk, gk, pid, _ = run_handshake(w)
    assert dk.K_s == gk.K_s and dk.CK == gk.CK and dk.K_m == gk.K_m
    assert len(m3) == 197 and max(len(m1), len(m2), len(m3)) <= 255
    assert w.ta.resolve(pid) == w.real_id
    assert w.real_id not in m1 + m2 + m3          # real identity never on the air


def test_cached_cert_saves_109_bytes():
    cold = run_handshake(make_world())[1]; hot = run_handshake(make_world(cached=True))[1]
    assert len(cold) - len(hot) == 109


def test_cookie_path():
    w = make_world(); r = run_handshake(w, require_cookie=True)
    assert r[3].K_s == r[4].K_s


def test_every_attack_behaves():
    rng = random.Random(7)
    for name, fn in ATTACKS:
        for _ in range(5):
            o = fn(rng)
            expect = ("control" in name) or ("static" in name)
            assert o.accepted == expect, name


def test_pseudonym_keys_are_independent():
    w = make_world(k=20)
    pks = {p.cert.pk for p in w.drone.state.pool}; pids = {p.pid for p in w.drone.state.pool}
    assert len(pks) == len(pids) == 20


def test_ratchet_heals_after_passive_disclosure_and_forward_secrecy():
    w = make_world(); *_, dk, gk, _, _ = run_handshake(w)
    d, g = Session("D", dk), Session("G", gk)
    for _ in range(3): g.recv(d.send(b"x"))
    leaked = d.export_state()
    r = d.dh_request(); s = g.dh_respond(r); d.dh_finish(s)
    # attacker re-derives chain from leaked state: no longer matches
    from rla_iod.session import _step
    ck = leaked["ck_send"]
    for _ in range(2): _, ck = _step(ck)       # req frame + one more
    assert ck != d.ck_send
    g.recv(d.send(b"after")); d.recv(g.send(b"back"))
    # forward secrecy within session: old keys not derivable from current chain key (one-way hash)
    assert C.H(b"\x01", leaked["ck_send"]) != d.ck_send


def test_failed_frame_does_not_advance_state():
    w = make_world(); *_, dk, gk, _, _ = run_handshake(w)
    d, g = Session("D", dk), Session("G", gk); f = d.send(b"hello")
    bad = f[:5] + bytes([f[5] ^ 1]) + f[6:]
    try: g.recv(bad)
    except C.CryptoError: pass
    assert g.recv(f) == b"hello"


def test_closed_form_optimum_and_regret():
    p = Params(); L = optimal_span(288, 100, 3e-4)
    assert abs(L - 138.6) < 0.1
    grid = np.linspace(20, 800, 5000)
    assert abs(grid[np.argmin([objective(l, .12, 288, 100, 3e-4) for l in grid])] - L) < 1
    assert abs(regret(4) - 0.25) < 1e-9 and abs(regret(10) - 0.7393) < 1e-3


def test_operation_counts_match_manuscript():
    assert OPS["RLA-IoD drone, cold"].ms("Cortex-M4") == 1061
    assert OPS["One DH ratchet, either side"].ms("Cortex-M4") == 288
    assert persistent_storage_bytes(50) == (7450, 7604)


def test_vectorised_sim_equals_scalar_controller():
    p = Params(); w = S.make_world(4, 6000, 3)
    x = S.anomalies(w, p.eps, p.rho); d = S.disclosures(w, 1e-3, 5e-2)   # inflated hazard: exercise exposure path
    res = S.simulate(x, w.a, d, [S.ADAPTIVE], [100], p)
    for m in range(4):
        _, tot = S.trace_mission(w, m, p.with_(mu=100), 0, 1, d, x)
        assert abs(tot["cost_ms"] - res["cost_ms"][0, m]) < 1e-6
        assert tot["exposed"] == res["exposed"][0, m] and tot["n_hs"] == res["n_hs"][0, m]
