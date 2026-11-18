"""Tables 5, 6, 8, 9 and the data behind Figures 4a, 5, 6 (host MEASUREMENTS)."""
import os, time
import numpy as np
from common import parser, write_table, write_json
from rla_iod import crypto as C
from rla_iod.pki import persistent_storage_bytes, DroneState, TrustedAuthority
from rla_iod.protocol import GCS, Drone, PSKScheme, StaticECDH, M1_LEN, M3_LEN
from rla_iod.testbed import make_world, Clock
from rla_iod.costmodel import PLATFORMS, OPS


def timeit(fn, n):
    ts = np.empty(n)
    for i in range(n):
        t0 = time.perf_counter_ns(); fn(); ts[i] = (time.perf_counter_ns() - t0) / 1e6
    return ts

mci = lambda ts: (float(ts.mean()), float(1.96 * ts.std(ddof=1) / np.sqrt(len(ts))))  # noqa: E731


def main():
    a = parser(__doc__).parse_args()
    n, nh = (200, 1000) if a.quick else (1000, 5000)
    # ---------------- Table 5: primitives on the host
    k1, k2 = C.gen_keypair(), C.gen_keypair()
    pub2, pub1 = k2.public_key(), k1.public_key()
    msg = os.urandom(64); sig = C.sign(k1, msg); b32 = os.urandom(32)
    for _ in range(200): C.ecdh(k1, pub2)  # warm-up
    prim = {
        "ECC scalar multiplication (ECDH)": mci(timeit(lambda: C.ecdh(k1, pub2), n)),
        "ECDSA sign": mci(timeit(lambda: C.sign(k1, msg), n)),
        "ECDSA verify": mci(timeit(lambda: C.verify(pub1, sig, msg), n)),
        "HKDF (32 B)": mci(timeit(lambda: C.hkdf(b32, b32, b"info"), nh)),
        "HMAC-SHA-256": mci(timeit(lambda: C.hmac_sha256(b32, msg), nh)),
        "SHA-256": mci(timeit(lambda: C.H(msg), nh)),
    }
    pk_key = {"ECC scalar multiplication (ECDH)": 0, "ECDSA sign": 1, "ECDSA verify": 2}
    rows = []
    for k, (m, ci) in prim.items():
        r = {"Operation": k, "Host_ms": m, "Host_CI95": ci}
        for p, v in PLATFORMS.items():
            r[p + "_ms"] = v[pk_key[k]] if k in pk_key else "negligible"
        rows.append(r)
    write_table("table5_primitives", rows, "Table 5. Per-operation cost (host measured; others published, see costmodel.py)")

    # ---------------- Table 6: whole handshakes, per side
    N = n
    def per_side(setup, drone_fn, gcs_fn):
        d, g = [], []
        for _ in range(N):
            ctx = setup()
            t0 = time.perf_counter_ns(); r1 = drone_fn(ctx, None); t1 = time.perf_counter_ns()
            r2 = gcs_fn(ctx, r1); t2 = time.perf_counter_ns()
            r3 = drone_fn(ctx, r2); t3 = time.perf_counter_ns()
            gcs_fn(ctx, r3, final=True); t4 = time.perf_counter_ns()
            d.append((t1 - t0 + t3 - t2) / 1e6); g.append((t2 - t1 + t4 - t3) / 1e6)
        return mci(np.array(d)), mci(np.array(g))

    # PSK
    def psk_setup(): return PSKScheme(os.urandom(32), os.urandom(16), os.urandom(16))
    def psk_d(s, x): return s.drone_start() if x is None else s.drone_finish(x)
    def psk_g(s, x, final=False):
        if final: return None
        m2, _ = s.gcs_handle(x); return m2
    psk_cpu = per_side(psk_setup, psk_d, psk_g)
    w0 = make_world(); did = os.urandom(16); dsk = C.gen_keypair()
    def st_setup(): return StaticECDH(did, dsk, w0.gcs.creds, w0.ta.pk, {did: C.pub_bytes(dsk)}, clock=w0.clock)
    def st_d(s, x): return s.drone_start() if x is None else s.drone_finish(x)
    def st_g(s, x, final=False):
        if final: return None
        m2, _ = s.gcs_handle(x); return m2
    st_cpu = per_side(st_setup, st_d, st_g)

    def rla(cached):
        w = make_world(k=4, cached=cached)
        def setup():
            w.drone.state.cached_gcs_cert = w.gcs.creds.cert if cached else None
            return {"p": None}
        def dfn(ctx, x):
            if x is None: return w.drone.start()
            m3, _ = w.drone.handle_m2(x); return m3
        def gfn(ctx, x, final=False):
            if final: w.gcs.handle_m3(x, ctx["p"]); return None
            m2, ctx["p"] = w.gcs.handle_m1(x); return m2
        cpu = per_side(setup, dfn, gfn)
        setup(); m1 = w.drone.start(); m2, p = w.gcs.handle_m1(m1); m3, _ = w.drone.handle_m2(m2)
        return cpu, (len(m1), len(m2), len(m3))
    rla_c, sz_c = rla(True); rla_x, sz_x = rla(False)
    t6 = [
        ("PSK-HMAC", psk_cpu, 104 * 8, 0, "no", "no"),
        ("Static-ECDH design", st_cpu, 301 * 8, 4, "no", "no"),
        ("RLA-IoD, GCS cert cached", rla_c, sum(sz_c) * 8, OPS["RLA-IoD drone, cert cached"].pk_ops(), "yes", "yes"),
        ("RLA-IoD, cold", rla_x, sum(sz_x) * 8, OPS["RLA-IoD drone, cold"].pk_ops(), "yes", "yes"),
    ]
    rows6 = [{"Scheme": s, "Drone_CPU_ms": c[0][0], "GCS_CPU_ms": c[1][0], "Wire_bits": w, "Drone_PK_ops": o,
              "Forward_secrecy": f, "Identity_hidden_from_GCS": i} for s, c, w, o, f, i in t6]
    write_table("table6_auth_comparison", rows6, "Table 6. Authentication comparison (host measured)")

    # ---------------- Table 8: storage
    rows8 = []
    for k in (10, 25, 50, 100):
        pool, tot = persistent_storage_bytes(k)
        rows8.append({"Pool_size_k": k, "Pool_bytes": pool, "Persistent_total_bytes": tot, "Bits": tot * 8})
    write_table("table8_storage", rows8, "Table 8. Persistent storage on the drone")

    # ---------------- Table 9: flood cost at the GCS
    w = make_world(cached=False)
    import struct
    def forged():
        X = C.pub_bytes(C.gen_keypair())
        return X + struct.pack(">I", w.clock()) + os.urandom(16) + b"\0" * 8
    pre = [forged() for _ in range(n)]
    def mk(fn):
        it = iter(pre)
        def run():
            try: fn(next(it))
            except C.CryptoError: pass
        return run
    w.gcs.require_cookie = False
    fresh = mci(timeit(mk(lambda m: w.gcs.handle_m1(m)), n))
    stale_msgs = [m[:33] + struct.pack(">I", w.clock() - 60) + m[37:] for m in pre]
    it2 = iter(stale_msgs)
    def stale_run():
        try: w.gcs.handle_m1(next(it2))
        except C.CryptoError: pass
    stale = mci(timeit(stale_run, n))
    w.gcs.require_cookie = True
    cookie = mci(timeit(mk(lambda m: w.gcs.handle_m1(m)), n))
    legit = rla_x[1][0]
    rows9 = [
        {"Forged_or_stale_M1": "Fresh forgery, no cookie", "GCS_cost_ms": fresh[0], "Relative": 1.0},
        {"Forged_or_stale_M1": "Stale replay (timestamp check)", "GCS_cost_ms": stale[0], "Relative": stale[0] / fresh[0]},
        {"Forged_or_stale_M1": "Fresh forgery, cookie required", "GCS_cost_ms": cookie[0], "Relative": cookie[0] / fresh[0]},
        {"Forged_or_stale_M1": "Legitimate Auth (reference)", "GCS_cost_ms": legit, "Relative": legit / fresh[0]},
    ]
    write_table("table9_flood", rows9, "Table 9. Cost of one forged or stale M1 at the GCS (host)")
    rates = np.linspace(0, 6000, 61)
    cap = lambda c: np.maximum(0.0, 1 - rates * c / 1000) / (legit / 1000)  # noqa: E731
    write_json("bench", {
        "primitives": {k: {"mean": m, "ci95": ci} for k, (m, ci) in prim.items()},
        "handshake_cpu": {r["Scheme"]: {"drone": r["Drone_CPU_ms"], "gcs": r["GCS_CPU_ms"]} for r in rows6},
        "msg_sizes_cached": sz_c, "msg_sizes_cold": sz_x,
        "flood": {"rates": rates, "no_cookie": cap(fresh[0]), "cookie": cap(cookie[0]), "idle": 1000 / legit,
                  "at_5000": {"no_cookie": float(cap(fresh[0])[50]), "cookie": float(cap(cookie[0])[50])}},
    })
    for r in rows6: print(r)
    print(rows9)

if __name__ == "__main__":
    main()
