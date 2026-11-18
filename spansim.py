"""Monte-Carlo simulation of risk-driven span control (Section 6.6).

World model (per mission of T messages):
  * attack episodes start with prob 1/4000 per calm message and last 150 messages
    on average (geometric);
  * the GCS sees an anomaly with prob eps (calm) or eps+rho (attack);
  * a state disclosure happens with prob h0 (calm) or h0+h1 (attack) per message;
  * a disclosure exposes every message until the next renewal (DH ratchet or handshake).

All policies are run on the *same* random worlds (common random numbers) and are
vectorised over (policy x mission) with numpy, looping only over message index.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.signal import lfilter

from .controller import Params, RiskController

FIXED, TIMEOUT, ADAPTIVE, ORACLE = 0, 1, 2, 3


@dataclass
class World:
    a: np.ndarray      # (M,T) bool attack state
    u_anom: np.ndarray # (M,T) float32 uniforms driving anomalies
    u_disc: np.ndarray # (M,T) float32 uniforms driving disclosures

    @property
    def shape(self):
        return self.a.shape


def make_world(M: int, T: int, seed: int, p_start: float = 1 / 4000, mean_len: float = 150.0) -> World:
    rng = np.random.default_rng(seed)
    a = np.zeros((M, T), dtype=bool)
    cur = np.zeros(M, dtype=bool)
    r_start = rng.random((M, T), dtype=np.float32)
    r_end = rng.random((M, T), dtype=np.float32)
    p_end = 1.0 / mean_len
    for t in range(T):
        cur = np.where(cur, r_end[:, t] >= p_end, r_start[:, t] < p_start)
        a[:, t] = cur
    return World(a, rng.random((M, T), dtype=np.float32), rng.random((M, T), dtype=np.float32))


def anomalies(w: World, eps: float, rho: float) -> np.ndarray:
    return w.u_anom < (eps + rho * w.a).astype(np.float32)


def disclosures(w: World, h0: float, h1: float) -> np.ndarray:
    return w.u_disc < (h0 + h1 * w.a).astype(np.float32)


def simulate(x, a, d, kind, par, p: Params, rho: float | None = None):
    """Run policies in parallel.

    kind[c] in {FIXED, TIMEOUT, ADAPTIVE, ORACLE}
    par[c]  = span L (FIXED), period in messages (TIMEOUT) or exposure price mu (ADAPTIVE/ORACLE)
    Returns dict of (C,M) arrays: cost_ms, exposed, n_dh, n_hs.
    """
    kind = np.asarray(kind)
    par = np.asarray(par, dtype=np.float64)
    C = len(kind)
    M, T = x.shape
    rho = p.rho if rho is None else rho
    fixed, tout = kind == FIXED, kind == TIMEOUT
    smart = kind >= ADAPTIVE
    orac = (kind == ORACLE)[:, None]
    smart_c = smart[:, None]
    tout_c = tout[:, None]
    Lfix = par[:, None]
    mu = np.where(smart, par, 1.0)[:, None]

    r = np.full((C, M), p.eps)
    n = np.zeros((C, M), dtype=np.int64)
    age = np.zeros((C, M), dtype=np.int64)
    armed = np.ones((C, M), dtype=bool)
    open_d = np.zeros((C, M), dtype=np.int64)
    cost = np.zeros((C, M))
    exposed = np.zeros((C, M))
    n_dh = np.zeros((C, M), dtype=np.int64)
    n_hs = np.zeros((C, M), dtype=np.int64)
    fixedlike = (fixed | tout)[:, None]

    for t in range(T):
        xt, at, dt = x[:, t][None, :], a[:, t][None, :], d[:, t][None, :]
        exposed += open_d            # message t is sent while the state is known to the adversary
        open_d += dt                 # a disclosure during message t exposes what follows
        r += p.lam * (xt - r)
        a_hat = np.where(orac, at, np.clip((r - p.eps) / rho, 0.0, 1.0))
        h = p.h0 + p.h1 * a_hat
        L = np.clip(np.sqrt(2.0 * p.c_dh / (mu * h)), p.L_min, p.L_max)
        L = np.where(fixedlike, Lfix, L)
        n += 1
        age += 1
        sig = np.where(orac, at, r >= p.theta)
        rearm = np.where(orac, ~at, r < p.theta / 2)
        armed |= rearm & smart_c
        risk = smart_c & armed & sig
        armed &= ~risk
        lvl3 = risk | (smart_c & (age >= p.W_max)) | (tout_c & (n >= Lfix))
        lvl2 = ~lvl3 & ~tout_c & (n >= L)
        cost += p.c_msg + lvl2 * p.c_dh + lvl3 * p.c_hs
        renew = lvl2 | lvl3
        n[renew] = 0
        open_d[renew] = 0
        age[lvl3] = 0
        n_dh += lvl2
        n_hs += lvl3
    return {"cost_ms": cost, "exposed": exposed, "n_dh": n_dh, "n_hs": n_hs, "T": T}


def summarise(res: dict, c: int) -> dict:
    """Mean and 95% CI across missions for policy index c (per message / per 1000 messages)."""
    T, M = res["T"], res["cost_ms"].shape[1]
    cost = res["cost_ms"][c] / T
    expo = 1000.0 * res["exposed"][c] / T
    ci = lambda v: 1.96 * v.std(ddof=1) / np.sqrt(len(v))  # noqa: E731
    return {"cost": cost.mean(), "cost_ci": ci(cost), "exposure": expo.mean(), "exposure_ci": ci(expo),
            "dh_per_msg": res["n_dh"][c].sum() / (M * T), "hs_per_msg": res["n_hs"][c].sum() / (M * T)}


class Frontier:
    """Fixed-span (cost, exposure) frontier; interpolate exposure at a given cost."""

    def __init__(self, L_grid, cost, exposure):
        order = np.argsort(L_grid)
        self.L = np.asarray(L_grid, float)[order]
        self.cost = np.asarray(cost, float)[order]
        # exposure must be non-decreasing in L; remove sampling wiggles
        self.expo = np.maximum.accumulate(np.asarray(exposure, float)[order])

    def at_cost(self, c: float) -> float:
        # cost falls with L, exposure rises with L -> interpolate in log-log space
        o = np.argsort(self.cost)
        return float(np.exp(np.interp(np.log(c), np.log(self.cost[o]), np.log(self.expo[o]))))


def fixed_frontier(world: World, p: Params, L_grid=None, d=None):
    L_grid = L_grid if L_grid is not None else np.unique(np.round(np.geomspace(3, 3000, 60)).astype(int))
    d = d if d is not None else disclosures(world, p.h0, p.h1)
    x = anomalies(world, p.eps, p.rho)
    res = simulate(x, world.a, d, np.full(len(L_grid), FIXED), L_grid, p)
    T = res["T"]
    cost = res["cost_ms"].mean(1) / T
    expo = 1000.0 * res["exposed"].mean(1) / T
    return Frontier(L_grid, cost, expo), res, L_grid


# ----------------------------------------------------------------------------
# Detector statistics (Table 12)
# ----------------------------------------------------------------------------
def ewma_series(x: np.ndarray, lam: float, eps: float) -> np.ndarray:
    """r_t = (1-lam) r_{t-1} + lam x_t with r_{-1} = eps, along the last axis."""
    zi = np.full(x.shape[:-1] + (1,), (1 - lam) * eps)
    out, _ = lfilter([lam], [1.0, -(1 - lam)], x.astype(np.float64), axis=-1, zi=zi)
    return out


def detection_stats(a: np.ndarray, x: np.ndarray, lam: float, eps: float, theta: float,
                    min_len: int = 30, calm_gap: int = 200) -> dict:
    r = ewma_series(x, lam, eps)
    M, T = a.shape
    detected = delays = 0
    delay_list, n_ep = [], 0
    calm_len = 0
    false_alarms = 0
    for m in range(M):
        am = a[m]
        edges = np.flatnonzero(np.diff(np.concatenate(([0], am.astype(np.int8), [0]))))
        starts, ends = edges[0::2], edges[1::2]  # [start, end)
        over = r[m] >= theta
        for s, e in zip(starts, ends):
            if e - s < min_len:
                continue
            n_ep += 1
            hit = np.flatnonzero(over[s:e])
            if hit.size:
                detected += 1
                delay_list.append(hit[0] + 1)
        # calm region: not attack and >= calm_gap messages after the last episode end
        idx = np.where(am, np.arange(T), -10**9)
        last_end = np.maximum.accumulate(idx)
        calm = (~am) & (np.arange(T) - last_end > calm_gap)
        rising = over & ~np.concatenate(([False], over[:-1]))
        false_alarms += int(np.count_nonzero(rising & calm))
        calm_len += int(calm.sum())
    return {"episodes": n_ep, "detected_frac": detected / max(n_ep, 1),
            "median_delay": float(np.median(delay_list)) if delay_list else float("nan"),
            "false_alarms_per_1e4": 1e4 * false_alarms / max(calm_len, 1)}


# ----------------------------------------------------------------------------
# One mission with the scalar Algorithm-1 controller (for Fig. 8 and for testing)
# ----------------------------------------------------------------------------
def trace_mission(world: World, m: int, p: Params, start: int, length: int, d: np.ndarray, x: np.ndarray):
    ctl = RiskController(p)
    T = world.shape[1]
    rec = {k: [] for k in ("r", "L", "a", "level2", "level3", "disc")}
    cost = 0.0
    exposed = 0
    open_d = 0
    n_dh = n_hs = 0
    for t in range(T):
        exposed += open_d
        open_d += int(d[m, t])
        act = ctl.on_frame(bool(x[m, t]))
        cost += p.c_msg + (p.c_dh if act == "level2" else 0) + (p.c_hs if act == "level3" else 0)
        if act != "none":
            open_d = 0
            n_dh += act == "level2"
            n_hs += act == "level3"
        if start <= t < start + length:
            rec["r"].append(ctl.r); rec["L"].append(ctl.L); rec["a"].append(bool(world.a[m, t]))
            rec["level2"].append(act == "level2"); rec["level3"].append(act == "level3")
            rec["disc"].append(bool(d[m, t]))
    return {k: np.array(v) for k, v in rec.items()}, {"cost_ms": cost, "exposed": exposed, "n_dh": n_dh, "n_hs": n_hs}
