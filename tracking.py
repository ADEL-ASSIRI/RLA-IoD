"""Pseudonym-rotation privacy simulation (Section 6.7).

* 30-minute flights in a 2 km x 2 km area, 1 Hz broadcasts of (pseudonym, position)
  with 3 m (s.d.) GPS noise per axis.
* Mobility: random-waypoint at 5-15 m/s with heading noise. Formations: groups of g
  drones follow one leader; offsets settle from ~20 m to a few metres (tau = 60 s).
* Rotation policies: independent timers (random phase) and RLA-IoD coordination
  (GCS epochs, density gate, T_min / T_max).
* Tracker: passive; extrapolates the last 10 reports of each vanished identifier by a
  least-squares line to the time a new identifier appears and solves the assignment
  with the Hungarian algorithm (globally best matching, distance-gated).
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.optimize import linear_sum_assignment


@dataclass(frozen=True)
class Scenario:
    n_drones: int = 64
    g: int = 8                  # formation size (1 = solo)
    T: int = 1800               # flight length, seconds
    area: float = 2000.0        # side of the square, metres
    gps_sigma: float = 3.0      # metres per axis
    silent: int = 5             # silent period s (seconds)
    speed: tuple = (5.0, 15.0)
    heading_noise: float = 0.08  # rad per second
    offset_sigma: float = 3.5   # settled formation offset, metres per axis
    offset_init: float = 20.0   # initial formation offset, metres per axis
    offset_tau: float = 60.0
    offset_jitter: float = 0.5  # per-second independent jitter, metres


@dataclass(frozen=True)
class CoordParams:
    E_ep: int = 30
    T_min: int = 120
    T_max: int = 600
    R_mix: float = 60.0
    k_min: int | None = None    # None -> min(3, g)


# -----------------------------------------------------------------------------
# Motion
# -----------------------------------------------------------------------------
def simulate_motion(sc: Scenario, rng: np.random.Generator):
    """Returns (true[T,N,2], group[N])."""
    N, g, T = sc.n_drones, sc.g, sc.T
    G = int(np.ceil(N / g))
    group = np.minimum(np.arange(N) // g, G - 1)
    pos = rng.uniform(0, sc.area, (G, 2))
    wp = rng.uniform(0, sc.area, (G, 2))
    v = rng.uniform(*sc.speed, G)
    leaders = np.empty((T, G, 2))
    for t in range(T):
        leaders[t] = pos
        vec = wp - pos
        dist = np.linalg.norm(vec, axis=1)
        arrived = dist < v
        heading = np.arctan2(vec[:, 1], vec[:, 0]) + rng.normal(0, sc.heading_noise, G)
        pos = pos + v[:, None] * np.stack([np.cos(heading), np.sin(heading)], 1)
        pos = np.clip(pos, 0, sc.area)
        if arrived.any():
            k = int(arrived.sum())
            wp[arrived] = rng.uniform(0, sc.area, (k, 2))
            v[arrived] = rng.uniform(*sc.speed, k)
    final = rng.normal(0, sc.offset_sigma, (N, 2))
    init = rng.normal(0, sc.offset_init, (N, 2))
    tt = np.arange(T)[:, None, None]
    decay = np.exp(-tt / sc.offset_tau)
    offs = final[None] + (init - final)[None] * decay + rng.normal(0, sc.offset_jitter, (T, N, 2))
    true = leaders[:, group, :] + offs
    if g == 1:
        true = leaders[:, group, :]  # solo: no offsets
    return true, group


# -----------------------------------------------------------------------------
# Rotation policies -> list of rotation times per drone
# -----------------------------------------------------------------------------
def timer_rotations(sc: Scenario, period: int, rng: np.random.Generator) -> list[np.ndarray]:
    out = []
    for _ in range(sc.n_drones):
        phase = rng.uniform(0, period)
        ts = np.arange(phase, sc.T - sc.silent - 1, period)
        out.append(np.round(ts[ts >= 1]).astype(int))
    return out


def coordinated_rotations(sc: Scenario, true: np.ndarray, group: np.ndarray, cp: CoordParams,
                          rng: np.random.Generator) -> list[list[int]]:
    N = sc.n_drones
    k_min = cp.k_min if cp.k_min is not None else min(3, sc.g)
    # drones of one group are launched together -> same initial pseudonym age
    a0_group = rng.uniform(0, cp.T_min, group.max() + 1)
    last_rot = -a0_group[group]  # age(t) = t - last_rot
    rots: list[list[int]] = [[] for _ in range(N)]
    for t in range(cp.E_ep, sc.T - sc.silent - 1, cp.E_ep):
        age = t - last_rot
        elig = age >= cp.T_min
        p = true[t]
        d2 = ((p[:, None, :] - p[None, :, :]) ** 2).sum(-1)
        near = d2 <= cp.R_mix**2
        k_a = (near & elig[None, :]).sum(1)  # eligible drones within R_mix (incl. itself)
        rot = (age >= cp.T_max) | (elig & (k_a >= k_min))
        for i in np.flatnonzero(rot):
            rots[i].append(t)
        last_rot = np.where(rot, t, last_rot)
    return rots


# -----------------------------------------------------------------------------
# Tracker
# -----------------------------------------------------------------------------
def _fit_extrapolate(ts: np.ndarray, xy: np.ndarray, t_new: float) -> np.ndarray:
    if len(ts) < 2:
        return xy[-1]
    tc = ts - ts.mean()
    A = np.stack([np.ones_like(tc), tc], 1)
    coef, *_ = np.linalg.lstsq(A, xy, rcond=None)
    return coef[0] + coef[1] * (t_new - ts.mean())


def run_tracker(sc: Scenario, obs: np.ndarray, rotations: list, gate: float = 150.0) -> dict:
    """`rotations[i]` = sorted rotation times of drone i. Returns tracking metrics."""
    N, T, s = sc.n_drones, sc.T, sc.silent
    # ---- build identifier timelines ---------------------------------------
    ids = []  # dict(owner, first, last)
    owner_of_rot = []  # (drone, t_rot, old_id, new_id)
    for i in range(N):
        start = 0
        cur = len(ids)
        ids.append({"owner": i, "first": 0, "last": None})
        for tr in rotations[i]:
            ids[cur]["last"] = tr - 1
            new = len(ids)
            ids.append({"owner": i, "first": tr + s, "last": None})
            owner_of_rot.append((i, tr, cur, new))
            cur = new
        ids[cur]["last"] = T - 1
    first = np.array([d["first"] for d in ids])
    last = np.array([d["last"] for d in ids])
    owner = np.array([d["owner"] for d in ids])

    def reports(k):
        t = np.arange(first[k], last[k] + 1)
        return t, obs[t, owner[k]]

    # ---- link new identifiers to vanished ones ---------------------------
    link = {}  # new_id -> old_id
    taken = set()
    window = s + 3
    new_by_time: dict[int, list[int]] = {}
    for k in range(len(ids)):
        if first[k] > 0:
            new_by_time.setdefault(int(first[k]), []).append(k)
    for t_a in sorted(new_by_time):
        news = new_by_time[t_a]
        cand = [k for k in np.flatnonzero((last >= t_a - window) & (last <= t_a - 1)) if k not in taken]
        if not cand:
            continue
        pred = []
        for k in cand:
            tk, xk = reports(k)
            pred.append(_fit_extrapolate(tk[-10:].astype(float), xk[-10:], t_a))
        pred = np.array(pred)
        newpos = np.array([obs[t_a, owner[k]] for k in news])
        D = np.linalg.norm(pred[:, None, :] - newpos[None, :, :], axis=-1)
        cost = np.where(D <= gate, D, 1e4)
        ri, ci = linear_sum_assignment(cost)
        for r_, c_ in zip(ri, ci):
            if D[r_, c_] <= gate:
                link[news[c_]] = int(cand[r_])
                taken.add(int(cand[r_]))
    # ---- score ------------------------------------------------------------
    correct = 0
    first_mistake = np.full(N, float(T))
    for (i, tr, old, new) in owner_of_rot:
        if link.get(new) == old:
            correct += 1
        else:
            first_mistake[i] = min(first_mistake[i], first[new])
    n_rot = len(owner_of_rot)
    return {
        "link_success": correct / n_rot if n_rot else float("nan"),
        "tracked_fraction": float(np.mean(first_mistake / T)),
        "rotations": n_rot,
        "rot_per_drone_hour": n_rot / (N * T / 3600.0),
    }


# -----------------------------------------------------------------------------
# One experiment cell
# -----------------------------------------------------------------------------
POLICIES = ("Fixed 300 s, async", "Fixed 120 s, async", "RLA-IoD coordinated")


def run_cell(sc: Scenario, seed: int, cp: CoordParams = CoordParams(), policies=POLICIES) -> dict:
    """Same trajectories and GPS noise for every policy."""
    rng = np.random.default_rng(seed)
    true, group = simulate_motion(sc, rng)
    obs = true + rng.normal(0, sc.gps_sigma, true.shape)
    out = {}
    for pol in policies:
        prng = np.random.default_rng([seed, hash(pol) & 0xFFFF])
        if pol == "Fixed 300 s, async":
            rots = timer_rotations(sc, 300, prng)
        elif pol == "Fixed 120 s, async":
            rots = timer_rotations(sc, 120, prng)
        else:
            rots = coordinated_rotations(sc, true, group, cp, prng)
        out[pol] = run_tracker(sc, obs, rots)
    return out
