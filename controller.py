"""Risk estimator and span controller (Sections 4.4-4.5, Algorithm 1)."""
from __future__ import annotations

import math
from dataclasses import dataclass, replace

from .costmodel import C_DH_MS, C_HS_MS, CORTEX_M4_C_MSG_MS


@dataclass(frozen=True)
class Params:
    # estimator (Eq. 8)
    lam: float = 0.06       # EWMA smoothing
    eps: float = 0.002      # benign anomaly rate
    rho: float = 0.3        # extra anomaly rate during an attack
    # hazard model (Eq. 9) -- policy inputs, not measurements
    h0: float = 1e-4
    h1: float = 1e-2
    # objective (Eq. 10)
    mu: float = 100.0       # exposure price (ms of CPU per exposed message)
    c_dh: float = C_DH_MS
    c_msg: float = CORTEX_M4_C_MSG_MS
    c_hs: float = C_HS_MS
    # escalation / clamps
    theta: float = 0.15     # risk threshold for Level-3 re-handshake
    L_min: int = 4
    L_max: int = 3000
    W_max: int = 36_000     # maximum session age in messages (1 h at 10 Hz)

    def with_(self, **kw) -> "Params":
        return replace(self, **kw)


def optimal_span(c_dh: float, mu: float, h: float) -> float:
    """Eq. (11): L* = sqrt(2 c_dh / (mu h))."""
    return math.sqrt(2.0 * c_dh / (mu * h))


def objective(L: float, c_msg: float, c_dh: float, mu: float, h: float) -> float:
    """Eq. (10): J(L) = c_msg + c_dh/L + mu h L/2."""
    return c_msg + c_dh / L + mu * h * L / 2.0


def regret(kappa: float) -> float:
    """Relative extra variable cost when the hazard is mis-estimated by factor kappa."""
    return 0.5 * (math.sqrt(kappa) + 1.0 / math.sqrt(kappa)) - 1.0


class RiskController:
    """Per-session GCS logic, line-for-line Algorithm 1 (plus a re-arm hysteresis).

    The manuscript does not say how repeated Level-3 requests are avoided while the
    risk estimate stays above theta. We latch: one Level-3 request per episode, re-armed
    once r_hat falls below theta/2. This is the only addition to Algorithm 1.
    """

    def __init__(self, p: Params) -> None:
        self.p = p
        self.r = p.eps
        self.n = 0
        self.age = 0
        self.armed = True
        self.L = float(p.L_max)

    def a_hat(self) -> float:
        p = self.p
        return min(1.0, max(0.0, (self.r - p.eps) / p.rho))

    def on_frame(self, anomaly: bool) -> str:
        """Returns 'level3', 'level2' or 'none' for this frame."""
        p = self.p
        self.r += p.lam * (float(anomaly) - self.r)
        h = p.h0 + p.h1 * self.a_hat()
        self.L = min(max(optimal_span(p.c_dh, p.mu, h), p.L_min), p.L_max)
        self.n += 1
        self.age += 1
        if self.r < p.theta / 2:
            self.armed = True
        risk = self.armed and self.r >= p.theta
        if risk:
            self.armed = False
        if risk or self.age >= p.W_max:
            self.n = 0
            self.age = 0
            return "level3"
        if self.n >= self.L:
            self.n = 0
            return "level2"
        return "none"
