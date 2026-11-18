"""Operation counts and projections onto constrained hardware (Section 6.3).

Per-operation timings are *published* benchmark values, not measurements of this
code (see README, "measured vs projected vs simulated"):
  * AVR  : micro-ecc, ATmega256RFR2 @16 MHz        (Puch et al., EuroS&P 2026, ref [32])
  * M4   : p256-m, STM32F411 @100 MHz              (Mbed TLS contributors, ref [33])
  * RPi  : micro-ecc, Raspberry Pi B+              (ref [32])
All values are in milliseconds for P-256.
"""
from __future__ import annotations

from dataclasses import dataclass

# (scalar multiplication, ECDSA sign, ECDSA verify) in ms
PLATFORMS: dict[str, tuple[float, float, float]] = {
    "AVR": (2220.0, 2386.0, 2650.0),
    "Cortex-M4": (144.0, 155.0, 309.0),
    "RPi B+": (7.9, 8.6, 9.2),
}
CORE_POWER_MW = 33.0  # STM32F411: 100 uA/MHz * 100 MHz * 3.3 V (core only, no radio/flash)
CORTEX_M4_C_MSG_MS = 0.12  # framed message: software SHA-256 at ~30 cycles/byte (assumption)


@dataclass(frozen=True)
class Ops:
    mul: int = 0
    sign: int = 0
    verify: int = 0

    def pk_ops(self) -> int:
        return self.mul + self.sign + self.verify

    def ms(self, platform: str) -> float:
        m, s, v = PLATFORMS[platform]
        return self.mul * m + self.sign * s + self.verify * v


# Exact public-key operation counts, read off the protocol description.
OPS = {
    # Drone: X=xG, Z=xY, verify Cert_G, verify sigma_G, sign sigma_D
    "RLA-IoD drone, cold": Ops(mul=2, sign=1, verify=2),
    "RLA-IoD drone, cert cached": Ops(mul=2, sign=1, verify=1),
    "  + precomputed ephemeral key": Ops(mul=1, sign=1, verify=1),
    # GCS: Y=yG, Z=yX, sign sigma_G, verify Cert_j, verify sigma_D
    "RLA-IoD GCS side": Ops(mul=2, sign=1, verify=2),
    # Static design (drone): ECDH(sk_i, pk_G), sign, verify Cert_G, verify sigma_G
    "Static-ECDH design, drone": Ops(mul=1, sign=1, verify=2),
    "One DH ratchet, either side": Ops(mul=2),
}

C_DH_MS = OPS["One DH ratchet, either side"].ms("Cortex-M4")  # 288 ms
C_HS_MS = OPS["RLA-IoD drone, cold"].ms("Cortex-M4")  # 1061 ms


def energy_mj(ms: float) -> float:
    return ms * CORE_POWER_MW / 1000.0


def projection_table() -> list[dict]:
    rows = []
    for name, ops in OPS.items():
        t = {p: ops.ms(p) for p in PLATFORMS}
        rows.append(
            {
                "component": name.strip(),
                "AVR_ms": t["AVR"],
                "CortexM4_ms": t["Cortex-M4"],
                "CortexM4_mJ": energy_mj(t["Cortex-M4"]),
                "RPiB+_ms": t["RPi B+"],
                "pk_ops": ops.pk_ops(),
            }
        )
    return rows
