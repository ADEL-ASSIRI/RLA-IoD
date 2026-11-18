# RLA-IoD: code and data

Reference implementation, adversary harness and simulations for

> A. S. Assiri, **RLA-IoD: Risk-Adaptive Authentication and Coordinated Pseudonym Management for the Internet of Drones**.

The article has no external dataset. Every number in it is produced by the code in this repository, so *the code and its generated outputs are the dataset*. Everything runs on a laptop CPU in about 5 minutes.

## Quick start

```bash
pip install -r requirements.txt
pytest -q tests                          # 10 tests, ~2 s
python experiments/run_all.py --quick    # smoke test, ~1 min
python experiments/run_all.py            # full run (150 missions, 300 trials, 30 tracker seeds), ~5 min
```

Outputs are written to `results/` (`*.csv` and `*.md` tables, `*.json` figure data, `figures/*.png`). Seeds are fixed (`--seed`, default 2026), so the simulations are repeatable. The timing results in Tables 5, 6 and 9 depend on your machine.

## What produces what

| Manuscript item | Script | Kind of evidence |
|---|---|---|
| Table 3 (16 attacks + control, 300 trials) | `experiments/run_attacks.py` | executed on real byte strings |
| Tables 5, 6, 8, 9; Figs 4a, 5, 6 | `experiments/bench.py` | **measured** on the host (OpenSSL via `cryptography`) |
| Table 7; Fig 4b | `experiments/projections.py` | **projected**: exact operation counts × published AVR / Cortex-M4 / RPi timings (`rla_iod/costmodel.py`) |
| Tables 10-13; Figs 7, 8 | `experiments/run_span.py` | **simulated** (risk-driven span control) |
| Table 14; Figs 9, 10 | `experiments/run_tracking.py` | **simulated** (pseudonym rotation vs. a Hungarian-matching tracker) |
| Figs 4-10 | `experiments/make_figures.py` | from `results/*.json` |

Figures 1-3 are diagrams and are not generated here.

## Layout

```
rla_iod/
  crypto.py      P-256 ECDH/ECDSA, HKDF, HMAC wrappers (fixed-length wire encodings)
  pki.py         trusted authority, certificates, pseudonym pools (Eq. 1)
  protocol.py    three-message handshake M1-M3, stateless cookie, PSK and static-ECDH baselines
  session.py     hash ratchet (Level 1) and authenticated DH ratchet (Level 2)
  controller.py  EWMA risk estimator, optimal span (Eqs 8-11), Algorithm 1
  spansim.py     vectorised Monte-Carlo span simulation, detector statistics
  tracking.py    mobility, rotation policies, tracking adversary
  attacks.py     the adversary harness
  costmodel.py   operation counts and hardware projections
experiments/     one script per group of tables/figures, plus run_all.py
tests/           unit tests (protocol, session, attacks, closed forms, sim/scalar equivalence)
results/         generated tables, figure data and figures from the full run
```

## Implementation notes and choices the manuscript does not fix

These are stated so a reader can judge them:

* **Wire format.** M1 = 61 B, M2 = 246 B (137 B with a cached GCS certificate), M3 = 197 B, so 504 B cold and 395 B cached. Certificates are 117 B; a cached certificate saves 109 B.
* **Session layer.** Each direction runs its own hash chain seeded from `CK`. The DH-ratchet request/response is exchanged with no data frames in flight, and delivery is in order (both stated as limitations in the paper). Frames are authenticated, not encrypted, as in Eq. (6).
* **Controller.** Smoothing λ = 0.06, θ = 0.15, L_min = 4, L_max = 3000, W_max = 1 h; these values are my choices. Algorithm 1 does not say how repeated Level-3 requests are avoided while r̂ ≥ θ. The code latches one request per episode and re-arms once r̂ < θ/2.
* **Charging Level-3 handshakes.** Each risk-triggered handshake is charged its full 1,061 ms. This matters at low μ: with the handshake charged, the adaptive controller does *not* beat the fixed-span frontier at μ ≤ 10 (see below).
* **Tracking.** Formation offsets settle to σ = 3.5 m per axis (the paper says "a few metres"); the tracker's gate is 150 m; GPS noise is 3 m; formation members share an initial pseudonym age, and the epoch grid is perfectly synchronised.
* Static-ECDH baseline: 301 B on the wire, 4 drone public-key operations. PSK baseline: 104 B.

## Reproduction status against the manuscript

`results/` holds the output of the full run. Where it differs from the manuscript, **the repository output is the reference.** The comparison is written up in `REPRODUCIBILITY.md`.

## Licence and citation

Code: MIT (`LICENSE`). Generated data in `results/`: CC-BY 4.0 (`LICENSE-DATA.md`). See `CITATION.cff`.
