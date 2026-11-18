"""Section 6.6 (SIMULATION): Tables 10-13, the square-root law, and Figure 7/8 data."""
import numpy as np
from common import parser, write_table, write_json
from rla_iod.controller import Params, optimal_span, objective
from rla_iod import spansim as S

MUS = [3, 10, 30, 100, 300, 1000, 3000]

def main():
    a = parser(__doc__).parse_args()
    M, T = (20, 20000) if a.quick else (150, 20000)
    p = Params()
    w = S.make_world(M, T, a.seed)
    x = S.anomalies(w, p.eps, p.rho); d = S.disclosures(w, p.h0, p.h1)
    print(f"{M} missions x {T} msgs; attack fraction {w.a.mean():.4f}; disclosures/1000 msgs {1000*d.mean():.3f}")

    # ---- main run: fixed grid + timeout + adaptive + oracle on the same worlds
    grid = np.unique(np.concatenate([np.round(np.geomspace(3, 3000, 60)).astype(int), [3, 50, 500, 3000]]))
    kind = [S.FIXED] * len(grid) + [S.TIMEOUT] + [S.ADAPTIVE] * len(MUS) + [S.ORACLE] * len(MUS)
    par = list(grid) + [3000] + MUS + MUS
    res = S.simulate(x, w.a, d, kind, par, p)
    nG = len(grid)
    summ = [S.summarise(res, c) for c in range(len(kind))]
    fr = S.Frontier(grid, [s["cost"] for s in summ[:nG]], [s["exposure"] for s in summ[:nG]])
    t_out = summ[nG]; ad = summ[nG + 1: nG + 1 + len(MUS)]; orc = summ[nG + 1 + len(MUS):]
    rows10 = []
    for i, mu in enumerate(MUS):
        fx = fr.at_cost(ad[i]["cost"])
        rows10.append({"mu": mu, "Cost_ms_per_msg": ad[i]["cost"], "Exposure_per_1000": ad[i]["exposure"],
                       "Exposure_CI95": ad[i]["exposure_ci"], "FixedL_exposure_equal_cost": fx,
                       "Reduction_pct": 100 * (1 - ad[i]["exposure"] / fx),
                       "Oracle_reduction_pct": 100 * (1 - orc[i]["exposure"] / fr.at_cost(orc[i]["cost"]))})
    write_table("table10_adaptive_vs_fixed", rows10, "Table 10. Adaptive controller vs fixed-span frontier at equal cost")

    # ---- Table 13: one hour at 10 Hz
    def hour(name, s):
        cpu = s["cost"] * 36000 / 1000
        return {"Policy": name, "CPU_s_per_h": cpu, "Duty_pct": s["cost"] * 10 / 10, "Energy_J_per_h": cpu * 0.033,
                "Exposed_per_1000": s["exposure"]}
    idx = {int(L): i for i, L in enumerate(grid)}
    rows13 = [hour("Re-handshake every 300 s (static timeout)", t_out)]
    rows13 += [hour(f"Fixed DH-ratchet span L = {L}", summ[idx[L]]) for L in (3, 50, 500)]
    rows13 += [hour(f"RLA-IoD adaptive (mu = {mu})", ad[MUS.index(mu)]) for mu in (30, 100, 300)]
    write_table("table13_one_hour", rows13, "Table 13. One hour at 10 msg/s (Cortex-M4 costs, 33 mW core)")

    # ---- Figure 7a data
    write_json("span_main", {"fixed": {"L": grid, "cost": [s["cost"] for s in summ[:nG]], "exposure": [s["exposure"] for s in summ[:nG]],
              "exposure_ci": [s["exposure_ci"] for s in summ[:nG]]}, "timeout": t_out,
              "adaptive": {"mu": MUS, "points": ad}, "oracle": {"mu": MUS, "points": orc}})

    # ---- Tables 11 and 12: detectability sweep
    RHOS = [0.005, 0.01, 0.02, 0.05, 0.15, 0.3, 0.6]
    sub_mu = [10, 30, 100, 300]
    rows11 = []
    for rho in RHOS:
        xr = S.anomalies(w, p.eps, rho)
        r = S.simulate(xr, w.a, d, [S.ADAPTIVE] * len(sub_mu), sub_mu, p, rho=rho)
        row = {"rho": rho}
        for j, mu in enumerate(sub_mu):
            s = S.summarise(r, j)
            row[f"mu={mu}"] = 100 * (1 - s["exposure"] / fr.at_cost(s["cost"]))
        rows11.append(row)
    write_table("table11_signal_strength", rows11, "Table 11. Exposure reduction at equal cost (%) vs detectability rho")
    rows12 = []
    for rho in (0.1, 0.3, 0.6):
        xr = S.anomalies(w, p.eps, rho)
        for th in (0.10, 0.15, 0.25):
            st = S.detection_stats(w.a, xr, p.lam, p.eps, th)
            rows12.append({"rho": rho, "theta": th, "Episodes_detected_pct": 100 * st["detected_frac"],
                           "Median_delay_msgs": st["median_delay"], "False_alarms_per_1e4": st["false_alarms_per_1e4"],
                           "Episodes": st["episodes"]})
    write_table("table12_detection", rows12, "Table 12. EWMA detection of attack episodes (>= 30 msgs)")

    # ---- Square-root law (constant hazard) + objective curve for Fig 7b
    mu0, h0c = 100.0, 3e-4
    Msl = 40 if a.quick else 400
    rng = np.random.default_rng(a.seed + 1)
    dc = rng.random((Msl, T), dtype=np.float32) < h0c
    Ls = np.unique(np.round(np.geomspace(30, 600, 45)).astype(int))
    r2 = S.simulate(np.zeros((Msl, T), bool), np.zeros((Msl, T), bool), dc, [S.FIXED] * len(Ls), Ls, p)
    J = p.c_msg + p.c_dh / Ls + mu0 * (r2["exposed"].mean(1) / T)
    Lstar = optimal_span(p.c_dh, mu0, h0c)
    emp = int(Ls[np.argmin(J)])
    Lc = np.geomspace(30, 600, 100)
    write_json("sqrt_law", {"L": Ls, "J_empirical": J, "L_curve": Lc, "J_closed": [objective(l, p.c_msg, p.c_dh, mu0, h0c) for l in Lc],
                            "L_star": Lstar, "L_emp": emp, "mu": mu0, "h": h0c,
                            "J_at_emp_vs_opt_pct": 100 * (objective(emp, p.c_msg, p.c_dh, mu0, h0c) / objective(Lstar, p.c_msg, p.c_dh, mu0, h0c) - 1)})
    print(f"sqrt law: L* = {Lstar:.1f}, empirical minimiser = {emp}")

    # ---- Fig 8: one mission segment at mu = 100 (scalar Algorithm-1 controller)
    m_t = next(m for m in range(M) if w.a[m].any() and d[m][w.a[m]].any())
    s0 = int(np.flatnonzero(w.a[m_t])[0])
    tr, tot = S.trace_mission(w, m_t, p.with_(mu=100), max(0, s0 - 150), 450, d, x)
    write_json("trace_fig8", {**tr, "start": max(0, s0 - 150)})
    for r in rows10: print({k: round(v, 3) for k, v in r.items()})
    for r in rows13: print(r)

if __name__ == "__main__":
    main()
