"""Section 6.7 (SIMULATION): Table 14, Figure 9 and Figure 10 data."""
from multiprocessing import Pool
import numpy as np
from common import parser, write_table, write_json
from rla_iod.tracking import Scenario, CoordParams, POLICIES, run_cell

def _job(args):
    sc, seed, cp = args
    return run_cell(sc, seed, cp)

def sweep(cells, seeds, pool):
    """cells: list of (label, Scenario, CoordParams). Returns {label: {policy: metric: mean}}."""
    jobs = [(sc, s, cp) for _, sc, cp in cells for s in seeds]
    out = pool.map(_job, jobs, chunksize=1)
    res = {}
    for ci, (label, _, _) in enumerate(cells):
        rs = out[ci * len(seeds):(ci + 1) * len(seeds)]
        res[label] = {p: {m: float(np.mean([r[p][m] for r in rs])) for m in rs[0][p]} |
                         {"link_ci95": float(1.96 * np.std([r[p]["link_success"] for r in rs], ddof=1) / np.sqrt(len(rs)))}
                      for p in POLICIES}
    return res

def main():
    a = parser(__doc__).parse_args()
    nseed = 3 if a.quick else 30
    seeds = [a.seed + i for i in range(nseed)]
    cp = CoordParams()
    with Pool(2) as pool:
        G = [1, 2, 4, 8, 16]
        tabA = sweep([(g, Scenario(g=g), cp) for g in G], seeds, pool)
        S = [0, 2, 5, 10, 20, 40]
        tabB = sweep([(s, Scenario(g=8, silent=s), cp) for s in S], seeds, pool)
        Ns = [10, 25, 50, 100, 200, 400]
        tabC = sweep([(n, Scenario(n_drones=n, g=1), CoordParams(k_min=3)) for n in Ns], seeds[:max(2, nseed // 3)], pool)
    rows = []
    for p in POLICIES:
        r = {"Policy": p}
        for g in G:
            r[f"g={g}"] = f"{tabA[g][p]['link_success']:.2f} ({tabA[g][p]['tracked_fraction']:.2f})"
        r["Rotations_per_drone_hour_g8"] = tabA[8][p]["rot_per_drone_hour"]
        rows.append(r)
    write_table("table14_tracker", rows, "Table 14. Tracker link success (tracked fraction of flight) by formation size g; 64 drones, 5 s silence")
    write_json("tracking", {"formation": {str(k): v for k, v in tabA.items()}, "silence_g8": {str(k): v for k, v in tabB.items()},
                            "solo_density": {str(k): v for k, v in tabC.items()}, "seeds": nseed})
    for r in rows: print(r)
    print("silence sweep (g=8, link success):")
    for s in S: print(s, {p[:8]: round(tabB[s][p]["link_success"], 2) for p in POLICIES})
    print("solo density:")
    for n in Ns: print(n, {p[:8]: (round(tabC[n][p]["link_success"], 2), round(tabC[n][p]["rot_per_drone_hour"], 1)) for p in POLICIES})

if __name__ == "__main__":
    main()
