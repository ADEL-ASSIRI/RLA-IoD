"""Figures 4-10 from results/*.json (run the other scripts first). Figures 1-3 are diagrams."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from common import RESULTS, read_json
from rla_iod.costmodel import OPS, PLATFORMS

BLUE, ORANGE, AQUA, GREY, INK, MUTED = "#2a78d6", "#eb6834", "#1baf7a", "#8a8a86", "#0b0b0b", "#52514e"
plt.rcParams.update({"figure.facecolor": "#fcfcfb", "axes.facecolor": "#fcfcfb", "savefig.facecolor": "#fcfcfb",
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": "#e4e3df", "grid.linewidth": 0.6,
    "font.size": 9, "axes.titlesize": 10, "legend.frameon": False, "lines.linewidth": 2})
FIG = RESULTS / "figures"; FIG.mkdir(exist_ok=True)
def save(fig, name): fig.tight_layout(); fig.savefig(FIG / f"{name}.png", dpi=200); plt.close(fig); print("wrote", name)

def fig4():
    b = read_json("bench"); pr = read_json("projection")
    fig, ax = plt.subplots(1, 2, figsize=(9, 3.4))
    names = list(b["primitives"]); m = [b["primitives"][n]["mean"] for n in names]; ci = [b["primitives"][n]["ci95"] for n in names]
    ax[0].barh(range(len(names)), m, xerr=ci, color=BLUE, height=0.55, error_kw={"ecolor": INK, "lw": 1}); ax[0].set_xscale("log")
    ax[0].set_yticks(range(len(names)), names); ax[0].invert_yaxis(); ax[0].set_xlabel("ms per operation (host, log scale)"); ax[0].set_title("(a) Measured primitives")
    comps = ["RLA-IoD drone, cold", "RLA-IoD drone, cert cached", "+ precomputed ephemeral key", "Static-ECDH design, drone"]
    x = np.arange(len(comps)); w = 0.26
    for i, (k, c) in enumerate([("AVR_ms", BLUE), ("CortexM4_ms", ORANGE), ("RPiB+_ms", AQUA)]):
        ax[1].bar(x + (i - 1) * w, [pr[n][k] for n in comps], w, color=c, label=["AVR 16 MHz", "Cortex-M4 100 MHz", "RPi B+"][i])
    ax[1].set_yscale("log"); ax[1].set_xticks(x, ["cold", "cert cached", "+ precomp.", "static design"], rotation=15)
    ax[1].set_ylabel("ms (projected, log scale)"); ax[1].set_title("(b) Drone-side handshake, projected"); ax[1].legend()
    save(fig, "fig4_primitives_projection")

def fig5():
    b = read_json("bench"); h = b["handshake_cpu"]; names = list(h)
    fig, ax = plt.subplots(1, 2, figsize=(9, 3.4)); x = np.arange(len(names))
    ax[0].bar(x - 0.2, [h[n]["drone"] for n in names], 0.4, color=BLUE, label="drone")
    ax[0].bar(x + 0.2, [h[n]["gcs"] for n in names], 0.4, color=ORANGE, label="GCS")
    ax[0].set_yscale("log"); ax[0].set_xticks(x, ["PSK", "Static\nECDH", "RLA\ncached", "RLA\ncold"]); ax[0].set_ylabel("CPU ms per handshake (host, log)")
    ax[0].set_title("(a) CPU per handshake"); ax[0].legend()
    sz = b["msg_sizes_cold"]; parts = ["M1", "M2", "M3"]
    ax[1].bar(parts, sz, color=AQUA, width=0.5); ax[1].axhline(255, color=INK, ls="--", lw=1)
    ax[1].text(2.45, 258, "MAVLink 2 payload limit (255 B)", ha="right", fontsize=8, color=MUTED)
    for i, v in enumerate(sz): ax[1].text(i, v + 4, f"{v} B", ha="center", fontsize=8)
    ax[1].set_ylabel("bytes (cold handshake)"); ax[1].set_title("(b) Message sizes")
    save(fig, "fig5_cpu_and_sizes")

def fig6():
    f = read_json("bench")["flood"]; r = f["rates"]
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    ax.plot(r, f["cookie"], color=BLUE, label="cookie required"); ax.plot(r, f["no_cookie"], color=ORANGE, ls="--", label="no cookie")
    ax.set_xlabel("forged M1 per second"); ax.set_ylabel("legitimate auths per second (1 core)"); ax.legend(); ax.set_ylim(bottom=0)
    save(fig, "fig6_flood")

def fig7():
    s = read_json("span_main"); sq = read_json("sqrt_law"); fx = s["fixed"]
    fig, ax = plt.subplots(1, 3, figsize=(13, 3.8))
    ax[0].plot(fx["cost"], fx["exposure"], color=GREY, label="fixed DH-ratchet span"); 
    ap = s["adaptive"]["points"]; op = s["oracle"]["points"]
    ax[0].errorbar([p["cost"] for p in ap], [p["exposure"] for p in ap], yerr=[p["exposure_ci"] for p in ap], color=BLUE, marker="o", label="adaptive (mu = 3 ... 3000)", capsize=2)
    ax[0].plot([p["cost"] for p in op], [p["exposure"] for p in op], color=ORANGE, marker="^", ls="--", label="oracle")
    t = s["timeout"]; ax[0].plot(t["cost"], t["exposure"], "s", color=AQUA, ms=8, label="re-handshake every 300 s")
    ax[0].set_xscale("log"); ax[0].set_yscale("log"); ax[0].set_xlabel("drone CPU, ms per message"); ax[0].set_ylabel("messages exposed per 1000"); ax[0].legend(fontsize=7); ax[0].set_title("(a) Cost vs exposure")
    ax[1].plot(sq["L_curve"], sq["J_closed"], color=BLUE, label="closed form J(L)"); ax[1].plot(sq["L"], sq["J_empirical"], "o", color=ORANGE, ms=4, label="simulated")
    ax[1].axvline(sq["L_star"], color=INK, ls="--", lw=1); ax[1].text(sq["L_star"] * 1.04, ax[1].get_ylim()[1] * 0.97, f"L* = {sq['L_star']:.0f}", fontsize=8, va="top")
    ax[1].set_xlabel("span L (messages)"); ax[1].set_ylabel("J (ms per message)"); ax[1].legend(); ax[1].set_title("(b) Square-root law")
    import csv
    rows = list(csv.DictReader(open(RESULTS / "table11_signal_strength.csv")))
    rho = [float(r["rho"]) for r in rows]
    for (mu, c, mk) in [(10, BLUE, "o"), (30, ORANGE, "s"), (100, AQUA, "^"), (300, GREY, "D")]:
        ax[2].plot(rho, [float(r[f"mu={mu}"]) for r in rows], color=c, marker=mk, label=f"mu = {mu}")
    ax[2].axhline(0, color=INK, lw=0.8); ax[2].set_xscale("log"); ax[2].set_xlabel("attack detectability rho (extra anomaly rate)")
    ax[2].set_ylabel("exposure reduction at equal cost (%)"); ax[2].legend(); ax[2].set_title("(c) Weaker signal")
    save(fig, "fig7_span_control")

def fig8():
    t = read_json("trace_fig8"); n = len(t["r"]); x = np.arange(n) + t["start"]
    fig, ax = plt.subplots(3, 1, figsize=(8, 6), sharex=True)
    a = np.array(t["a"], bool)
    for k in ax:
        k.fill_between(x, 0, 1, where=a, color=ORANGE, alpha=0.15, transform=k.get_xaxis_transform(), lw=0)
    ax[0].plot(x, t["r"], color=BLUE); ax[0].set_ylabel("risk estimate r"); 
    ax[1].plot(x, t["L"], color=BLUE); ax[1].set_yscale("log"); ax[1].set_ylabel("span L")
    l2 = x[np.array(t["level2"], bool)]; l3 = x[np.array(t["level3"], bool)]; dc = x[np.array(t["disc"], bool)]
    ax[2].eventplot([l2, l3, dc], colors=[BLUE, AQUA, ORANGE], lineoffsets=[2, 1, 0], linelengths=0.7)
    ax[2].set_yticks([0, 1, 2], ["disclosure", "Level-3", "DH ratchet"]); ax[2].set_xlabel("message index")
    fig.suptitle("Mission segment, mu = 100 (shaded: attack episode)", fontsize=10)
    save(fig, "fig8_trace")

def fig9_10():
    t = read_json("tracking"); pols = ["Fixed 300 s, async", "Fixed 120 s, async", "RLA-IoD coordinated"]
    cols = [BLUE, ORANGE, AQUA]; mk = ["o", "s", "^"]
    G = sorted(int(g) for g in t["formation"]); fig, ax = plt.subplots(1, 3, figsize=(13, 3.7))
    for p, c, m in zip(pols, cols, mk):
        ax[0].errorbar(G, [t["formation"][str(g)][p]["link_success"] for g in G], yerr=[t["formation"][str(g)][p]["link_ci95"] for g in G], color=c, marker=m, label=p, capsize=2)
        ax[1].plot(G, [t["formation"][str(g)][p]["tracked_fraction"] for g in G], color=c, marker=m, label=p)
    S = sorted(int(s) for s in t["silence_g8"])
    for p, c, m in zip(pols, cols, mk):
        ax[2].plot(S, [t["silence_g8"][str(s)][p]["link_success"] for s in S], color=c, marker=m, label=p)
    for k, (xl, yl, ti) in zip(ax, [("formation size g", "rotations linked correctly", "(a) Link success"), ("formation size g", "fraction of flight followed", "(b) Tracked fraction"), ("silent period s (s), g = 8", "rotations linked correctly", "(c) Silence")]):
        k.set_xlabel(xl); k.set_ylabel(yl); k.set_title(ti); k.set_ylim(0, 1.05)
    ax[0].set_xscale("log", base=2); ax[1].set_xscale("log", base=2); ax[0].set_xticks(G, G); ax[1].set_xticks(G, G); ax[0].minorticks_off(); ax[1].minorticks_off(); ax[0].legend(fontsize=7)
    save(fig, "fig9_tracker")
    N = sorted(int(n) for n in t["solo_density"]); fig, ax = plt.subplots(figsize=(5.2, 3.4))
    for p, c, m in zip(pols, cols, mk): ax.plot(N, [t["solo_density"][str(n)][p]["link_success"] for n in N], color=c, marker=m, label=p)
    ax.set_xscale("log"); ax.set_ylim(0, 1.05); ax.set_xlabel("solo drones in 4 km^2"); ax.set_ylabel("rotations linked correctly"); ax.legend(fontsize=7)
    save(fig, "fig10_solo_density")

if __name__ == "__main__":
    for f in (fig4, fig5, fig6, fig7, fig8, fig9_10): f()
