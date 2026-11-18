"""Shared helpers for the experiment scripts."""
from __future__ import annotations
import argparse, csv, json, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def parser(desc: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=desc)
    ap.add_argument("--quick", action="store_true", help="small sample sizes (smoke test, minutes -> seconds)")
    ap.add_argument("--seed", type=int, default=2026)
    return ap


def write_table(name: str, rows: list[dict], title: str = "") -> None:
    """Write results/<name>.csv and results/<name>.md."""
    if not rows:
        return
    cols = list(rows[0].keys())
    with open(RESULTS / f"{name}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    fmt = lambda v: f"{v:.4g}" if isinstance(v, float) else str(v)  # noqa: E731
    md = [f"### {title or name}", "", "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    md += ["| " + " | ".join(fmt(r[c]) for c in cols) + " |" for r in rows]
    (RESULTS / f"{name}.md").write_text("\n".join(md) + "\n")


def write_json(name: str, obj) -> None:
    def conv(o):
        import numpy as np
        if isinstance(o, (np.integer,)): return int(o)
        if isinstance(o, (np.floating,)): return float(o)
        if isinstance(o, np.ndarray): return o.tolist()
        raise TypeError(type(o))
    (RESULTS / f"{name}.json").write_text(json.dumps(obj, indent=1, default=conv))


def read_json(name: str):
    return json.loads((RESULTS / f"{name}.json").read_text())
