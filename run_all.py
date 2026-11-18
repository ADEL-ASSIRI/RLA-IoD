"""Regenerate every table and figure.   python experiments/run_all.py [--quick]"""
import subprocess, sys, time
from pathlib import Path
here = Path(__file__).parent
extra = ["--quick"] if "--quick" in sys.argv else []
for s in ["run_attacks.py", "bench.py", "projections.py", "run_span.py", "run_tracking.py", "make_figures.py"]:
    t = time.time(); print(f"\n=== {s} ===", flush=True)
    subprocess.run([sys.executable, str(here / s)] + (extra if s != "make_figures.py" and s != "projections.py" else []), check=True)
    print(f"[{s}: {time.time()-t:.0f}s]")
