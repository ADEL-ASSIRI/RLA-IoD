"""Table 3: adversary harness. 300 trials per test, fresh keys every trial."""
import collections, random
from common import parser, write_table
from rla_iod.attacks import ATTACKS

def main():
    a = parser(__doc__).parse_args()
    n = 30 if a.quick else 300
    rng = random.Random(a.seed)
    rows = []
    for name, fn in ATTACKS:
        acc, stages = 0, collections.Counter()
        for _ in range(n):
            o = fn(rng); acc += o.accepted; stages[o.stage] += 1
        st = "; ".join(f"{k} ({v})" if len(stages) > 1 else k for k, v in stages.most_common())
        rows.append({"Test": name, "Accepted/trials": f"{acc}/{n}", "Rejected at": st if "control" not in name else "-"})
        print(f"{name:52s} {acc}/{n}  {st}")
    write_table("table3_attacks", rows, 'Table 3. Adversary harness ("Accepted" = attack succeeded; control: honest run succeeded)')

if __name__ == "__main__":
    main()
