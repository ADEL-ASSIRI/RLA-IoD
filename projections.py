"""Table 7 and Figure 4b data: PROJECTIONS from published per-operation timings."""
from common import parser, write_table, write_json
from rla_iod.costmodel import projection_table, OPS, PLATFORMS

def main():
    parser(__doc__).parse_args()
    rows = projection_table()
    write_table("table7_projection", [{k: v for k, v in r.items() if k != "pk_ops"} for r in rows],
                "Table 7. Projected drone-side cost per exchange component (published timings x exact op counts)")
    write_json("projection", {r["component"]: r for r in rows})
    for r in rows: print(r)

if __name__ == "__main__":
    main()
