"""Print a short summary of a CSV file."""

import csv
import sys


def summarize(path: str) -> None:
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    if not rows:
        print("empty file")
        return

    print(f"rows: {len(rows)}")
    print(f"columns: {', '.join(rows[0].keys())}")

    for column in rows[0]:
        missing = sum(1 for row in rows if not row.get(column))
        print(f"  {column}: {missing} missing")

    print("\npreview:")
    for row in rows[:5]:
        print("  ", row)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: summarize.py <file.csv>")
    summarize(sys.argv[1])
