#!/usr/bin/env python3
"""Aggregate JSON results into HTML/PDF offline."""
import json
from pathlib import Path

TEMPLATE = """<html><body><h1>NETS Test Report</h1><pre>{content}</pre></body></html>"""


def main() -> None:
    data = {}
    for path in Path("tests/results").glob("*.json"):
        data[path.stem] = json.loads(path.read_text())
    html = TEMPLATE.format(content=json.dumps(data, indent=2, ensure_ascii=False))
    out = Path("tests/results/report.html")
    out.write_text(html)
    print(f"Report generated at {out}")


if __name__ == "__main__":
    main()
