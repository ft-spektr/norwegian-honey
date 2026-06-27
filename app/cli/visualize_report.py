"""CLI: render investigation / threat / analysis / OSINT JSON as pandas tables."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.services.report_visualizer import load_tables, render_html, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Visualize Norwegian Honey JSON reports as pandas tables.",
    )
    parser.add_argument("report", type=Path, help="investigation.json, report.json, analysis.json, or osint.json")
    parser.add_argument(
        "--html",
        type=Path,
        help="Write HTML table view to file",
    )
    parser.add_argument(
        "--text",
        type=Path,
        help="Write plain-text table view to file (default: stdout if no --html)",
    )

    args = parser.parse_args(argv)
    report_type, tables = load_tables(args.report)
    text = render_text(report_type, tables)

    if args.html:
        html = render_html(report_type, tables, title=args.report.name)
        args.html.write_text(html, encoding="utf-8")
        print(f"Wrote HTML: {args.html}", file=sys.stderr)

    if args.text:
        args.text.write_text(text, encoding="utf-8")
        print(f"Wrote text: {args.text}", file=sys.stderr)
    elif not args.html:
        print(text, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
