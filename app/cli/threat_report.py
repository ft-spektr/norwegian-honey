"""CLI: threat score report from analysis JSON (+ optional OSINT)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from app.config import get_settings
from app.models.analyze import HeaderAnalysisResponse
from app.models.osint import OSINTQueryRequest, OSINTQueryResponse
from app.services.osint.aggregator import aggregate_osint
from app.services.threat_scorer import build_threat_report


async def _run(
    analysis_path: Path,
    osint_path: Path | None,
    skip_osint: bool,
    include_source: bool,
) -> str:
    analysis = HeaderAnalysisResponse.model_validate_json(analysis_path.read_text(encoding="utf-8"))
    osint: OSINTQueryResponse | None = None

    if osint_path:
        osint = OSINTQueryResponse.model_validate_json(osint_path.read_text(encoding="utf-8"))
    elif not skip_osint:
        settings = get_settings()
        request = OSINTQueryRequest(
            ips=analysis.extracted_ips[: settings.osint_max_entities_per_type],
            domains=analysis.extracted_domains[: settings.osint_max_entities_per_type],
            emails=analysis.extracted_emails[: settings.osint_max_entities_per_type],
        )
        osint = await aggregate_osint(request, settings)

    report = build_threat_report(analysis, osint, include_source=include_source)
    return report.model_dump_json(indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a phishing/spam threat score report from analysis and OSINT JSON.",
    )
    parser.add_argument("analysis", type=Path, help="Path to header analysis JSON")
    parser.add_argument("--osint", type=Path, help="Optional OSINT JSON (skip live lookups)")
    parser.add_argument(
        "--skip-osint",
        action="store_true",
        help="Score headers/identity only; do not run OSINT lookups",
    )
    parser.add_argument(
        "--include-source",
        action="store_true",
        help="Embed full analysis and OSINT payloads in the report",
    )
    parser.add_argument("-o", "--output", type=Path, help="Write report JSON to file")

    args = parser.parse_args(argv)
    payload = asyncio.run(
        _run(args.analysis, args.osint, args.skip_osint, args.include_source),
    )

    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
