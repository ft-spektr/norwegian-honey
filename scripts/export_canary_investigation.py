#!/usr/bin/env python3
"""Export canary investigation report (hits + optional OSINT) as JSON."""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.config import get_settings
from app.core.json_document import load_json_document
from app.models.analyze import HeaderAnalysisResponse
from app.models.canary import StoredCanaryHit
from app.models.osint import OSINTQueryRequest, OSINTQueryResponse
from app.models.report import ThreatScoreReport
from app.services.canary_investigation import build_canary_investigation
from app.services.osint.aggregator import aggregate_osint


def _load_hits(db_path: Path, token: str | None, trap: str | None, limit: int) -> list[StoredCanaryHit]:
    if not db_path.exists():
        raise FileNotFoundError(f"database not found: {db_path}")

    clauses: list[str] = []
    params: list[object] = []
    if token:
        clauses.append("token = ?")
        params.append(token)
    if trap:
        clauses.append("trap = ?")
        params.append(trap)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"""
        SELECT id, token, trap, client_ip, user_agent, referer, method, headers_json, timestamp
        FROM canary_hits
        {where}
        ORDER BY timestamp ASC, id ASC
        LIMIT ?
    """
    params.append(limit)

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()

    hits: list[StoredCanaryHit] = []
    for row in rows:
        try:
            headers = json.loads(row[7] or "{}")
        except json.JSONDecodeError:
            headers = {}
        ts = datetime.fromisoformat(str(row[8]).replace("Z", "+00:00"))
        hits.append(
            StoredCanaryHit(
                id=row[0],
                token=row[1],
                trap=row[2] or "images",
                client_ip=row[3],
                user_agent=row[4],
                referer=row[5],
                method=row[6] or "GET",
                headers=headers,
                timestamp=ts,
            )
        )
    return hits


async def _run(args: argparse.Namespace) -> str:
    hits = _load_hits(Path(args.db_path), args.token, args.trap, args.limit)
    osint: OSINTQueryResponse | None = None
    analysis: HeaderAnalysisResponse | None = None
    threat_report: ThreatScoreReport | None = None

    if args.osint:
        osint = OSINTQueryResponse.model_validate(load_json_document(args.osint))
    elif args.run_osint:
        ips = list(dict.fromkeys(hit.client_ip for hit in hits))
        if ips:
            settings = get_settings()
            osint = await aggregate_osint(OSINTQueryRequest(ips=ips), settings)

    if args.analysis:
        analysis = HeaderAnalysisResponse.model_validate(load_json_document(args.analysis))
    if args.threat_report:
        threat_report = ThreatScoreReport.model_validate(load_json_document(args.threat_report))

    report = build_canary_investigation(
        hits,
        token=args.token,
        trap=args.trap,
        osint=osint,
        analysis=analysis,
        threat_report=threat_report,
    )
    return report.model_dump_json(indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export canary hits + OSINT investigation JSON.")
    parser.add_argument("--db-path", default="./data/canary.db", help="Canary SQLite path")
    parser.add_argument("--token", help="Filter by canary token")
    parser.add_argument("--trap", choices=("images", "portfolio"), help="Filter by trap type")
    parser.add_argument("--limit", type=int, default=500, help="Max hits to export")
    parser.add_argument("--run-osint", action="store_true", help="Run OSINT on unique hit IPs")
    parser.add_argument("--osint", type=Path, help="Use existing OSINT JSON instead of live lookups")
    parser.add_argument("--analysis", type=Path, help="Include header analysis JSON")
    parser.add_argument("--threat-report", type=Path, help="Include threat score report JSON")
    parser.add_argument("-o", "--output", type=Path, help="Write JSON to file (default: stdout)")

    args = parser.parse_args(argv)
    payload = asyncio.run(_run(args))

    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
