"""Pandas tables for human-readable investigation and threat reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from app.core.json_document import load_json_document

pd.set_option("display.max_colwidth", 72)
pd.set_option("display.width", 120)


def _short_ua(ua: str | None, limit: int = 48) -> str:
    if not ua:
        return ""
    return ua if len(ua) <= limit else ua[: limit - 1] + "…"


def _ipinfo_fields(osint: dict[str, Any]) -> dict[str, str]:
    info = osint.get("ipinfo") or {}
    abuse = osint.get("abuseipdb") or {}
    abuse_score = ""
    if abuse.get("skipped"):
        abuse_score = "—"
    elif "abuseConfidenceScore" in abuse:
        abuse_score = str(abuse.get("abuseConfidenceScore"))
    return {
        "country": str(info.get("country") or ""),
        "city": str(info.get("city") or ""),
        "org": str(info.get("org") or ""),
        "hostname": str(info.get("hostname") or ""),
        "abuse_score": abuse_score,
    }


def investigation_tables(data: dict[str, Any]) -> dict[str, pd.DataFrame]:
    tables: dict[str, pd.DataFrame] = {}

    overview = pd.DataFrame(
        [
            {
                "exported_at": data.get("exported_at"),
                "token": data.get("token"),
                "trap": data.get("trap"),
                "hits": data.get("hit_count"),
                "unique_ips": data.get("unique_ip_count"),
                "summary": data.get("summary"),
            }
        ]
    )
    tables["overview"] = overview

    timeline_rows = []
    for hit in data.get("timeline") or []:
        timeline_rows.append(
            {
                "id": hit.get("id"),
                "timestamp": hit.get("timestamp"),
                "ip": hit.get("client_ip"),
                "trap": hit.get("trap"),
                "user_agent": _short_ua(hit.get("user_agent"), 56),
            }
        )
    tables["timeline"] = pd.DataFrame(timeline_rows)

    profile_rows = []
    for profile in data.get("ip_profiles") or []:
        geo = _ipinfo_fields(profile.get("osint") or {})
        profile_rows.append(
            {
                "ip": profile.get("ip"),
                "role": profile.get("role"),
                "hits": profile.get("hit_count"),
                "first_seen": profile.get("first_seen"),
                "last_seen": profile.get("last_seen"),
                "country": geo["country"],
                "city": geo["city"],
                "org": geo["org"],
                "hostname": geo["hostname"],
                "abuse_%": geo["abuse_score"],
                "user_agent": _short_ua(
                    (profile.get("user_agents") or [""])[0],
                    40,
                ),
                "notes": "; ".join(profile.get("notes") or []),
            }
        )
    tables["ip_profiles"] = pd.DataFrame(profile_rows)

    threat = data.get("threat_report")
    if threat:
        tables.update(threat_report_tables(threat))

    analysis = data.get("analysis")
    if analysis:
        tables.update(analysis_tables(analysis))

    return tables


def threat_report_tables(data: dict[str, Any]) -> dict[str, pd.DataFrame]:
    tables: dict[str, pd.DataFrame] = {}

    tables["threat_overview"] = pd.DataFrame(
        [
            {
                "score": data.get("overall_score"),
                "verdict": data.get("verdict"),
                "from": data.get("from_address"),
                "domain": data.get("from_domain"),
                "subject": data.get("subject"),
                "summary": data.get("summary"),
            }
        ]
    )

    category_rows = [
        {
            "category": cat.get("name"),
            "score": cat.get("score"),
            "weight": cat.get("weight"),
            "findings": len(cat.get("findings") or []),
        }
        for cat in data.get("categories") or []
    ]
    tables["threat_categories"] = pd.DataFrame(category_rows)

    finding_rows = []
    for item in data.get("findings") or []:
        finding_rows.append(
            {
                "category": item.get("category"),
                "severity": item.get("severity"),
                "points": item.get("points"),
                "code": item.get("code"),
                "message": item.get("message"),
            }
        )
    tables["threat_findings"] = pd.DataFrame(finding_rows)

    return tables


def analysis_tables(data: dict[str, Any]) -> dict[str, pd.DataFrame]:
    tables: dict[str, pd.DataFrame] = {}

    tables["email_overview"] = pd.DataFrame(
        [
            {
                "from": data.get("from_address"),
                "domain": data.get("from_domain"),
                "reply_to": data.get("reply_to"),
                "subject": data.get("subject"),
                "date": data.get("date"),
            }
        ]
    )

    hop_rows = []
    for hop in data.get("received_hops") or []:
        hop_rows.append(
            {
                "hop": hop.get("index"),
                "from": hop.get("from_host"),
                "by": hop.get("by_host"),
                "ip": hop.get("source_ip"),
                "time": hop.get("timestamp"),
            }
        )
    tables["received_hops"] = pd.DataFrame(hop_rows)

    anomaly_rows = []
    for item in data.get("anomalies") or []:
        anomaly_rows.append(
            {
                "severity": item.get("severity"),
                "code": item.get("code"),
                "message": item.get("message"),
            }
        )
    tables["anomalies"] = pd.DataFrame(anomaly_rows)

    return tables


def osint_tables(data: dict[str, Any]) -> dict[str, pd.DataFrame]:
    tables: dict[str, pd.DataFrame] = {}

    ip_rows = []
    grouped: dict[str, dict[str, Any]] = {}
    for item in data.get("ips") or []:
        grouped.setdefault(item.get("ip"), {})[item.get("source")] = item.get("data") or {}

    for ip, sources in grouped.items():
        info = sources.get("ipinfo") or {}
        abuse = sources.get("abuseipdb") or {}
        abuse_score = ""
        if abuse.get("skipped"):
            abuse_score = "—"
        elif "abuseConfidenceScore" in abuse:
            abuse_score = str(abuse.get("abuseConfidenceScore"))
        ip_rows.append(
            {
                "ip": ip,
                "country": info.get("country"),
                "city": info.get("city"),
                "org": info.get("org"),
                "hostname": info.get("hostname"),
                "abuse_%": abuse_score,
            }
        )
    tables["osint_ips"] = pd.DataFrame(ip_rows)

    domain_rows = []
    for item in data.get("domains") or []:
        whois = item.get("data") or {}
        domain_rows.append(
            {
                "domain": item.get("domain"),
                "found": whois.get("found"),
                "registrar": whois.get("registrar"),
                "created": whois.get("creation_date"),
                "org": whois.get("org"),
            }
        )
    tables["osint_domains"] = pd.DataFrame(domain_rows)

    return tables


def detect_report_type(data: dict[str, Any]) -> str:
    if "ip_profiles" in data and "timeline" in data:
        return "investigation"
    if "overall_score" in data and "verdict" in data:
        return "threat"
    if "received_hops" in data and "anomalies" in data:
        return "analysis"
    if "ips" in data or "domains" in data:
        return "osint"
    return "unknown"


def load_tables(path: Path) -> tuple[str, dict[str, pd.DataFrame]]:
    data = load_json_document(path)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    report_type = detect_report_type(data)
    if report_type == "investigation":
        return report_type, investigation_tables(data)
    if report_type == "threat":
        return report_type, threat_report_tables(data)
    if report_type == "analysis":
        return report_type, analysis_tables(data)
    if report_type == "osint":
        return report_type, osint_tables(data)
    raise ValueError(f"Unrecognized report format: {path}")


def render_text(report_type: str, tables: dict[str, pd.DataFrame]) -> str:
    titles = {
        "overview": "CANARY INVESTIGATION",
        "timeline": "Hit timeline",
        "ip_profiles": "IP profiles",
        "threat_overview": "THREAT SCORE",
        "threat_categories": "Category scores",
        "threat_findings": "Findings",
        "email_overview": "EMAIL",
        "received_hops": "Received hops",
        "anomalies": "Anomalies",
        "osint_ips": "OSINT — IPs",
        "osint_domains": "OSINT — Domains",
    }
    lines = [f"=== Norwegian Honey report ({report_type}) ===", ""]
    for key, df in tables.items():
        if df.empty:
            continue
        title = titles.get(key, key.replace("_", " ").title())
        lines.append(title)
        lines.append("-" * len(title))
        lines.append(df.to_string(index=False))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(report_type: str, tables: dict[str, pd.DataFrame], title: str) -> str:
    parts = [
        "<!DOCTYPE html>",
        "<html lang='en'><head><meta charset='utf-8'>",
        f"<title>{title}</title>",
        "<style>",
        "body{font-family:system-ui,sans-serif;margin:2rem;background:#f6f7f9;color:#1f2933}",
        "h1{font-size:1.4rem} h2{font-size:1rem;margin-top:2rem;color:#52606d}",
        "table{border-collapse:collapse;width:100%;background:#fff;margin:.5rem 0 1.5rem",
        "border:1px solid #d9e2ec;font-size:.88rem}",
        "th,td{padding:.5rem .65rem;border-bottom:1px solid #e4e7eb;text-align:left;vertical-align:top}",
        "th{background:#f0f4f8;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}",
        "tr:nth-child(even){background:#fafbfc}",
        ".meta{color:#627d98;margin-bottom:1.5rem}",
        "</style></head><body>",
        f"<h1>{title}</h1>",
        f"<p class='meta'>Report type: {report_type}</p>",
    ]
    titles = {
        "overview": "Overview",
        "timeline": "Hit timeline",
        "ip_profiles": "IP profiles",
        "threat_overview": "Threat overview",
        "threat_categories": "Category scores",
        "threat_findings": "Findings",
        "email_overview": "Email overview",
        "received_hops": "Received hops",
        "anomalies": "Anomalies",
        "osint_ips": "OSINT — IPs",
        "osint_domains": "OSINT — Domains",
    }
    for key, df in tables.items():
        if df.empty:
            continue
        parts.append(f"<h2>{titles.get(key, key)}</h2>")
        parts.append(df.to_html(index=False, escape=True, border=0))
    parts.append("</body></html>")
    return "\n".join(parts)
