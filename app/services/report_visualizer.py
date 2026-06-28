"""Pandas tables for human-readable investigation and threat reports."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

import pandas as pd

from app.core.json_document import load_json_document

pd.set_option("display.max_colwidth", 72)
pd.set_option("display.width", 120)

# Columns that tend to contain long prose — wrap in HTML/terminal output.
_WRAP_COLUMNS = frozenset(
    {
        "summary",
        "message",
        "notes",
        "user_agent",
        "from",
        "subject",
        "hostname",
        "org",
        "raw",
        "action",
        "reason",
        "headline",
    }
)

_CODE_COLUMNS = frozenset({"code"})

# Medium-length values — wrap inside the column (timestamps, domains, roles, …).
_MEDIUM_COLUMNS = frozenset(
    {
        "timestamp",
        "first_seen",
        "last_seen",
        "exported_at",
        "time",
        "domain",
        "role",
        "ip",
        "priority",
        "registrar",
        "created",
        "by",
        "category",
        "reply_to",
        "date",
    }
)

# Short values — single line; ellipsis if the allotted width is too narrow.
_COMPACT_COLUMNS = frozenset(
    {
        "severity",
        "points",
        "score",
        "verdict",
        "weight",
        "hits",
        "hop",
        "id",
        "trap",
        "token",
        "country",
        "city",
        "found",
        "abuse_%",
        "findings",
    }
)

_COLUMN_WEIGHT = {"compact": 1.0, "medium": 2.8, "code": 3.8, "prose": 6.5}
_PRIMARY_PROSE = ("message", "summary", "action", "user_agent", "notes", "hostname", "reason", "org")

_TERMINAL_CELL_MAX = 56

_TABLE_TITLES: dict[str, str] = {
    "overview": "Canary overview",
    "timeline": "Hit timeline",
    "ip_profiles": "IP profiles",
    "threat_score": "Threat score",
    "threat_email": "Email",
    "threat_summary": "Summary",
    "threat_overview": "Threat overview",
    "threat_action_headline": "Recommended actions",
    "threat_action_plan": "Action plan",
    "threat_categories": "Category scores",
    "threat_findings": "Findings",
    "email_overview": "Email overview",
    "received_hops": "Received hops",
    "anomalies": "Header anomalies",
    "osint_ips": "OSINT — IPs",
    "osint_domains": "OSINT — Domains",
    "canary_overview": "Canary overview",
    "canary_timeline": "Canary hit timeline",
    "canary_ip_profiles": "Canary IP profiles",
}

_HTML_STYLES = """
body{font-family:system-ui,sans-serif;margin:2rem;background:#f6f7f9;color:#1f2933}
h1{font-size:1.4rem} h2{font-size:1rem;margin-top:2rem;color:#52606d}
.meta{color:#627d98;margin-bottom:1.5rem}
.headline-box{margin:0 0 1.5rem;padding:.85rem 1rem;background:#fff;border:1px solid #d9e2ec;
border-left:4px solid #3e4c59;font-size:.95rem;line-height:1.45}
.score-hero{display:flex;align-items:baseline;gap:1rem;margin:0 0 1.5rem;padding:1rem 1.25rem;
background:#fff;border:1px solid #d9e2ec;border-radius:4px}
.score-value{font-size:2.5rem;font-weight:700;line-height:1;color:#1f2933}
.score-verdict{font-size:1rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em}
.verdict-low{color:#2f855a}.verdict-moderate{color:#b7791f}
.verdict-high{color:#c05621}.verdict-critical{color:#c53030}
.table-wrap{overflow-x:auto;margin:.5rem 0 1.5rem}
table.report-table{border-collapse:collapse;width:100%;background:#fff;
border:1px solid #d9e2ec;font-size:.88rem;table-layout:fixed}
table.report-table.wide{min-width:1080px}
table.report-table th,table.report-table td{
padding:.55rem .65rem;border-bottom:1px solid #e4e7eb;text-align:left;vertical-align:top;
overflow:hidden}
table.report-table th{background:#f0f4f8;font-size:.75rem;text-transform:uppercase;
letter-spacing:.04em;font-weight:600}
table.report-table tr:nth-child(even){background:#fafbfc}
table.report-table th.compact,table.report-table td.compact{
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
table.report-table td.medium,table.report-table th.medium,
table.report-table td.code,table.report-table th.code{white-space:normal;min-width:5.5rem}
table.report-table td.prose,table.report-table th.prose{white-space:normal;min-width:8rem}
table.report-table td.medium .cell-text,table.report-table td.code .cell-text,
table.report-table td.prose .cell-text{display:block;overflow-wrap:break-word;word-break:break-word;
line-height:1.45;hyphens:auto}
"""


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


def canary_investigation_core_tables(data: dict[str, Any]) -> dict[str, pd.DataFrame]:
    """Canary hit timeline and IP profiles (no nested threat/analysis)."""
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
                "user_agent": hit.get("user_agent") or "",
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
                "user_agent": (profile.get("user_agents") or [""])[0],
                "notes": "; ".join(profile.get("notes") or []),
            }
        )
    tables["ip_profiles"] = pd.DataFrame(profile_rows)
    return tables


def investigation_tables(data: dict[str, Any]) -> dict[str, pd.DataFrame]:
    tables = canary_investigation_core_tables(data)

    threat = data.get("threat_report")
    if threat:
        tables.update(threat_report_tables(threat))

    analysis = data.get("analysis")
    if analysis:
        tables.update(analysis_tables(analysis))

    return tables


def _merge_tables(
    base: dict[str, pd.DataFrame],
    extra: dict[str, pd.DataFrame],
    *,
    prefix: str = "",
) -> dict[str, pd.DataFrame]:
    for key, frame in extra.items():
        name = f"{prefix}{key}" if prefix else key
        base[name] = frame
    return base


def threat_report_tables(data: dict[str, Any]) -> dict[str, pd.DataFrame]:
    tables: dict[str, pd.DataFrame] = {}

    tables["threat_score"] = pd.DataFrame(
        [
            {
                "score": data.get("overall_score"),
                "verdict": data.get("verdict"),
            }
        ]
    )
    tables["threat_email"] = pd.DataFrame(
        [
            {
                "from": data.get("from_address"),
                "domain": data.get("from_domain"),
                "subject": data.get("subject"),
            }
        ]
    )
    if data.get("summary"):
        tables["threat_summary"] = pd.DataFrame([{"summary": data.get("summary")}])

    plan = data.get("action_plan") or {}
    if plan:
        if plan.get("headline"):
            tables["threat_action_headline"] = pd.DataFrame([{"headline": plan.get("headline")}])
        plan_rows = [
            {
                "priority": item.get("priority"),
                "action": item.get("action"),
                "reason": item.get("reason") or "",
            }
            for item in plan.get("actions") or []
        ]
        tables["threat_action_plan"] = pd.DataFrame(plan_rows)

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

    investigation = data.get("investigation")
    if isinstance(investigation, dict) and investigation.get("timeline"):
        _merge_tables(tables, canary_investigation_core_tables(investigation), prefix="canary_")

    analysis = data.get("analysis")
    if isinstance(analysis, dict) and analysis.get("from_domain"):
        _merge_tables(tables, analysis_tables(analysis))

    osint = data.get("osint")
    if isinstance(osint, dict) and (osint.get("ips") or osint.get("domains")):
        _merge_tables(tables, osint_tables(osint))

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


def _cell_str(value: Any) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    text = str(value)
    return "" if text == "nan" else text


def _column_kind(column: str) -> str:
    if column in _COMPACT_COLUMNS:
        return "compact"
    if column in _CODE_COLUMNS:
        return "code"
    if column in _MEDIUM_COLUMNS:
        return "medium"
    return "prose"


def _primary_prose_column(columns: list[str]) -> str | None:
    prose_columns = [column for column in columns if _column_kind(column) == "prose"]
    if not prose_columns:
        return None
    for name in _PRIMARY_PROSE:
        if name in prose_columns:
            return name
    return prose_columns[-1]


def _column_width_percent(columns: list[str], column: str) -> str:
    primary = _primary_prose_column(columns)
    weights: list[float] = []
    for col in columns:
        weight = _COLUMN_WEIGHT[_column_kind(col)]
        if col == primary:
            weight += 3.0
        weights.append(weight)
    total = sum(weights) or 1.0
    share = weights[columns.index(column)] * 100.0 / total
    return f"{share:.1f}%"


def _table_title(key: str) -> str:
    return _TABLE_TITLES.get(key, key.replace("_", " ").title())


def _render_score_hero(tables: dict[str, pd.DataFrame]) -> str:
    df = tables.get("threat_score")
    if df is None or df.empty:
        return ""
    row = df.iloc[0]
    score = _cell_str(row.get("score"))
    verdict = _cell_str(row.get("verdict"))
    if not score and not verdict:
        return ""
    verdict_class = f"verdict-{verdict}" if verdict else ""
    return (
        '<div class="score-hero">'
        f'<div class="score-value">{html.escape(score)}</div>'
        f'<div class="score-verdict {verdict_class}">{html.escape(verdict)}</div>'
        "</div>"
    )


def _dataframe_to_html(df: pd.DataFrame) -> str:
    columns = [str(column) for column in df.columns]
    table_class = "report-table wide" if len(columns) >= 8 else "report-table"
    lines = [f'<table class="{table_class}">', "  <colgroup>"]
    for column in columns:
        width = _column_width_percent(columns, column)
        lines.append(f'    <col style="width:{width}">')
    lines.append("  </colgroup>")
    lines.append("  <thead><tr>")
    for column in columns:
        kind = _column_kind(column)
        lines.append(f'    <th class="{kind}">{html.escape(column)}</th>')
    lines.append("  </tr></thead>")
    lines.append("  <tbody>")
    for _, row in df.iterrows():
        lines.append("    <tr>")
        for column in columns:
            kind = _column_kind(column)
            text = html.escape(_cell_str(row[column]))
            if kind in {"prose", "code", "medium"}:
                lines.append(f'      <td class="{kind}"><div class="cell-text">{text}</div></td>')
            else:
                lines.append(f'      <td class="{kind}">{text}</td>')
        lines.append("    </tr>")
    lines.append("  </tbody>")
    lines.append("</table>")
    return "\n".join(lines)


def _truncate_cell_text(value: Any, max_len: int = _TERMINAL_CELL_MAX) -> str:
    text = _cell_str(value)
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _dataframe_for_terminal(df: pd.DataFrame) -> pd.DataFrame:
    trimmed = df.copy()
    for col in trimmed.columns:
        if col in _WRAP_COLUMNS or col in _CODE_COLUMNS or col in _MEDIUM_COLUMNS:
            trimmed[col] = trimmed[col].map(_truncate_cell_text)
    return trimmed


def render_text(report_type: str, tables: dict[str, pd.DataFrame]) -> str:
    lines = [f"=== Norwegian Honey report ({report_type}) ===", ""]
    for key, df in tables.items():
        if df.empty or key == "threat_score":
            continue
        title = _table_title(key).upper() if key == "overview" else _table_title(key)
        lines.append(title)
        lines.append("-" * len(title))
        lines.append(_dataframe_for_terminal(df).to_string(index=False))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(report_type: str, tables: dict[str, pd.DataFrame], title: str) -> str:
    parts = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>{html.escape(title)}</title>",
        f"<style>{_HTML_STYLES}</style>",
        "</head>",
        "<body>",
        f"<h1>{html.escape(title)}</h1>",
        f"<p class='meta'>Report type: {html.escape(report_type)}</p>",
    ]
    hero = _render_score_hero(tables)
    if hero:
        parts.append(hero)
    for key, df in tables.items():
        if df.empty or key == "threat_score":
            continue
        parts.append(f"<h2>{html.escape(_table_title(key))}</h2>")
        if key == "threat_action_headline" and len(df.columns) == 1:
            headline = _cell_str(df.iloc[0, 0])
            parts.append(f'<p class="headline-box">{html.escape(headline)}</p>')
            continue
        parts.append('<div class="table-wrap">')
        parts.append(_dataframe_to_html(df))
        parts.append("</div>")
    parts.extend(["</body>", "</html>"])
    return "\n".join(parts)
