"""Build canary hit + OSINT investigation exports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.models.canary import StoredCanaryHit
from app.models.canary_investigation import CanaryInvestigationReport, IPProfile
from app.models.osint import OSINTQueryResponse


CLOUD_HOST_MARKERS = (
    "amazonaws.com",
    "compute.amazonaws",
    "googleusercontent.com",
    "azure",
    "digitalocean",
    "vultr",
    "linode",
    "hwclouds",
    "aliyuncs",
    "compute.",
    ".ecs-",
    "ecs-",
)

CLOUD_ORG_MARKERS = (
    "AMAZON",
    "GOOGLE CLOUD",
    "MICROSOFT",
    "DIGITALOCEAN",
    "HETZNER",
    "OVH",
    "HUAWEI CLOUD",
    "ALIBABA",
    "LINODE",
    "VULTR",
)

MOBILE_ORG_MARKERS = (
    "MOBILE",
    "CELLULAR",
    "WIRELESS",
    "AIRTEL",
    "VODAFONE",
    "T-MOBILE",
    "TELECOM",
    "LTE",
)


def _osint_by_ip(osint: OSINTQueryResponse | None) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    if osint is None:
        return grouped
    for item in osint.ips:
        grouped.setdefault(item.ip, {})[item.source] = item.data if not item.error else {"error": item.error}
    return grouped


def _classify_ip(ip: str, osint_entry: dict[str, Any], user_agents: list[str]) -> tuple[str, list[str]]:
    notes: list[str] = []
    ipinfo = osint_entry.get("ipinfo") or {}
    hostname = str(ipinfo.get("hostname") or "").lower()
    org = str(ipinfo.get("org") or "").upper()

    if any(marker in hostname for marker in CLOUD_HOST_MARKERS) or any(
        marker in org for marker in CLOUD_ORG_MARKERS
    ):
        notes.append("Cloud/VPS infrastructure — likely automation or backend fetch.")
        return "automation_likely", notes

    if any(marker in org for marker in MOBILE_ORG_MARKERS):
        notes.append("Mobile or consumer ISP — consistent with human client or phone tether.")
        return "human_likely", notes

    if user_agents:
        ua = " ".join(user_agents).lower()
        if "headless" in ua or "curl" in ua or "python-requests" in ua or "wget" in ua:
            notes.append("Scripted user-agent.")
            return "automation_likely", notes

    notes.append("Residential or business ISP — may be human operator or VPN exit.")
    return "unknown", notes


def _build_summary(
    hits: list[StoredCanaryHit],
    profiles: list[IPProfile],
) -> str:
    if not hits:
        return "No canary hits recorded for the selected filter."

    parts = [
        f"{len(hits)} hit(s) from {len(profiles)} unique IP(s).",
    ]
    roles = {p.role for p in profiles}
    if "human_likely" in roles and "automation_likely" in roles:
        parts.append(
            "Mixed human-like and cloud/automation IPs — consistent with manual click followed by backend fetch."
        )
    elif "automation_likely" in roles and len(profiles) == 1:
        parts.append("Single cloud/automation IP — likely bot or link scanner only.")
    elif "human_likely" in roles:
        parts.append("Consumer/mobile IP pattern — consistent with a person opening the link.")

    if len(hits) > len(profiles):
        parts.append("Duplicate hits from the same IP suggest refresh, retry, or double-click.")

    if len(profiles) >= 2:
        first = profiles[0].first_seen
        last = profiles[-1].first_seen
        if first and last and first != last:
            delta = int((last - first).total_seconds())
            parts.append(f"First and last unique IPs were {delta}s apart.")

    return " ".join(parts)


def build_canary_investigation(
    hits: list[StoredCanaryHit],
    *,
    token: str | None = None,
    trap: str | None = None,
    osint: OSINTQueryResponse | None = None,
    analysis=None,
    threat_report=None,
) -> CanaryInvestigationReport:
    osint_map = _osint_by_ip(osint)
    by_ip: dict[str, list[StoredCanaryHit]] = {}
    for hit in hits:
        by_ip.setdefault(hit.client_ip, []).append(hit)

    profiles: list[IPProfile] = []
    for ip, ip_hits in sorted(by_ip.items(), key=lambda item: item[1][0].timestamp):
        user_agents = list(dict.fromkeys(h.user_agent for h in ip_hits if h.user_agent))
        traps = list(dict.fromkeys(h.trap for h in ip_hits))
        role, notes = _classify_ip(ip, osint_map.get(ip, {}), user_agents)
        if len(ip_hits) > 1:
            notes.append(f"{len(ip_hits)} requests from this IP.")
        profiles.append(
            IPProfile(
                ip=ip,
                hit_ids=[h.id for h in ip_hits],
                hit_count=len(ip_hits),
                first_seen=ip_hits[0].timestamp,
                last_seen=ip_hits[-1].timestamp,
                user_agents=user_agents,
                traps=traps,
                role=role,
                notes=notes,
                osint=osint_map.get(ip, {}),
            )
        )

    return CanaryInvestigationReport(
        exported_at=datetime.now(timezone.utc),
        token=token,
        trap=trap,
        hit_count=len(hits),
        unique_ip_count=len(profiles),
        summary=_build_summary(hits, profiles),
        timeline=hits,
        ip_profiles=profiles,
        osint=osint,
        analysis=analysis,
        threat_report=threat_report,
    )
