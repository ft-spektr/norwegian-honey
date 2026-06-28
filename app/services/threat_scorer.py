"""Combine header analysis and OSINT into a phishing/spam threat score."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any

from app.models.analyze import (
    AnomalySeverity,
    AuthResultStatus,
    HeaderAnalysisResponse,
)
from app.models.canary_investigation import CanaryInvestigationReport
from app.models.osint import OSINTQueryResponse
from app.models.report import CategoryScore, ScoreFinding, ThreatScoreReport

FREE_WEBMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "icloud.com",
        "me.com",
        "proton.me",
        "protonmail.com",
        "aol.com",
        "mail.com",
        "gmx.com",
    }
)

SEVERITY_POINTS: dict[AnomalySeverity, int] = {
    AnomalySeverity.LOW: 8,
    AnomalySeverity.MEDIUM: 18,
    AnomalySeverity.HIGH: 35,
    AnomalySeverity.CRITICAL: 50,
}

CATEGORY_WEIGHTS = {
    "identity": 0.40,
    "headers": 0.30,
    "authentication": 0.15,
    "infrastructure": 0.15,
}

CATEGORY_WEIGHTS_WITH_CANARY = {
    "identity": 0.35,
    "headers": 0.28,
    "authentication": 0.15,
    "infrastructure": 0.12,
    "canary": 0.10,
}

# Recipient-side hops often show private IPs; downweight for inbound mail.
RECIPIENT_HOP_ANOMALY_CODES = frozenset({"private_ip_in_first_hop"})

MAIL_INFRA_DOMAIN_SUFFIXES = (
    ".google.com",
    ".gmail.com",
    ".outlook.com",
    ".prod.outlook.com",
    ".one.com",
    ".mailpod",
)

_DOMAIN_LIKE_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.IGNORECASE,
)


def _is_private_ip(ip: str) -> bool:
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            return 16 <= int(parts[1]) <= 31
    return ip.startswith("169.254.") or ip == "::1"


def _is_mail_infrastructure_domain(domain: str) -> bool:
    lowered = domain.lower()
    if lowered in FREE_WEBMAIL_DOMAINS:
        return True
    return any(lowered.endswith(suffix) or suffix.strip(".") in lowered for suffix in MAIL_INFRA_DOMAIN_SUFFIXES)


def _sender_focus_domains(analysis: HeaderAnalysisResponse) -> set[str]:
    domains: set[str] = set()
    _, from_email, from_domain = _parse_sender(analysis.from_address)

    if from_email and from_domain in FREE_WEBMAIL_DOMAINS:
        local_part = from_email.split("@", 1)[0]
        if _looks_like_domain_token(local_part):
            domains.add(local_part.lower())

    for candidate in (analysis.from_domain, analysis.reply_to_domain, analysis.return_path_domain):
        if candidate and not _is_mail_infrastructure_domain(candidate):
            domains.add(candidate.lower())

    return domains


def _sender_focus_ips(analysis: HeaderAnalysisResponse) -> set[str]:
    ips: set[str] = set()
    if analysis.x_originating_ip and not _is_private_ip(analysis.x_originating_ip):
        ips.add(analysis.x_originating_ip)

    # Outermost hops are recipient MX; sender-side IPs are usually deeper in the chain.
    for hop in analysis.received_hops[1:]:
        if hop.source_ip and not _is_private_ip(hop.source_ip):
            ips.add(hop.source_ip)
    return ips


def _clamp_score(points: int) -> int:
    return max(0, min(100, points))


def _verdict(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "moderate"
    return "low"


def _summary(score: int, verdict: str, top_findings: list[ScoreFinding]) -> str:
    lead = {
        "critical": "Strong indicators of phishing or impersonation.",
        "high": "Multiple suspicious signals; treat as likely malicious or deceptive.",
        "moderate": "Some suspicious signals; verify sender identity out-of-band.",
        "low": "Few strong threat signals in headers and OSINT.",
    }[verdict]
    if not top_findings:
        return f"Overall threat score {score}/100 ({verdict}). {lead}"
    highlights = "; ".join(f.message for f in top_findings[:3])
    return f"Overall threat score {score}/100 ({verdict}). {lead} Key signals: {highlights}"


def _parse_sender(from_address: str | None) -> tuple[str | None, str | None, str | None]:
    if not from_address:
        return None, None, None
    display_name, addr = parseaddr(from_address)
    display_name = display_name.strip() or None
    addr = addr.strip().lower() or None
    domain = addr.rsplit("@", 1)[-1] if addr and "@" in addr else None
    return display_name, addr, domain


def _looks_like_domain_token(value: str) -> bool:
    token = value.strip().lower()
    if not token or "@" in token:
        return False
    if token in FREE_WEBMAIL_DOMAINS:
        return False
    return bool(_DOMAIN_LIKE_RE.match(token))


def _identity_findings(analysis: HeaderAnalysisResponse) -> list[ScoreFinding]:
    findings: list[ScoreFinding] = []
    display_name, from_email, from_domain = _parse_sender(analysis.from_address)

    if display_name and from_domain in FREE_WEBMAIL_DOMAINS:
        findings.append(
            ScoreFinding(
                category="identity",
                code="business_name_on_free_webmail",
                severity="high",
                points=30,
                message=f"Display name '{display_name}' sends from free webmail ({from_domain}).",
                evidence={"display_name": display_name, "from_domain": from_domain},
            )
        )

    if from_email and from_domain in FREE_WEBMAIL_DOMAINS:
        local_part = from_email.split("@", 1)[0]
        if _looks_like_domain_token(local_part):
            findings.append(
                ScoreFinding(
                    category="identity",
                    code="domain_like_local_part_on_webmail",
                    severity="high",
                    points=28,
                    message=(
                        f"Gmail/local address embeds a domain-like token '{local_part}' "
                        "— common impersonation pattern."
                    ),
                    evidence={"from_email": from_email, "local_part": local_part},
                )
            )

    if analysis.reply_to_domain and analysis.from_domain:
        if analysis.reply_to_domain != analysis.from_domain:
            findings.append(
                ScoreFinding(
                    category="identity",
                    code="reply_to_domain_mismatch",
                    severity="high",
                    points=35,
                    message="Reply-To domain differs from From domain.",
                    evidence={
                        "from_domain": analysis.from_domain,
                        "reply_to_domain": analysis.reply_to_domain,
                    },
                )
            )

    if analysis.return_path_domain and analysis.from_domain:
        if analysis.return_path_domain != analysis.from_domain:
            findings.append(
                ScoreFinding(
                    category="identity",
                    code="return_path_domain_mismatch",
                    severity="medium",
                    points=18,
                    message="Return-Path envelope domain does not match From domain.",
                    evidence={
                        "from_domain": analysis.from_domain,
                        "return_path_domain": analysis.return_path_domain,
                    },
                )
            )

    return findings


def _header_findings(analysis: HeaderAnalysisResponse) -> list[ScoreFinding]:
    findings: list[ScoreFinding] = []
    for anomaly in analysis.anomalies:
        points = SEVERITY_POINTS.get(anomaly.severity, 10)
        if anomaly.code in RECIPIENT_HOP_ANOMALY_CODES:
            points = max(4, points // 3)
            message = (
                f"{anomaly.message} (often benign on recipient MX infrastructure; "
                "low weight applied.)"
            )
        else:
            message = anomaly.message
        findings.append(
            ScoreFinding(
                category="headers",
                code=anomaly.code,
                severity=anomaly.severity.value,
                points=points,
                message=message,
                evidence=anomaly.evidence,
            )
        )
    return findings


def _auth_findings(analysis: HeaderAnalysisResponse) -> list[ScoreFinding]:
    findings: list[ScoreFinding] = []
    auth_by_mechanism = {a.mechanism: a for a in analysis.authentication}

    for mechanism in ("spf", "dkim", "dmarc"):
        auth = auth_by_mechanism.get(mechanism)
        if auth is None:
            continue
        if auth.status in (AuthResultStatus.FAIL, AuthResultStatus.PERMERROR):
            points = 35 if mechanism == "dmarc" else 25
            findings.append(
                ScoreFinding(
                    category="authentication",
                    code=f"{mechanism}_failed",
                    severity="high" if mechanism == "dmarc" else "medium",
                    points=points,
                    message=f"{mechanism.upper()} authentication failed.",
                    evidence={"domain": auth.domain, "detail": auth.detail, "status": auth.status.value},
                )
            )
        elif auth.status in (AuthResultStatus.SOFTFAIL, AuthResultStatus.NEUTRAL):
            findings.append(
                ScoreFinding(
                    category="authentication",
                    code=f"{mechanism}_{auth.status.value}",
                    severity="medium",
                    points=12,
                    message=f"{mechanism.upper()} result is {auth.status.value}.",
                    evidence={"domain": auth.domain, "detail": auth.detail},
                )
            )

    if not analysis.authentication and analysis.from_domain:
        findings.append(
            ScoreFinding(
                category="authentication",
                code="auth_results_missing_in_headers",
                severity="low",
                points=6,
                message="No Authentication-Results header present — cannot confirm SPF/DKIM/DMARC from this message.",
                evidence={"from_domain": analysis.from_domain},
            )
        )

    return findings


def _parse_whois_date(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value)
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _infrastructure_findings(
    analysis: HeaderAnalysisResponse,
    osint: OSINTQueryResponse | None,
) -> list[ScoreFinding]:
    if osint is None:
        return []

    findings: list[ScoreFinding] = []
    sender_domain = (analysis.from_domain or "").lower()
    sender_email = (_parse_sender(analysis.from_address)[1] or "").lower()
    focus_domains = _sender_focus_domains(analysis)
    focus_ips = _sender_focus_ips(analysis)

    for item in osint.ips:
        if item.ip not in focus_ips or _is_private_ip(item.ip):
            continue
        if item.error:
            continue
        if item.source == "abuseipdb":
            data = item.data
            if data.get("skipped"):
                continue
            score = data.get("abuseConfidenceScore")
            if isinstance(score, (int, float)) and score >= 25:
                sev = "high" if score >= 75 else "medium"
                pts = 40 if score >= 75 else 22
                findings.append(
                    ScoreFinding(
                        category="infrastructure",
                        code="abuseipdb_high_confidence",
                        severity=sev,
                        points=pts,
                        message=f"AbuseIPDB reports {score}% abuse confidence for {item.ip}.",
                        evidence={"ip": item.ip, "abuseConfidenceScore": score},
                    )
                )
            total_reports = data.get("totalReports")
            if isinstance(total_reports, int) and total_reports > 0 and (not score or score < 25):
                findings.append(
                    ScoreFinding(
                        category="infrastructure",
                        code="abuseipdb_reports_present",
                        severity="low",
                        points=10,
                        message=f"AbuseIPDB has {total_reports} report(s) for {item.ip}.",
                        evidence={"ip": item.ip, "totalReports": total_reports},
                    )
                )

        if item.source == "ipinfo":
            data = item.data
            if data.get("privacy", {}).get("vpn") or data.get("privacy", {}).get("proxy"):
                findings.append(
                    ScoreFinding(
                        category="infrastructure",
                        code="ip_privacy_or_vpn",
                        severity="medium",
                        points=15,
                        message=f"IP {item.ip} flagged as VPN/proxy-related in ipinfo.",
                        evidence={"ip": item.ip, "data": data},
                    )
                )

    seen_domains: set[str] = set()
    for item in osint.domains:
        domain = item.domain.lower()
        if domain in seen_domains:
            continue
        seen_domains.add(domain)
        if domain not in focus_domains:
            continue
        if item.error or not item.data.get("found", True):
            if _looks_like_domain_token(domain):
                findings.append(
                    ScoreFinding(
                        category="infrastructure",
                        code="whois_domain_not_found",
                        severity="medium",
                        points=16,
                        message=f"WHOIS lookup found no registration for {domain}.",
                        evidence={"domain": domain},
                    )
                )
            continue

        created = _parse_whois_date(item.data.get("creation_date"))
        if created:
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < 30:
                findings.append(
                    ScoreFinding(
                        category="infrastructure",
                        code="domain_recently_registered",
                        severity="high",
                        points=30,
                        message=f"Domain {domain} registered approximately {age_days} days ago.",
                        evidence={"domain": domain, "creation_date": item.data.get("creation_date")},
                    )
                )
            elif age_days < 180:
                findings.append(
                    ScoreFinding(
                        category="infrastructure",
                        code="domain_under_six_months",
                        severity="medium",
                        points=14,
                        message=f"Domain {domain} is under six months old.",
                        evidence={"domain": domain, "creation_date": item.data.get("creation_date")},
                    )
                )

    for item in osint.emails:
        email = item.email.lower()
        if email != sender_email:
            continue
        if item.error:
            continue
        if not item.data.get("found", True) and sender_domain not in FREE_WEBMAIL_DOMAINS:
            findings.append(
                ScoreFinding(
                    category="infrastructure",
                    code="sender_domain_unregistered",
                    severity="medium",
                    points=18,
                    message=f"Sender domain {sender_domain} has no WHOIS registration.",
                    evidence={"email": item.email, "domain": sender_domain},
                )
            )

    return findings


def _category_score(findings: list[ScoreFinding]) -> int:
    return _clamp_score(sum(f.points for f in findings))


def merge_osint(
    primary: OSINTQueryResponse | None,
    secondary: OSINTQueryResponse | None,
) -> OSINTQueryResponse | None:
    """Merge OSINT results; secondary fills gaps and adds canary hitter IPs."""
    if primary is None:
        return secondary
    if secondary is None:
        return primary

    seen_ips = {(item.ip, item.source) for item in primary.ips}
    seen_domains = {(item.domain, item.source) for item in primary.domains}
    seen_emails = {(item.email, item.source) for item in primary.emails}

    ips = list(primary.ips)
    for item in secondary.ips:
        key = (item.ip, item.source)
        if key not in seen_ips:
            ips.append(item)
            seen_ips.add(key)

    domains = list(primary.domains)
    for item in secondary.domains:
        key = (item.domain, item.source)
        if key not in seen_domains:
            domains.append(item)
            seen_domains.add(key)

    emails = list(primary.emails)
    for item in secondary.emails:
        key = (item.email, item.source)
        if key not in seen_emails:
            emails.append(item)
            seen_emails.add(key)

    return OSINTQueryResponse(ips=ips, domains=domains, emails=emails)


def _canary_findings(investigation: CanaryInvestigationReport | None) -> list[ScoreFinding]:
    if investigation is None or investigation.hit_count == 0:
        return []

    findings: list[ScoreFinding] = [
        ScoreFinding(
            category="canary",
            code="canary_trap_triggered",
            severity="high",
            points=28,
            message=(
                f"Canary trap triggered: {investigation.hit_count} hit(s) from "
                f"{investigation.unique_ip_count} unique IP(s)."
            ),
            evidence={
                "hit_count": investigation.hit_count,
                "unique_ip_count": investigation.unique_ip_count,
                "token": investigation.token,
                "trap": investigation.trap,
            },
        )
    ]

    for profile in investigation.ip_profiles:
        if profile.role == "human_likely":
            findings.append(
                ScoreFinding(
                    category="canary",
                    code="canary_human_operator_likely",
                    severity="high",
                    points=22,
                    message=f"Canary opened from consumer/mobile IP {profile.ip} (human-likely).",
                    evidence={"ip": profile.ip, "role": profile.role, "hit_count": profile.hit_count},
                )
            )
        elif profile.role == "automation_likely":
            findings.append(
                ScoreFinding(
                    category="canary",
                    code="canary_automation_followup",
                    severity="medium",
                    points=14,
                    message=f"Canary followed by cloud/automation IP {profile.ip}.",
                    evidence={"ip": profile.ip, "role": profile.role, "hit_count": profile.hit_count},
                )
            )

        abuse = profile.osint.get("abuseipdb") or {}
        score = abuse.get("abuseConfidenceScore")
        if isinstance(score, (int, float)) and score >= 25:
            findings.append(
                ScoreFinding(
                    category="canary",
                    code="canary_hitter_abuseipdb_high",
                    severity="high" if score >= 75 else "medium",
                    points=35 if score >= 75 else 18,
                    message=f"Canary hitter {profile.ip} has AbuseIPDB confidence {score}%.",
                    evidence={"ip": profile.ip, "abuseConfidenceScore": score},
                )
            )
        else:
            total_reports = abuse.get("totalReports")
            if isinstance(total_reports, int) and total_reports > 0:
                findings.append(
                    ScoreFinding(
                        category="canary",
                        code="canary_hitter_abuseipdb_reports",
                        severity="low",
                        points=10,
                        message=f"Canary hitter {profile.ip} has {total_reports} AbuseIPDB report(s).",
                        evidence={"ip": profile.ip, "totalReports": total_reports},
                    )
                )

    return findings


def build_threat_report(
    analysis: HeaderAnalysisResponse,
    osint: OSINTQueryResponse | None = None,
    *,
    investigation: CanaryInvestigationReport | None = None,
    include_source: bool = False,
) -> ThreatScoreReport:
    weights = CATEGORY_WEIGHTS_WITH_CANARY if investigation else CATEGORY_WEIGHTS

    identity = _identity_findings(analysis)
    headers = _header_findings(analysis)
    authentication = _auth_findings(analysis)
    infrastructure = _infrastructure_findings(analysis, osint)
    canary = _canary_findings(investigation)

    categories = [
        CategoryScore(
            name="identity",
            score=_category_score(identity),
            weight=weights["identity"],
            findings=identity,
        ),
        CategoryScore(
            name="headers",
            score=_category_score(headers),
            weight=weights["headers"],
            findings=headers,
        ),
        CategoryScore(
            name="authentication",
            score=_category_score(authentication),
            weight=weights["authentication"],
            findings=authentication,
        ),
        CategoryScore(
            name="infrastructure",
            score=_category_score(infrastructure),
            weight=weights["infrastructure"],
            findings=infrastructure,
        ),
    ]
    if investigation:
        categories.append(
            CategoryScore(
                name="canary",
                score=_category_score(canary),
                weight=weights["canary"],
                findings=canary,
            )
        )

    overall = round(sum(c.score * c.weight for c in categories))
    overall = _clamp_score(overall)

    all_findings = identity + headers + authentication + infrastructure + canary
    all_findings.sort(key=lambda f: f.points, reverse=True)
    top = all_findings[:5]

    return ThreatScoreReport(
        overall_score=overall,
        verdict=_verdict(overall),
        summary=_summary(overall, _verdict(overall), top),
        from_address=analysis.from_address,
        from_domain=analysis.from_domain,
        subject=analysis.subject,
        categories=categories,
        findings=all_findings,
        analysis=analysis if include_source else None,
        osint=osint if include_source else None,
        investigation=investigation if include_source else None,
    )
