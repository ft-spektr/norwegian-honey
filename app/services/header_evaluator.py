"""Email raw-header and .eml parsing with anomaly detection."""

from __future__ import annotations

import email
import re
from email.message import Message
from email.utils import parseaddr
from pathlib import Path
from typing import Any

from app.models.analyze import (
    Anomaly,
    AnomalySeverity,
    AuthCheckResult,
    AuthResultStatus,
    HeaderAnalysisResponse,
    ReceivedHop,
)
from app.services.auth_checks import (
    enrich_auth_with_dns,
    lookup_dmarc_record,
    lookup_spf_record,
    parse_authentication_results,
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_DOMAIN_RE = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")


def _extract_domain(address: str | None) -> str | None:
    if not address:
        return None
    _, addr = parseaddr(address)
    if "@" in addr:
        return addr.rsplit("@", 1)[1].lower().strip(">")
    return None


def _parse_received_hop(index: int, raw: str) -> ReceivedHop:
    from_match = re.search(r"\bfrom\s+(\S+)", raw, re.IGNORECASE)
    by_match = re.search(r"\bby\s+(\S+)", raw, re.IGNORECASE)
    with_match = re.search(r"\bwith\s+(\S+)", raw, re.IGNORECASE)
    date_match = re.search(r";\s*(.+)$", raw)

    source_ip: str | None = None
    bracket_ip = re.search(r"\[([^\]]+)\]", raw)
    if bracket_ip:
        source_ip = bracket_ip.group(1)
    else:
        ipv4 = _IPV4_RE.search(raw)
        if ipv4:
            source_ip = ipv4.group(0)

    return ReceivedHop(
        index=index,
        raw=raw.strip(),
        from_host=from_match.group(1).strip("<>") if from_match else None,
        by_host=by_match.group(1).strip("<>") if by_match else None,
        with_protocol=with_match.group(1) if with_match else None,
        timestamp=date_match.group(1).strip() if date_match else None,
        source_ip=source_ip,
    )


def _get_header_values(msg: Message, name: str) -> list[str]:
    values: list[str] = []
    if name in msg:
        values.extend(msg.get_all(name, []))
    return [str(v) for v in values]


def _unique_sorted(items: list[str]) -> list[str]:
    return sorted({i.lower() for i in items if i})


def _detect_anomalies(
    *,
    from_domain: str | None,
    reply_to_domain: str | None,
    return_path_domain: str | None,
    x_originating_ip: str | None,
    received_hops: list[ReceivedHop],
    auth_results: list[AuthCheckResult],
    from_address: str | None,
    reply_to: str | None,
) -> list[Anomaly]:
    anomalies: list[Anomaly] = []

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        anomalies.append(
            Anomaly(
                code="reply_to_domain_mismatch",
                severity=AnomalySeverity.HIGH,
                message="Reply-To domain differs from From domain — common phishing indicator.",
                evidence={"from_domain": from_domain, "reply_to_domain": reply_to_domain},
            )
        )

    if return_path_domain and from_domain and return_path_domain != from_domain:
        anomalies.append(
            Anomaly(
                code="return_path_domain_mismatch",
                severity=AnomalySeverity.MEDIUM,
                message="Return-Path envelope domain does not match From domain.",
                evidence={"from_domain": from_domain, "return_path_domain": return_path_domain},
            )
        )

    for auth in auth_results:
        if auth.status in (AuthResultStatus.FAIL, AuthResultStatus.PERMERROR):
            anomalies.append(
                Anomaly(
                    code=f"{auth.mechanism}_failed",
                    severity=AnomalySeverity.HIGH if auth.mechanism == "dmarc" else AnomalySeverity.MEDIUM,
                    message=f"{auth.mechanism.upper()} authentication failed.",
                    evidence={"domain": auth.domain, "detail": auth.detail},
                )
            )

    if from_domain:
        spf_dns = lookup_spf_record(from_domain)
        dmarc_dns = lookup_dmarc_record(from_domain)
        if not spf_dns.get("found"):
            anomalies.append(
                Anomaly(
                    code="spf_record_missing",
                    severity=AnomalySeverity.LOW,
                    message=f"No SPF TXT record found for {from_domain}.",
                    evidence={"domain": from_domain},
                )
            )
        if not dmarc_dns.get("found"):
            anomalies.append(
                Anomaly(
                    code="dmarc_record_missing",
                    severity=AnomalySeverity.MEDIUM,
                    message=f"No DMARC record found for {from_domain}.",
                    evidence={"domain": from_domain},
                )
            )
        elif dmarc_dns.get("policy") == "none":
            anomalies.append(
                Anomaly(
                    code="dmarc_policy_none",
                    severity=AnomalySeverity.LOW,
                    message=f"DMARC policy is 'none' for {from_domain} — no enforcement.",
                    evidence={"domain": from_domain, "policy": "none"},
                )
            )

    hop_ips = [h.source_ip for h in received_hops if h.source_ip]
    if x_originating_ip and hop_ips and x_originating_ip not in hop_ips:
        anomalies.append(
            Anomaly(
                code="x_originating_ip_not_in_received",
                severity=AnomalySeverity.MEDIUM,
                message="X-Originating-IP does not appear in Received hop chain.",
                evidence={"x_originating_ip": x_originating_ip, "received_ips": hop_ips},
            )
        )

    # Private / bogon ranges in outermost hop suggest relay obfuscation
    if received_hops:
        first_ip = received_hops[0].source_ip
        if first_ip and _is_private_ip(first_ip):
            anomalies.append(
                Anomaly(
                    code="private_ip_in_first_hop",
                    severity=AnomalySeverity.MEDIUM,
                    message="First Received hop contains a private/reserved IP.",
                    evidence={"ip": first_ip},
                )
            )

    if from_address and reply_to and from_address.lower() != reply_to.lower():
        anomalies.append(
            Anomaly(
                code="reply_to_address_mismatch",
                severity=AnomalySeverity.MEDIUM,
                message="Reply-To address differs from From address.",
                evidence={"from": from_address, "reply_to": reply_to},
            )
        )

    return anomalies


def _is_private_ip(ip: str) -> bool:
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            second = int(parts[1]) if parts[1].isdigit() else -1
            return 16 <= second <= 31
    return ip.startswith("169.254.") or ip == "::1"


def _parse_message(msg: Message) -> HeaderAnalysisResponse:
    received_raw = _get_header_values(msg, "Received")
    received_hops = [_parse_received_hop(i, hop) for i, hop in enumerate(received_raw)]

    from_address = msg.get("From")
    reply_to = msg.get("Reply-To")
    return_path = msg.get("Return-Path")
    from_domain = _extract_domain(from_address)
    reply_to_domain = _extract_domain(reply_to)
    return_path_domain = _extract_domain(return_path)

    x_originating_ip: str | None = None
    for header_name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        val = msg.get(header_name)
        if val:
            ip_match = _IPV4_RE.search(val) or _IPV6_RE.search(val)
            if ip_match:
                x_originating_ip = ip_match.group(0)
                break

    auth_headers = _get_header_values(msg, "Authentication-Results")
    auth_results = parse_authentication_results(auth_headers)
    auth_results = enrich_auth_with_dns(auth_results, from_domain)

    # Collect entities for downstream OSINT
    all_header_text = "\n".join(f"{k}: {v}" for k, v in msg.items())
    extracted_ips = _unique_sorted(
        [x_originating_ip] if x_originating_ip else []
        + [h.source_ip for h in received_hops if h.source_ip]
        + _IPV4_RE.findall(all_header_text)
    )
    extracted_emails = _unique_sorted(_EMAIL_RE.findall(all_header_text))
    extracted_domains = _unique_sorted(
        [d for d in (_extract_domain(e) for e in extracted_emails) if d]
        + [from_domain, reply_to_domain, return_path_domain]
        + _DOMAIN_RE.findall(all_header_text)
    )
    extracted_domains = [d for d in extracted_domains if d and not d.endswith(".arpa")]

    anomalies = _detect_anomalies(
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        return_path_domain=return_path_domain,
        x_originating_ip=x_originating_ip,
        received_hops=received_hops,
        auth_results=auth_results,
        from_address=from_address,
        reply_to=reply_to,
    )

    return HeaderAnalysisResponse(
        message_id=msg.get("Message-ID"),
        from_address=from_address,
        from_domain=from_domain,
        reply_to=reply_to,
        reply_to_domain=reply_to_domain,
        return_path=return_path,
        return_path_domain=return_path_domain,
        subject=msg.get("Subject"),
        date=msg.get("Date"),
        x_originating_ip=x_originating_ip,
        received_hops=received_hops,
        authentication=auth_results,
        extracted_ips=extracted_ips,
        extracted_domains=extracted_domains,
        extracted_emails=extracted_emails,
        anomalies=anomalies,
    )


def parse_raw_email(raw: str) -> HeaderAnalysisResponse:
    """Parse a full RFC 822 message or headers-only blob."""
    msg = email.message_from_string(raw)
    return _parse_message(msg)


def parse_eml_file(path: Path) -> HeaderAnalysisResponse:
    """Parse an .eml file from disk."""
    content = path.read_text(encoding="utf-8", errors="replace")
    return parse_raw_email(content)


def parse_headers_only(raw_headers: str) -> HeaderAnalysisResponse:
    """Parse headers without a body (synthesizes minimal message)."""
    # Ensure blank line separator so email parser treats input as headers
    if not raw_headers.endswith("\n"):
        raw_headers += "\n"
    return parse_raw_email(raw_headers + "\n")
