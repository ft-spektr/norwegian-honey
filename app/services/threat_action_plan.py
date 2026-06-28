"""Recommended user actions keyed to threat score and findings."""

from __future__ import annotations

from typing import Literal

from app.models.canary_investigation import CanaryInvestigationReport
from app.models.report import ScoreFinding, ThreatActionItem, ThreatActionPlan

Priority = Literal["immediate", "recommended", "optional"]

_PRIORITY_RANK: dict[str, int] = {"immediate": 0, "recommended": 1, "optional": 2}

_VERDICT_HEADLINES: dict[str, str] = {
    "critical": "Treat as active phishing or impersonation — act now.",
    "high": "Likely malicious or deceptive — do not trust this message without verification.",
    "moderate": "Suspicious signals present — verify the sender before replying or acting.",
    "low": "Few strong threat signals — routine email caution applies.",
}

_BASE_ACTIONS: dict[str, list[tuple[Priority, str, str]]] = {
    "critical": [
        (
            "immediate",
            "Do not reply, click links, or open attachments from this message.",
            "Score indicates strong phishing or impersonation indicators.",
        ),
        (
            "immediate",
            "Quarantine the message and report it to your security or IT team with the full .eml file.",
            "Preserves headers for investigation and blocking.",
        ),
        (
            "immediate",
            "Block the sender address and any impersonated domains at your mail gateway.",
            "Stops repeat delivery from the same campaign.",
        ),
        (
            "recommended",
            "If you already interacted: change passwords, enable MFA, and monitor financial accounts.",
            "Credential or data theft is a common follow-on risk.",
        ),
        (
            "recommended",
            "Preserve analysis and threat-report JSON as evidence for your security team.",
            "Supports incident response and pattern tracking.",
        ),
        (
            "optional",
            "Consider reporting to your national CERT or anti-phishing service.",
            "Helps broader takedown and awareness efforts.",
        ),
    ],
    "high": [
        (
            "immediate",
            "Do not click links, open attachments, or act on requests in this email.",
            "Multiple independent suspicious signals were detected.",
        ),
        (
            "immediate",
            "Verify any claim via a known channel — official website, CRM, or phone directory. Never use Reply-To or links in this message.",
            "Impersonation often relies on you replying in-thread.",
        ),
        (
            "recommended",
            "Mark as spam or phishing in your mail client and alert security if this arrived at a work address.",
            "Improves filtering and gives your team early warning.",
        ),
        (
            "recommended",
            "Search for the purported organization independently; do not trust display names or Gmail local parts.",
            "Business-name-on-free-webmail is a common recruiter scam pattern.",
        ),
        (
            "optional",
            "Save the .eml and run a full threat report if you have not already.",
            "Documents the case if the sender follows up.",
        ),
    ],
    "moderate": [
        (
            "recommended",
            "Verify sender identity out-of-band before scheduling calls, sharing a résumé, or sending credentials.",
            "Moderate scores often reflect impersonation without hard proof of malice.",
        ),
        (
            "recommended",
            "Avoid clicking embedded links — open the service manually in your browser if needed.",
            "Reduces drive-by credential harvesting risk.",
        ),
        (
            "recommended",
            "Check whether the display name matches a real contact at the claimed organization.",
            "Identity findings drove part of this score.",
        ),
        (
            "optional",
            "Keep the message for review if you are monitoring a recurring campaign.",
            "Useful when multiple similar messages arrive.",
        ),
        (
            "optional",
            "Embed canary trap links in future replies to detect whether the sender opens them.",
            "Norwegian Honey portfolio/pixel traps confirm active engagement.",
        ),
    ],
    "low": [
        (
            "optional",
            "Apply standard caution — confirm unexpected requests before acting.",
            "No urgent indicators from headers or OSINT alone.",
        ),
        (
            "optional",
            "No immediate action required based on current signals.",
            "Re-score if new messages arrive or OSINT context changes.",
        ),
    ],
}


def _finding_codes(findings: list[ScoreFinding]) -> set[str]:
    return {finding.code for finding in findings}


def _has_suspicious_canary_pattern(findings: list[ScoreFinding]) -> bool:
    codes = _finding_codes(findings)
    return bool(
        codes
        & {
            "canary_suspicious_hit_pattern",
            "canary_human_then_automation",
            "canary_multi_country_ops",
        }
    )


def _has_canary_hits(investigation: CanaryInvestigationReport | None) -> bool:
    return investigation is not None and investigation.hit_count > 0


def _canary_roles(investigation: CanaryInvestigationReport | None) -> set[str]:
    if investigation is None:
        return set()
    return {profile.role for profile in investigation.ip_profiles}


def _append(
    items: list[ThreatActionItem],
    seen: set[str],
    priority: Priority,
    action: str,
    reason: str | None = None,
) -> None:
    key = action.strip().lower()
    if key in seen:
        return
    seen.add(key)
    items.append(ThreatActionItem(priority=priority, action=action, reason=reason))


def build_action_plan(
    *,
    verdict: str,
    overall_score: int,
    findings: list[ScoreFinding],
    investigation: CanaryInvestigationReport | None = None,
) -> ThreatActionPlan:
    codes = _finding_codes(findings)
    items: list[ThreatActionItem] = []
    seen: set[str] = set()

    for priority, action, reason in _BASE_ACTIONS.get(verdict, _BASE_ACTIONS["low"]):
        _append(items, seen, priority, action, reason)

    if codes & {
        "business_name_on_free_webmail",
        "domain_like_local_part_on_webmail",
        "reply_to_domain_mismatch",
    }:
        _append(
            items,
            seen,
            "recommended",
            "Look up the organization on its official domain — not via addresses or links in this email.",
            "Identity signals suggest possible brand impersonation.",
        )

    if "reply_to_domain_mismatch" in codes or "return_path_domain_mismatch" in codes:
        _append(
            items,
            seen,
            "immediate" if verdict in {"critical", "high"} else "recommended",
            "Do not reply to this thread for verification; Reply-To or envelope domain does not match From.",
            "Mismatched routing domains are a common phishing technique.",
        )

    if _has_suspicious_canary_pattern(findings):
        roles = _canary_roles(investigation)
        _append(
            items,
            seen,
            "immediate",
            "Canary hit pattern suggests organized scam infrastructure — do not engage further or send personal data.",
            "Human consumer IP followed by cloud/automation is not typical of a lone legitimate recruiter.",
        )
        _append(
            items,
            seen,
            "recommended",
            "Export and preserve canary investigation JSON (`make prod-canary-export`) and attach it to your security report.",
            "Includes timeline, IP profiles, and OSINT on hitters.",
        )
        if "human_likely" in roles and "automation_likely" in roles:
            _append(
                items,
                seen,
                "recommended",
                "Document the human-then-cloud hit pattern — consistent with scam operators (manual click plus backend fetch).",
                "Useful context for incident responders and law enforcement.",
            )
        elif "automation_likely" in roles and "human_likely" not in roles:
            _append(
                items,
                seen,
                "optional",
                "Single cloud/automation hit may be a mail link scanner — still treat the email as untrusted.",
                "Lower confidence of a live human operator on the other end.",
            )
    elif _has_canary_hits(investigation):
        _append(
            items,
            seen,
            "optional",
            "Canary recorded that the link was opened — this alone does not prove malice; review hit patterns in investigation.json.",
            "Any recipient who clicks the trap will generate a hit.",
        )

    if verdict in {"critical", "high"} and overall_score >= 55:
        _append(
            items,
            seen,
            "recommended",
            "Warn colleagues if this is a recruiter or vendor impersonation targeting your industry.",
            "These campaigns are often sent in parallel to many targets.",
        )

    headline = _VERDICT_HEADLINES.get(verdict, _VERDICT_HEADLINES["low"])
    if _has_suspicious_canary_pattern(findings) and verdict in {"high", "critical"}:
        headline = f"{headline} Canary hit pattern supports active scam infrastructure."

    items.sort(key=lambda item: (_PRIORITY_RANK[item.priority], item.action))
    return ThreatActionPlan(headline=headline, actions=items)
