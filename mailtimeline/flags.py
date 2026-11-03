"""Spoofing patterns and an overall verdict, in plain English."""

from __future__ import annotations

import email.utils
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .dmarc import AuthReport

# brand/domain pairs used for display-name impersonation checks
_BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "outlook": "microsoft.com",
    "office": "microsoft.com",
    "apple": "apple.com",
    "icloud": "apple.com",
    "google": "google.com",
    "gmail": "google.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "facebook.com",
    "linkedin": "linkedin.com",
    "bank": "",
    "irs": "",
    "coinbase": "coinbase.com",
    "bloomberg": "bloomberg.com",
    "chase": "chase.com",
    "wells": "wellsfargo.com",
}

_FREE_PROVIDERS = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}

_SUSPICIOUS_REPLY_WORDS = (
    "confirm",
    "verify",
    "secure",
    "update",
    "account",
    "login",
    "billing",
    "support",
)

_DOMAIN_LIKE = re.compile(r"\b([a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.[a-z]{2,})\b", re.IGNORECASE)


@dataclass
class Flag:
    level: str  # "high" | "medium" | "low" | "info"
    title: str
    detail: str

    def as_line(self) -> str:
        icon = {"high": "!!", "medium": " !", "low": " .", "info": "=="}[self.level]
        return f"[{icon}] {self.title} - {self.detail}"


@dataclass
class Verdict:
    label: str  # "appears legitimate" | "needs a closer look" | "likely spoofed"
    reason: str
    flags: list[Flag] = field(default_factory=list)
    auth_lines: list[str] = field(default_factory=list)

    def as_text(self) -> str:
        out = [f"VERDICT ({self.label}): {self.reason}"]
        if self.flags:
            out.append("")
            out.append("Flagged patterns:")
            out.extend("  " + f.as_line() for f in self.flags)
        else:
            out.append("No spoofing patterns flagged.")
        return "\n".join(out)


def _domain_of(address: str) -> str:
    try:
        _, addr = email.utils.parseaddr(address)
        if "@" in addr:
            return addr.rsplit("@", 1)[1].lower().strip().rstrip(">")
    except Exception:
        pass
    return ""


def _display_name(address: str) -> str:
    try:
        name, _ = email.utils.parseaddr(address)
    except Exception:
        return ""
    return name.strip()


def check_reply_to(parsed, report: AuthReport | None = None) -> list[Flag]:
    from_header = parsed.from_
    reply_to = parsed.reply_to
    flags: list[Flag] = []
    if not reply_to:
        return flags
    from_domain = _domain_of(from_header)
    reply_list = [d for _, addr in email.utils.getaddresses([reply_to]) if (d := _domain_of(addr))]
    if not reply_list:
        return flags
    reply_domain = reply_list[0]
    is_list = any(k.lower() == "list-id" for k, _ in parsed.headers)
    if from_domain and reply_domain and reply_domain != from_domain:
        if is_list:
            flags.append(
                Flag(
                    level="low",
                    title="Reply-To points at the mailing list (normal)",
                    detail=(
                        f"From: says <{from_domain}> and replies go to "
                        f"'{reply_domain}'. With a List-Id header present this is "
                        "standard mailing-list behaviour, not a scam."
                    ),
                )
            )
        else:
            severity = "high"
            reasons = []
            if reply_domain.endswith((".top", ".xyz", ".click", ".info", ".ru")):
                reasons.append(f"the reply domain '{reply_domain}' uses a pattern common in phishing")
            if any(w in reply_domain for w in _SUSPICIOUS_REPLY_WORDS):
                reasons.append("it contains urgency/inbox keywords")
            extra = f" ({'; '.join(reasons)})" if reasons else ""
            flags.append(
                Flag(
                    level=severity,
                    title="Reply-To points somewhere else",
                    detail=(
                        f"'From:' says <{from_domain}>, but replies would go to "
                        f"'{reply_domain}'. Filters validate 'From:', not replies{extra}. "
                        "Double-check before replying; scammers love this trick."
                    ),
                )
            )
    if len(reply_list) > 1:
        flags.append(
            Flag(
                level="medium",
                title="Multiple Reply-To addresses",
                detail="One reply would fan out to several inboxes - unusual for normal mail.",
            )
        )
    return flags


def check_display_name(from_header: str) -> list[Flag]:
    flags: list[Flag] = []
    name = _display_name(from_header)
    from_domain = _domain_of(from_header)
    if not name or not from_domain:
        return flags
    for brand, domain in _BRAND_DOMAINS.items():
        if re.search(rf"\b{brand}\b", name, re.IGNORECASE):
            known = bool(domain) and (
                from_domain == domain or from_domain.endswith("." + domain)
            )
            if not known:
                flags.append(
                    Flag(
                        level="high",
                        title="Brand name in display name, unfamiliar domain",
                        detail=(
                            f"The display name references '{name[:60]}' but mail came "
                            f"from '{from_domain}'. Real companies send from their own domain."
                        ),
                    )
                )
                break
    # generic: display name contains a different, embedded domain
    embedded = _DOMAIN_LIKE.findall(name)
    for dom in embedded:
        if dom.lower() != from_domain:
            flags.append(
                Flag(
                    level="medium",
                    title="Display name contains a different domain",
                    detail=(
                        f"'{dom}' appears inside the display name but the message "
                        f"really comes from '{from_domain}'."
                    )
                )
            )
            break
    return flags


def check_envelope_alignment(parsed, report: AuthReport) -> list[Flag]:
    flags: list[Flag] = []
    return_path = ""
    for key, val in parsed.headers:
        if key.lower() == "return-path":
            return_path = val.strip().strip("<>")
            break
    from_domain = _domain_of(parsed.from_)
    envelope_domain = _domain_of(return_path)
    if from_domain and envelope_domain and from_domain != envelope_domain:
        # mailing lists legitimately use a list envelope; note it
        list_like = any(k.lower() == "list-id" for k, _ in parsed.headers)
        flags.append(
            Flag(
                level="low" if list_like else "medium",
                title="Envelope domain differs from From:",
                detail=(
                    f"Return-Path is '{envelope_domain}', From: says '{from_domain}'. "
                    + ("Common for mailing lists, which may be fine." if list_like else "Known spammers use this gap.")
                ),
            )
        )
    return flags


def check_received_anomalies(parsed) -> list[Flag]:
    flags: list[Flag] = []
    if parsed.date:
        try:
            dt = email.utils.parsedate_to_datetime(parsed.date)
            now = datetime.now(timezone.utc)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if (dt - now).total_seconds() > 86400:
                flags.append(
                    Flag(
                        level="high",
                        title="Date header is in the future",
                        detail=f"Claimed date '{parsed.date}' is more than a day ahead - spoofed dates fool sorting and news-triage.",
                    )
                )
        except (TypeError, ValueError, OverflowError):
            pass
    if len(parsed.received) == 0:
        flags.append(
            Flag(
                level="medium",
                title="No Received headers",
                detail="Real mail in transit almost always carries Received hops; their absence means hand-crafted or re-sent messages.",
            )
        )
    return flags


def check_auth_consistency(parsed, report: AuthReport) -> list[Flag]:
    flags: list[Flag] = []
    if not report.present:
        flags.append(
            Flag(
                level="medium",
                title="No Authentication-Results header",
                detail="No mail server reported SPF/DKIM/DMARC, so we cannot confirm the sender; treat as unverified.",
            )
        )
        return flags
    if parsed.is_msg:
        # .msg best-effort: be gentle
        return flags
    if report.any_result("dkim", "fail") and report.any_result("spf", "pass"):
        flags.append(
            Flag(
                level="medium",
                title="DKIM failed but SPF passed",
                detail="Envelope looks fine but the signature check failed - content may have been altered in transit.",
            )
        )
    if report.any_result("dmarc", "fail"):
        flags.append(
            Flag(
                level="high",
                title="DMARC failed",
                detail="The 'From:' domain does not line up with the authenticated domain - the classic spoofing setup.",
            )
        )
    return flags


def analyze(parsed, report: AuthReport, ordering_ok: bool = True) -> Verdict:
    flags: list[Flag] = []
    flags += check_reply_to(parsed)
    flags += check_display_name(parsed.from_)
    flags += check_envelope_alignment(parsed, report)
    flags += check_received_anomalies(parsed)
    flags += check_auth_consistency(parsed, report)
    if not ordering_ok:
        flags.append(
            Flag(
                level="medium",
                title="Received dates out of order",
                detail="Hops are not in chronological order - headers may be forged to fake the route.",
            )
        )

    high = [f for f in flags if f.level == "high"]
    medium = [f for f in flags if f.level == "medium"]

    # verdict logic: DMARC pass is the strongest signal of legitimacy
    dmarc_pass = report.any_result("dmarc", "pass")
    dmarc_fail = report.any_result("dmarc", "fail")
    spf_pass = report.any_result("spf", "pass")
    dkim_pass = report.any_result("dkim", "pass")

    if dmarc_fail:
        label = "likely spoofed"
        reason = "DMARC failed: the visible From: domain does not match the domain the mail was actually authenticated as."
    elif high and not dmarc_pass:
        label = "likely spoofed"
        reason = "Multiple high-severity spoofing patterns (see flags) with no DMARC pass to restore trust."
    elif high:
        label = "needs a closer look"
        reason = "DMARC passed, but there are high-severity warnings worth checking before you trust it."
    elif dmarc_pass or (dkim_pass and spf_pass):
        label = "appears legitimate"
        reason = "DMARC (or DKIM + SPF) passed and nothing suspicious was flagged."
    elif medium:
        label = "needs a closer look"
        reason = "No strong authentication evidence plus some medium-severity warnings (see flags)."
    else:
        label = "needs a closer look"
        reason = "Not enough authentication evidence to call it safe either way."

    if dmarc_pass and label == "appears legitimate":
        reason = "DMARC passed: the visible From: domain matches what the mail server verified, and no spoofing patterns were flagged."
    return Verdict(label=label, reason=reason, flags=flags)
