"""SPF, DKIM and DMARC: parse Authentication-Results and explain in plain English."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_RESULT_RE = re.compile(
    r"(?P<mech>spf|dkim|dmarc|arc)\s*=\s*(?P<res>[a-z\-]+)(?:\s*\((?P<comment>[^)]*)\))?"
    r"(?:\s+(?P<props>[^;]*))?",
    re.IGNORECASE,
)

_DISTRIBUTOR_RE = re.compile(r"^\s*([a-zA-Z0-9.\-]+?)\s*;", )

_PLAIN = {
    "spf": (
        "SPF asks a simple question: 'did the machine that handed over this email "
        "have permission from the sending domain to send it?' Every domain can "
        "publish a public list of the mail servers it allows. Getting your name "
        "on the list proves the server is allowed - not that the person using it "
        "is trustworthy."
    ),
    "dkim": (
        "DKIM is a wax seal on the envelope: the sending server signs the message "
        "with a secret key, and the domain publishes a public key that anyone can "
        "use to check the signature still matches. If it passes, the message was "
        "not altered in transit."
    ),
    "dmarc": (
        "DMARC is the boss who checks both previous reports: does the domain in "
        "the visible 'From:' line also survive the SPF/DKIM checks (alignment)? "
        "It is the only one that answers 'is this From: line really that domain?'"
    ),
    "arc": (
        "ARC is a chain-of-custody record: it preserves earlier SPF/DKIM/DMARC "
        "results when the message is forwarded, so good mail forwarded through "
        "mailing lists is not unfairly failed later."
    ),
}


@dataclass
class MechResult:
    mechanism: str  # spf|dkim|dmarc|arc
    result: str  # pass|fail|softfail|none|neutral|temperror|permerror|...
    domain: str = ""  # for spf: smtp.mailfrom; for dkim: header.d; dmarc: header.from
    selector: str = ""  # dkim header.a / header.s extras
    comment: str = ""
    plain: str = ""  # plain-English verdict sentence

    def display(self) -> str:
        line = f"{self.mechanism.upper()}: {self.result.upper()}"
        if self.domain:
            line += f" (domain: {self.domain})"
        return line


@dataclass
class AuthReport:
    authenticator: str = ""
    mechanisms: list[MechResult] = field(default_factory=list)
    present: bool = False

    def get(self, mechanism: str, domain: str = "") -> MechResult | None:
        for m in self.mechanisms:
            if m.mechanism == mechanism and (not domain or m.domain == domain):
                return m
        return None

    def any_result(self, mechanism: str, *results: str) -> bool:
        for m in self.mechanisms:
            if m.mechanism == mechanism and m.result.lower() in results:
                return True
        return False


_PLAIN_VERDICT = {
    "pass": "passed - the check succeeded.",
    "fail": "FAILED - the check says the evidence does not line up.",
    "softfail": "softfail - the domain says 'probably not allowed' (suspicious but not certain).",
    "none": "none - this check could not run at all (no evidence found for it).",
    "neutral": "neutral - the domain deliberately made this check inconclusive.",
    "temperror": "temporary error - a technical hiccup (retryable), not necessarily fraud.",
    "permerror": "permerror - a permanent setup error: the domain's records are broken or malformed.",
    "policy": "policy - the message violated a published policy.",
}


def _extract_property(prop_text: str, key_regexes: tuple[str, ...]) -> str:
    for rx in key_regexes:
        m = re.search(rx, prop_text, re.IGNORECASE)
        if m:
            value = m.group(1).strip().strip('"')
            return value
    return ""


def parse_authentication_results(lines: list[str]) -> AuthReport:
    report = AuthReport()
    if not lines:
        return report
    text = ";".join(lines)
    m = _DISTRIBUTOR_RE.match(lines[0])
    if m:
        report.authenticator = m.group(1)
    report.present = True
    for match in _RESULT_RE.finditer(text):
        mech = match.group("mech").lower()
        result = match.group("res").lower()
        props = match.group("props") or ""
        comment = (match.group("comment") or "").strip()
        domain = selector = ""
        if mech in ("spf", "dmarc"):
            domain = _extract_property(
                props, (r"smtp\.mailfrom=([^\s;]+)", r"header\.from=([^\s;]+)")
            )
        elif mech == "dkim":
            domain = _extract_property(props, (r"header\.d=([^\s;]+)",))
            selector = _extract_property(
                props,
                (r"header\.s=([^\s;]+)", r"header\.i=([^\s;]+)", r"header\.a=([^\s;]+)"),
            )
        report.mechanisms.append(
            MechResult(
                mechanism=mech,
                result=result,
                domain=domain,
                selector=selector,
                comment=comment,
                plain=_PLAIN_VERDICT.get(result, f"unknown result '{result}'."),
            )
        )
    return report


def hardest_mechanism(report: AuthReport) -> str:
    score = {"fail": 0, "softfail": 1, "none": 2, "permerror": 2, "neutral": 3}
    order = ["dmarc", "dkim", "spf", "arc"]
    worst, worst_score = "pass", 4
    for mech in order:
        entries = [m for m in report.mechanisms if m.mechanism == mech]
        if not entries:
            continue
        # jump straight to the worst entry for that mechanism
        entry_scores = [score.get(m.result.lower(), 4) for m in entries]
        mech_score = min(entry_scores)
        if mech_score < worst_score:
            worst = mech
            worst_score = mech_score
    return worst


def plain_english(report: AuthReport, reason: str = "unknown") -> list[str]:
    """Explain each mechanism and why 'reason' was picked, like a friend would."""
    lines = [f"Reasoning summary: {reason}."]
    for mech in ("dmarc", "dkim", "spf", "arc"):
        entries = [m for m in report.mechanisms if m.mechanism == mech]
        if not entries:
            lines.append(f"{mech.upper()}: no report found - plain meaning: {_PLAIN[mech]}")
            continue
        for entry in entries:
            lines.append(
                f"{entry.display()} - plain meaning: {_PLAIN[mech]} "
                f"This one {entry.plain}"
            )
    return lines
