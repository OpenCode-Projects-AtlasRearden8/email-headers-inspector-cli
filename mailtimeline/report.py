"""Compose the full human-readable report and the JSON export."""

from __future__ import annotations

import json
from dataclasses import asdict

from . import __version__
from .dmarc import AuthReport, hardest_mechanism, plain_english
from .flags import Verdict, analyze
from .timeline import Timeline, label
from .parser import ParsedEmail


def build_verdict(parsed: ParsedEmail, report: AuthReport, tl: Timeline) -> Verdict:
    return analyze(parsed, report, ordering_ok=tl.ordering_ok)


def _reason_slug(parsed: ParsedEmail, report: AuthReport, tl: Timeline) -> str:
    mech = hardest_mechanism(report) if report.present else "no-auth-results"
    bits = [mech]
    if not tl.ordering_ok:
        bits.append("received-out-of-order")
    if parsed.reply_to:
        bits.append("reply-to-present")
    if parsed.parse_notes:
        bits.append("parse-notes")
    return ",".join(bits)


def _auth_summary(report: AuthReport) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in report.mechanisms:
        key = m.mechanism + (f":{m.domain}" if m.domain and m.mechanism == "dkim" else "")
        out[key] = m.result
    return out


def _timeline_summaries(tl: Timeline) -> list[dict]:
    entries = []
    for ts_text, desc in tl.to_entries():
        entries.append({"when": ts_text, "event": desc})
    return entries


def analysis_dict(parsed: ParsedEmail, report: AuthReport, tl: Timeline, verdict: Verdict) -> dict:
    return {
        "tool": "mailtimeline",
        "version": __version__,
        "source_file": parsed.source,
        "format": "outlook-msg" if parsed.is_msg else "rfc822-eml",
        "subject": parsed.subject,
        "from": parsed.from_,
        "reply_to": parsed.reply_to or None,
        "to": parsed.to,
        "message_id": parsed.message_id,
        "date_header": parsed.date,
        "authentication": {
            "present": report.present,
            "authenticator": report.authenticator or None,
            "results": _auth_summary(report),
            "explain": plain_english(report, _reason_slug(parsed, report, tl)),
        },
        "timeline": _timeline_summaries(tl),
        "received_hops": len(parsed.received),
        "expected_hops_note": "received headers are ordered oldest first in the timeline",
        "flags": [
            {"level": f.level, "title": f.title, "detail": f.detail} for f in verdict.flags
        ],
        "verdict": {
            "label": verdict.label,
            "reason": verdict.reason,
        },
        "parse_notes": parsed.parse_notes,
        "attachments": parsed.attachments,
        "privacy": "headers analyzed locally; nothing was sent to any server (AI summary is opt-in)",
    }


def to_json(payload: dict, indent: int = 2) -> str:
    return json.dumps(payload, indent=indent, ensure_ascii=False)
