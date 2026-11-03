"""Render the analysis as a friendly plain-text report."""

from __future__ import annotations

import textwrap

from .parser import ParsedEmail


def render(parsed: ParsedEmail, report, tl, verdict, reason_slug: str) -> str:
    width = 78
    out: list[str] = []
    divider = "=" * width

    out.append(divider)
    out.append(f"MAILTIMELINE - header analysis for: {parsed.source}")
    out.append(divider)

    out.append("Subject: " + (parsed.subject or "(no subject)"))
    out.append("From: " + (parsed.from_ or "(unknown)"))
    out.append("To: " + (parsed.to or "(unknown)"))
    if parsed.reply_to:
        out.append("Reply-To: " + parsed.reply_to)
    if parsed.message_id:
        out.append("Message-ID: " + parsed.message_id)
    if parsed.parse_notes:
        for note in parsed.parse_notes:
            out.append(f"Note: {note}")
    out.append("")

    out.append("Timeline (oldest first):")
    entries = tl.to_entries()
    if not entries:
        out.append("  (no time information found)")
    for i, (when, desc) in enumerate(entries, 1):
        out.append(_wrap_item(f"{i}. [{when}] {desc}", width))
    if tl.gaps:
        for gap in tl.gaps:
            out.append(f"  (gap: {gap})")
    out.append("")

    out.append("Authentication, in plain English:")
    lines = verdict.auth_lines
    if not lines and report.present:
        lines = _plain_lines(report, reason_slug)
    for line in lines:
        out.append(_wrap_item(line, width, hanging="  "))
    out.append("")

    out.append(verdict.as_text())
    out.append("")

    if parsed.attachments:
        out.append("Attachments (names only): " + ", ".join(parsed.attachments))
        out.append("")

    out.append(divider)
    out.append(
        "This tool reads headers only, entirely offline. "
        "Verdicts are heuristic advice, not proof."
    )
    out.append(divider)
    return "\n".join(out)


def _plain_lines(report, reason_slug: str) -> list[str]:
    from .dmarc import plain_english

    return plain_english(report, reason_slug)


def _wrap_item(text: str, width: int, hanging: str = "   ") -> str:
    first = hanging.replace(" ", "", 1)
    wrapped = textwrap.wrap(
        text,
        width=width,
        initial_indent="",
        subsequent_indent=hanging,
    )
    if len(wrapped) > 1:
        wrapped = [wrapped[0]] + wrapped[1:]
        wrapped[0] = first + " " + wrapped[0]
    return "\n".join(wrapped)
