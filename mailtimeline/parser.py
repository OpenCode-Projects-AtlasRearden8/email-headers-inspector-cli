"""Parse .eml and .msg files into a normalized header view.

Headers only: the body is inspected just enough to know whether one exists
and which attachments are named; body text is never extracted or analyzed.
"""

from __future__ import annotations

import email
import email.header
import email.policy
import gzip
from dataclasses import dataclass, field
from pathlib import Path

from . import msgfile


@dataclass
class ParsedEmail:
    source: str
    is_msg: bool
    headers: list[tuple[str, str]]
    subject: str
    from_: str
    sender: str
    reply_to: str
    to: str
    cc: str
    date: str
    message_id: str
    authentication_results: list[str]
    received: list[str]
    body_present: bool
    attachments: list[str] = field(default_factory=list)
    parse_notes: list[str] = field(default_factory=list)


_ADDRESS_HEADERS = ("from", "sender", "reply-to", "to", "cc", "bcc")


def _decode_header(raw) -> str:
    """Best-effort decode of a raw header value into a plain string."""
    try:
        return str(raw)
    except Exception:
        try:
            return "".join(
                s
                for s, _ in email.header.decode_header(raw or "")
                if isinstance(s, str)
            )
        except Exception:
            return str(raw or "")


def _to_parsed(source: str, msg, is_msg: bool) -> ParsedEmail:
    headers: list[tuple[str, str]] = []
    lower_seen: dict[str, int] = {}
    for key, val in msg.items():
        text = _decode_header(val).strip()
        headers.append((key, text))
        lower_seen[key.lower()] = lower_seen.get(key.lower(), 0) + 1

    def first(name: str) -> str:
        for key, val in headers:
            if key.lower() == name:
                return val
        return ""

    auth_results = [v for k, v in headers if k.lower() == "authentication-results"]
    received = [v for k, v in headers if k.lower() == "received"]
    subject = first("subject")

    attachments: list[str] = []
    body_present = False
    try:
        for part in msg.walk():
            ctype = str(part.get("Content-Type", "")).lower()
            cd = str(part.get("Content-Disposition", "")).lower()
            if part.is_multipart():
                continue
            if "attachment" in cd or ("filename" in cd or "filename" in ctype):
                fn = _decode_header(part.get_filename() or "").strip()
                attachments.append(fn or "(unnamed attachment)")
            elif ctype.startswith(("text/plain", "text/html")) or not ctype:
                body_present = True
    except Exception as exc:  # best-effort only
        attachments.append(f"(body scan error: {type(exc).__name__})")

    notes: list[str] = []
    for name in _ADDRESS_HEADERS:
        if lower_seen.get(name, 0) > 1:
            notes.append(f"multiple '{name}' headers present")

    return ParsedEmail(
        source=source,
        is_msg=is_msg,
        headers=headers,
        subject=subject,
        from_=first("from"),
        sender=first("sender"),
        reply_to=first("reply-to"),
        to=first("to"),
        cc=first("cc"),
        date=first("date"),
        message_id=first("message-id"),
        authentication_results=auth_results,
        received=received,
        body_present=body_present,
        attachments=attachments,
        parse_notes=notes,
    )


def parse_eml_bytes(data: bytes, source: str) -> ParsedEmail:
    msg = email.message_from_bytes(data, policy=email.policy.compat32)
    return _to_parsed(source, msg, is_msg=False)


def parse_file(path: Path) -> ParsedEmail:
    """Parse a .eml, .eml.gz or .msg file from disk."""
    path = Path(path)
    suffix = path.suffix.lower()
    try:
        if suffix == ".msg":
            data = path.read_bytes()
            parsed = msgfile.parse_msg(data, path.name, _to_parsed)
            if parsed is None:
                raise ValueError(
                    "no RFC-822 header block found in this .msg file "
                    "(only modern Outlook-exported .msg files are supported)"
                )
            return parsed
        if suffix == ".gz":
            with gzip.open(path, "rb") as f:
                data = f.read()
        else:
            data = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"could not read file: {exc}") from exc
    return parse_eml_bytes(data, path.name)
