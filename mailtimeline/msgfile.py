"""Best-effort header extraction from Outlook .msg files.

.msg is a Compound File Binary (OLE) container. One property,
PR_TRANSPORT_MESSAGE_HEADERS (0x007D), usually stores the full RFC-822
header block as UTF-16 text. We scan the raw bytes for header-like runs in
both UTF-16LE and single-byte encodings and feed the recovered block to the
same parser used for .eml. Fully offline; this is best-effort and the report
says so.
"""

from __future__ import annotations

import email
import email.policy
import re

_HEADER_START = re.compile(
    r"^(Received|Delivered-To|Return-Path|Authentication-Results|ARC-"
    r"|DKIM-Signature|DKIM-Status|DomainKey-Status|DMARC|From|Sender|Reply-To"
    r"|To|Cc|Date|Subject|Message-ID|List-Id|List-Unsubscribe|X-[A-Za-z0-9-]+):",
    re.IGNORECASE,
)


def _candidate_texts(data: bytes) -> list[str]:
    texts = []
    for enc in ("utf-16-le", "latin-1"):
        try:
            texts.append(data.decode(enc, errors="ignore"))
        except Exception:  # pragma: no cover - decode with ignore rarely raises
            pass
    return texts


def _extract_header_block(text: str) -> str | None:
    lines = text.splitlines()
    best: list[str] | None = None
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if _HEADER_START.match(line.strip()):
            block = [line]
            j = i + 1
            while j < n:
                nxt = lines[j]
                if not nxt.strip():
                    # one blank line may separate header lines inside the
                    # property stream; allow it but do not accumulate past it
                    lookahead = j + 1
                    if lookahead < n and _HEADER_START.match(lines[lookahead].strip()):
                        j += 1
                        continue
                    break
                if nxt[:1] in (" ", "\t") or _HEADER_START.match(nxt.strip()):
                    block.append(nxt)
                    j += 1
                else:
                    break
            # only treat long, structured runs as headers (noise filter)
            real = sum(1 for l in block if _HEADER_START.match(l.strip()))
            if real >= 3 and (best is None or len(block) > len(best)):
                best = block
            i = j
        else:
            i += 1
    if best is None:
        return None
    return "\n".join(best)


def extract_msg_headers(path_bytes: bytes) -> str | None:
    """Return the recovered header block text, if any."""
    for text in _candidate_texts(path_bytes):
        block = _extract_header_block(text)
        if block:
            return block
    return None


def parse_msg(data: bytes, source: str, to_parsed) -> object:
    """Parse raw .msg bytes; `to_parsed` builds the ParsedEmail from a message."""
    # convenience header block even if extraction fails, so callers get structure
    block = extract_msg_headers(data)
    if not block:
        return None
    msg = email.message_from_string(block, policy=email.policy.compat32)
    parsed = to_parsed(source, msg, is_msg=True)
    parsed.parse_notes.append(
        "Outlook .msg: headers recovered best-effort from the PR_TRANSPORT_MESSAGE_HEADERS property"
    )
    return parsed
