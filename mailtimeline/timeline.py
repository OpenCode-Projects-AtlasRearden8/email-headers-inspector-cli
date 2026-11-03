"""Build a human-readable, chronological timeline from Received hops."""

from __future__ import annotations

import email.utils
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class Hop:
    index: int
    raw: str
    sender_host: str
    receiver_host: str
    protocol: str
    for_addr: str
    timestamp: str
    parsed_ts: datetime | None
    note: str = ""

    def description(self) -> str:
        parts = [self.sender_host or "(sender not stated)"]
        parts.append(f"received by {self.receiver_host or '(receiver not stated)'}")
        if self.protocol:
            parts.append(f"via {self.protocol}")
        if self.for_addr:
            parts.append(f"for {self.for_addr}")
        return "; ".join(parts)


@dataclass
class Timeline:
    hops: list[Hop] = field(default_factory=list)
    date_header: str = ""
    date_ts: datetime | None = None
    gaps: list[str] = field(default_factory=list)
    ordering_ok: bool = True

    def to_entries(self) -> list[tuple[str, str]]:
        """(time label, description) oldest -> newest for display."""
        entries = []
        if self.date_ts:
            entries.append((label(self.date_ts), "Message composed (Date header)"))
        for hop in self.hops:
            entries.append((label(hop.parsed_ts), hop.description()))
        return entries


def label(ts: datetime | None) -> str:
    if not ts:
        return "(time unknown)"
    return ts.strftime("%Y-%m-%d %H:%M:%S %z")


def _clean_host(text: str, limit: int = 80) -> str:
    text = text.strip().rstrip(";,")
    text = re.sub(r"\s+\((?:HELO|EHLO)[^)]*\)", "", text, flags=re.IGNORECASE)
    return text[:limit].strip()


_DATE_SPLIT = re.compile(r";\s*(?P<date>[^;]+)$")


def parse_received(raw: str) -> Hop:
    sender = receiver = protocol = for_addr = ""
    ts: datetime | None = None
    note = ""

    # Received headers end with "; <date>" (or no semicolon: localhost stamp)
    m = _DATE_SPLIT.search(raw)
    raw_date = ""
    head = raw
    if m:
        raw_date = m.group("date").strip()
        head = raw[: m.start()]

    head = head.strip()
    fm = re.search(r"^from\s+(\S+)", head, re.IGNORECASE)
    if fm:
        sender = _clean_host(fm.group(1))
    bm = re.search(r"\bby\s+(\S+)", head, re.IGNORECASE)
    if bm:
        receiver = _clean_host(bm.group(1))
    wm = re.search(r"\bwith\s+(\S+)", head, re.IGNORECASE)
    if wm:
        protocol = wm.group(1).lower().strip(",;")
    fm2 = re.search(r"\bfor\s+<([^>]+)>", head, re.IGNORECASE)
    if fm2:
        for_addr = fm2.group(1)

    if raw_date:
        try:
            ts = email.utils.parsedate_to_datetime(raw_date)
        except (TypeError, ValueError):
            ts = None
        if ts is not None and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    else:
        note = "no timestamp in Received header"

    return Hop(
        index=0,
        raw=raw,
        sender_host=sender,
        receiver_host=receiver,
        protocol=protocol,
        for_addr=for_addr,
        timestamp=raw_date,
        parsed_ts=ts,
        note=note,
    )


def build(parsed) -> Timeline:
    tl = Timeline()
    tl.date_header = parsed.date
    if parsed.date:
        try:
            dt = email.utils.parsedate_to_datetime(parsed.date)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            tl.date_ts = dt
        except (TypeError, ValueError, OverflowError):
            pass

    # Received headers are listed newest-first; reverse for chronology
    hops = [parse_received(r) for r in parsed.received]
    hops.reverse()
    for i, hop in enumerate(hops, start=1):
        hop.index = i
    tl.hops = hops

    timed = [h for h in hops if h.parsed_ts]
    if len(timed) >= 2:
        previous = timed[0].parsed_ts
        for hop in timed[1:]:
            delta = hop.parsed_ts - previous
            if delta < timedelta(0):
                tl.ordering_ok = False
            if delta > timedelta(hours=1):
                tl.gaps.append(
                    f"{delta.total_seconds() / 3600:.1f}h delay "
                    f"between hop {hop.index - 1} and hop {hop.index}"
                )
            previous = hop.parsed_ts
    return tl
