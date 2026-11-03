"""Optional AI summary via any OpenAI-compatible chat endpoint.

Default target is a local Ollama server (http://localhost:11434/v1).
Nothing is sent anywhere unless the user passes --ai. No API key is needed
for Ollama; if a key is set in the MAILTIMELINE_API_KEY environment variable
it is used, but the tool never writes secrets to disk or logs them.
"""

from __future__ import annotations

import json
import urllib.request


def build_prompt(parsed, analysis: dict) -> str:
    """Compact, privacy-preserving prompt: headers/events only, no body text."""
    subject = analysis.get("subject") or "(no subject)"
    timeline = "\n".join(
        f"  - {e['when']}: {e['event']}" for e in analysis.get("timeline", [])
    )
    flags = "\n".join(
        f"  - [{f['level']}] {f['title']}: {f['detail']}"
        for f in analysis.get("flags", [])
    ) or "  - none"
    auth = analysis.get("authentication", {}).get("results", {}) or {}
    auth_txt = ", ".join(f"{k}={v}" for k, v in auth.items()) or "no results"
    return (
        "You are an email-header triage assistant. Summarize this email's "
        "headers for a busy person in 5 short bullet points then a one-line "
        "verdict. Use plain English, never condescending. Do not invent facts "
        "beyond what is listed. No body text is included (headers only).\n\n"
        f"Subject: {subject}\n"
        f"From: {parsed.from_ or '(unknown)'}\n"
        f"Reply-To: {parsed.reply_to or '(none)'}\n"
        f"To: {parsed.to or '(unknown)'}\n"
        f"Authentication results: {auth_txt}\n"
        f"Received hops: {len(parsed.received)}\n"
        f"Timeline:\n{timeline or '  - (none)'}\n"
        f"Flags:\n{flags}\n"
        f"Rule-based verdict: {analysis.get('verdict', {}).get('label')}\n"
    )


def summarize(
    parsed, analysis: dict, url: str, model: str, timeout: float = 60.0,
    api_key: str = "",
) -> tuple[bool, str]:
    """POST to an OpenAI-compatible /chat/completions endpoint. Returns (ok, text)."""
    prompt = build_prompt(parsed, analysis)
    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You explain email security headers in plain, friendly English.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
    ).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    endpoint = url.rstrip("/")
    if not endpoint.endswith("/chat/completions"):
        endpoint += "/chat/completions"

    request = urllib.request.Request(
        endpoint, data=payload, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return False, (
            f"AI summary unavailable ({type(exc).__name__}: {exc}). "
            f"Checked endpoint: {endpoint} with model '{model}'. "
            "Is your local server running?"
        )
    try:
        text = data["choices"][0]["message"]["content"].strip()
        return True, text
    except (KeyError, IndexError, TypeError):
        return False, "AI server responded, but the reply format was unexpected."
