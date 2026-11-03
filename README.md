# mailtimeline

Read email **headers only** from `.eml` and `.msg` files, turn them into a
human-readable timeline, explain SPF / DKIM / DMARC in plain English, flag
spoofing patterns (including reply-to mismatches), and export a JSON report.
100% offline. If you also run a local AI (Ollama by default), it can add a
plain-English summary too.

Built with the Python standard library only — no installs, no dependencies,
no network calls unless you opt in to the AI summary.

## New tool from Asdale Dynamics, LLC

mailtimeline is a beginner-friendly utility from **Asdale Dynamics, LLC**,
makers of *The Massive AI Manual* and the plain-English AI guides at
[dylanasdale.github.io](https://dylanasdale.github.io). Our tooling style is
local-first: everything happens on your machine and nothing is uploaded.

## What it does

- **Timeline** — every `Received:` hop is plotted oldest-first, including who
  sent it, who received it, the transport and (gap) delays over 1 hour.
- **Plain-English SPF/DKIM/DMARC** — parses `Authentication-Results` and
  translates each result into one friendly sentence ("SPF asks: did the
  machine that handed over this email have permission from the sending
  domain?").
- **Spoofing flags** — reply-to pointing outside the sender's domain, brand
  names in display names with mismatched domains, future dates, missing
  `Authentication-Results`, out-of-order `Received` hops, and more.
- **Verdict** — *appears legitimate*, *needs a closer look*, or *likely
  spoofed*, with the reason why.
- **JSON export** — `--json report.json` (or `--json -` for stdout); the
  machine-readable twin of the human report. Headers only — never the body.
- **Optional AI summary** — `--ai` posts a compact header summary (no body
  text) to any OpenAI-compatible endpoint. Default is local Ollama at
  `http://localhost:11434/v1` with model `llama3.2`.

## Quick start

```bash
# Works with any Python 3.10+, no installs needed:
python3 -m mailtimeline suspicious.eml

# Export a JSON report as well
python3 -m mailtimeline suspicious.eml --json report.json

# Quiet mode (JSON only), e.g. for scripting
python3 -m mailtimeline inbox.eml --quiet --json -
```

Optional local AI summary (make sure Ollama is running):

```bash
python3 -m mailtimeline suspicious.eml --ai
python3 -m mailtimeline suspicious.eml --ai --ai-url http://localhost:8080/v1 --model qwen2.5:3b
```

If the local model is not reachable, the tool tells you so and your rule-based
report is unaffected.

## Understanding the verdicts

| Verdict | Meaning in one breath |
|---|---|
| appears legitimate | DMARC (or DKIM + SPF) passed; patterns were clean |
| needs a closer look | nothing damning, but not confident either |
| likely spoofed | DMARC failed or multiple high-severity warnings |

Heuristics, not proof. When in doubt, do not click — ask a human.

## Privacy

- Header parsing, timeline, verdicts, JSON: **all on your machine, offline.**
- `--ai` is opt-in, and its data payload contains a header summary, never your
  message body or attachments. Set `MAILTIMELINE_API_KEY` only if your
  endpoint requires it (we never write keys anywhere).
- No telemetry, no accounts, no uploads, ever.

## Tests

```bash
python3 -m unittest discover -s mailtimeline/tests -v
```

`mailtimeline/samples/` ships sample emails (legitimate newsletter, PayPal
phishing, mailing-list forward, Outlook `.msg`) that the tests analyze.

## Known gaps

- `.msg` support is best-effort: it searches the Outlook property stream for
  the RFC-822 header block. Most modern Outlook exports work; exotic multipart
  `.msg` files might not.
- Verdicts are heuristic: a clean pass does not prove good intentions, and a
  flagged pattern does not prove fraud. It is education, not a security
  appliance.
- SPF/DKIM/DMARC live DNS lookups are out of scope on purpose: the tool trusts
  the `Authentication-Results` reported by the receiving mail server.
- No link checking or body attachment scanning: see other tools for that.

## License

MIT - see LICENSE. Copyright (c) 2026 Asdale Dynamics, LLC.
