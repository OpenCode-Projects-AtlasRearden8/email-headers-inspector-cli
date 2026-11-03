# STATUS.md - mailtimeline

Updated: 2026-11-03

## What was built

`mailtimeline` - an offline CLI that parses `.eml` / `.msg` headers into a
human-readable timeline with plain-English SPF/DKIM/DMARC explanations,
spoofing-pattern flags and verdicts, plus a JSON export and an optional
AI summary through any OpenAI-compatible endpoint (local Ollama by default).

- `mailtimeline/parser.py` - .eml/.eml.gz parsing via stdlib `email`; headers
  only, body is never extracted for analysis
- `mailtimeline/msgfile.py` - best-effort `.msg` support: scans the Outlook
  property stream for the RFC-822 header block (UTF-16LE aware)
- `mailtimeline/timeline.py` - `Received:` hops parsed and ordered oldest
  first, with gap detection (>1 hour delays) and out-of-order detection
- `mailtimeline/dmarc.py` - parses `Authentication-Results` and explains each
  result in plain English ("SPF asks: did the machine that sent this have
  permission from that domain?")
- `mailtimeline/flags.py` - spoofing patterns: reply-to outside the From:
  domain (downgraded for mailing lists), brand impersonation in display names,
  envelope/From mismatch, future Date, missing Authentication-Results,
  DKIM-fail-with-SPF-pass, reversed Received order
- `mailtimeline/flags.py (analyze)` - verdict: appears legitimate / needs a
  closer look / likely spoofed, with reasoning
- `mailtimeline/report.py` - JSON report structure (headers only; never body)
- `mailtimeline/ai.py` - optional `--ai` summary, opt-in only, header summary
  only (no body/attachments), default endpoint Ollama `localhost:11434/v1`
- `mailtimeline/render.py` - friendly 78-column text report
- `mailtimeline/cli.py` / `__main__.py` - argparse CLI
- `mailtimeline/samples/` - sample legitimate newsletter, PayPal-style
  phishing, mailing-list forward, and a synthesized .msg
- `mailtimeline/tests/` - 25 tests with standard library `unittest`

## How to run it

```bash
python3 -m mailtimeline message.eml                 # text report
python3 -m mailtimeline message.msg                 # Outlook .msg (best-effort)
python3 -m mailtimeline message.eml --json out.json # also export JSON
python3 -m mailtimeline message.eml --quiet --json -  # JSON to stdout only
python3 -m mailtimeline message.eml --ai            # optional local AI summary
python3 -m mailtimeline message.eml --ai --ai-url http://localhost:11434/v1 --model llama3.2
```

Python 3.10+; zero third-party dependencies; nothing leaves the machine
unless you pass `--ai`.

## Verification results

- `python3 -m unittest discover -s mailtimeline/tests` - **25/25 pass**
- All modules compile under `python3 -W error` (no import warnings)
- CLI exercised end-to-end on all four samples:
  - `legitimate.eml` -> verdict "appears legitimate", DMARC/DKIM/SPF explained, timeline 4 events
  - `phishing.eml` -> verdict "likely spoofed" with high flags for reply-to mismatch and brand impersonation
  - `club-forward.eml` -> verdict "needs a closer look" (weak auth evidence, list reply-to noted as normal)
  - `sample.msg` -> headers recovered from the .msg property stream, DMARC pass verdict
- `--json` to file and stdout verified to produce valid parseable JSON
- AI summary path verified against a stub OpenAI-compatible HTTP server and against a dead endpoint (graceful failure message)
- Missing/empty files handled with readable errors; exit code 1

## Known gaps

- `.msg` support is best-effort: relies on finding the RFC-822 header block in
  the property stream; multipart/decompressed edge cases may fail. Tests
  cover a synthesized UTF-16LE sample, not real .msg files exported by
  Outlook (none available offline).
- DKIM/SPF/DMARC live DNS verification is deliberately out of scope; the tool
  trusts `Authentication-Results` reported by receiving mail servers.
- Heuristic verdicts cannot prove fraud; brand-impersonation matching uses a
  keyword list and will miss novel brands.
- Chinese/RTL encoded display names are not deeply tested.
- Link checking and body analysis are out of scope by design.

## Privacy statement

Header parsing, timelines, verdicts and JSON export run fully offline on the
local machine. The optional `--ai` summary sends only a compact header
summary (subject/from/reply-to/dates/flags - never body text or attachments)
to the endpoint the user chooses. No keys or secrets are stored by the tool;
`MAILTIMELINE_API_KEY` is read from the environment only if set.
