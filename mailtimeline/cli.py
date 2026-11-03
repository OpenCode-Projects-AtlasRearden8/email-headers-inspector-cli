"""mailtimeline CLI - examine .eml/.msg headers offline and explain them simply.

Importable as module `mailtimeline.cli` and runnable via `python -m mailtimeline`.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, ai
from .dmarc import parse_authentication_results, plain_english
from .flags import analyze
from .parser import parse_file
from .report import _reason_slug, analysis_dict, to_json
from .render import render
from .timeline import build as build_timeline


def process_file(path: Path) -> tuple[dict | None, str | None, str | None]:
    """Analyze one file. Returns (analysis, rendered_text, error_message)."""
    try:
        parsed = parse_file(path)
    except ValueError as exc:
        return None, None, f"{path.name}: {exc}"
    except Exception as exc:  # defensive: never crash the whole run
        return None, None, f"{path.name}: unexpected {type(exc).__name__}: {exc}"

    if not parsed.headers:
        return None, None, f"{path.name}: no headers found (empty or unrelated file)"

    auth_report = parse_authentication_results(parsed.authentication_results)
    tl = build_timeline(parsed)
    slug = _reason_slug(parsed, auth_report, tl)
    verdict = analyze(parsed, auth_report, ordering_ok=tl.ordering_ok)
    verdict.auth_lines = plain_english(auth_report, slug)
    rendered = render(parsed, auth_report, tl, verdict, slug)
    analysis = analysis_dict(parsed, auth_report, tl, verdict)
    return analysis, rendered, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mailtimeline",
        description="Parse .eml/.msg headers into a timeline, plain-English "
        "SPF/DKIM/DMARC explainer, spoofing flags and a JSON report. Offline.",
    )
    parser.add_argument("files", nargs="+", type=Path, help=".eml or .msg files")
    parser.add_argument("--json", dest="json_path", type=Path, default=None,
                        help="write JSON report to this path (or --json - for stdout)")
    parser.add_argument("--ai", action="store_true",
                        help="add an AI summary (opt-in; uses the local endpoint)")
    parser.add_argument("--ai-url", default="http://localhost:11434/v1",
                        help="OpenAI-compatible base URL (default: Ollama)")
    parser.add_argument("--model", default="llama3.2",
                        help="chat model name (default: llama3.2)")
    parser.add_argument("--quiet", action="store_true", help="JSON/no text output")
    parser.add_argument("--version", action="version",
                        version=f"mailtimeline {__version__}")
    args = parser.parse_args(argv)

    outputs: list[dict] = []
    json_to_stdout = args.json_path is not None and str(args.json_path) == "-"

    for path in args.files:
        if not path.exists():
            _err(f"error: file not found: {path}", args.quiet)
            continue
        analysis, rendered, error = process_file(path)
        if error:
            _err(f"error: {error}", args.quiet)
            continue
        outputs.append(analysis)
        if not (args.quiet or json_to_stdout):
            print(rendered)
            print()

    files_ok = bool(outputs)

    if args.ai and files_ok:
        api_key = os.environ.get("MAILTIMELINE_API_KEY", "")
        for path, analysis in zip(args.files, outputs):
            parsed = parse_file(path)
            ok, text = ai.summarize(parsed, analysis, args.ai_url, args.model,
                                    api_key=api_key)
            if not args.quiet or json_to_stdout:
                print()
                print("== AI SUMMARY" + (" (unavailable)" if not ok else "") + " ==")
                print(text)

    if args.json_path is not None:
        payload = outputs if len(outputs) != 1 else outputs[0]
        text = to_json(payload)
        if json_to_stdout:
            print(text)
        else:
            try:
                args.json_path.write_text(text, encoding="utf-8")
                if not args.quiet:
                    print(f"JSON report written to {args.json_path}", file=sys.stderr)
            except OSError as exc:
                _err(f"error: could not write JSON: {exc}", args.quiet)
                return 1

    return 0 if files_ok else 1


def _err(message: str, quiet: bool) -> None:
    if not quiet:
        print(message, file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
