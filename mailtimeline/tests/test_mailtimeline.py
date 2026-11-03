import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SAMPLES = HERE.parent / "samples"

sys.path.insert(0, str(HERE.parent))

from mailtimeline import parser, timeline as tl_mod  # noqa: E402
from mailtimeline import dmarc, flags, report  # noqa: E402
from mailtimeline import cli  # noqa: E402
from mailtimeline.cli import process_file  # noqa: E402


class TestParser(unittest.TestCase):
    def test_legitimate_eml(self):
        p = parser.parse_file(SAMPLES / "legitimate.eml")
        self.assertEqual(p.subject, "This week in Example")
        self.assertIn("newsletter.example.com", p.from_)
        self.assertEqual(len(p.received), 3)
        self.assertTrue(p.body_present)
        self.assertFalse(p.is_msg)

    def test_address_headers_reported(self):
        p = parser.parse_file(SAMPLES / "legitimate.eml")
        self.assertEqual(p.reply_to, "")
        self.assertTrue(parsed_message_id_ok(p))

    def test_msg_support(self):
        p = parser.parse_file(SAMPLES / "sample.msg")
        self.assertTrue(p.is_msg)
        self.assertIn("Invoice for June", p.subject)
        self.assertIn("example.com", p.from_)
        self.assertGreaterEqual(len(p.received), 1)
        self.assertTrue(any("best-effort" in n for n in p.parse_notes))

    def test_missing_file(self):
        with self.assertRaises(ValueError):
            parser.parse_file(HERE / "definitely-missing.eml")


def parsed_message_id_ok(p):
    return p.message_id.strip() != ""


class TestTimeline(unittest.TestCase):
    def test_chronological_hop_order(self):
        p = parser.parse_file(SAMPLES / "legitimate.eml")
        tl = tl_mod.build(p)
        self.assertEqual(len(tl.hops), 3)
        times = [h.parsed_ts for h in tl.hops]
        self.assertTrue(all(times[i] <= times[i + 1] for i in range(len(times) - 1)))
        self.assertTrue(tl.ordering_ok)

    def test_descriptions_and_entries(self):
        p = parser.parse_file(SAMPLES / "legitimate.eml")
        tl = tl_mod.build(p)
        entries = tl.to_entries()
        # Date header entry first, then hops
        self.assertIn("composed", entries[0][1])
        merged = "\n".join(e[1] for e in entries)
        self.assertIn("origin.newsletter.example.com", merged)
        self.assertIn("mx.provider.example.com", merged)

    def test_out_of_order_detected(self):
        raw = [
            "from a by b with esmtp; Tue, 02 Jun 2026 07:00:00 +0000",
            "from c by d with esmtp; Tue, 02 Jun 2026 08:00:00 +0000",
        ]
        p = parser.ParsedEmail(
            source="t.eml", is_msg=False, headers=[("Received", r) for r in raw],
            subject="", from_="", sender="", reply_to="", to="", cc="", date="",
            message_id="", authentication_results=[], received=raw, body_present=False,
        )
        tl = tl_mod.build(p)
        self.assertFalse(tl.ordering_ok)

    def test_no_timestamp_hop(self):
        hop = tl_mod.parse_received("from a by b with esmtp")
        self.assertIsNone(hop.parsed_ts)
        self.assertEqual(hop.note, "no timestamp in Received header")


class TestDmarc(unittest.TestCase):
    def test_parse_auth_results(self):
        lines = [
            "mx.example.com;",
            "spf=pass smtp.mailfrom=newsletter.example.com;",
            "dkim=pass header.d=newsletter.example.com header.s=s2026;",
            "dmarc=pass header.from=newsletter.example.com",
        ]
        rep = dmarc.parse_authentication_results(lines)
        self.assertTrue(rep.present)
        self.assertEqual(rep.authenticator, "mx.example.com")
        results = {m.mechanism: m.result for m in rep.mechanisms}
        self.assertEqual(
            results, {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        )
        dkim = rep.get("dkim")
        self.assertEqual(dkim.domain, "newsletter.example.com")
        self.assertEqual(dkim.selector, "s2026")

    def test_empty(self):
        rep = dmarc.parse_authentication_results([])
        self.assertFalse(rep.present)
        self.assertEqual(len(rep.mechanisms), 0)

    def test_plaintext_explanations(self):
        lines = [
            "mx.example.com; spf=pass smtp.mailfrom=a.com; dmarc=pass header.from=a.com",
        ]
        rep = dmarc.parse_authentication_results(lines)
        text = " ".join(dmarc.plain_english(rep, "dmarc"))
        self.assertIn("plain meaning", text)
        self.assertIn("DMARC", text)
        self.assertIn("reasoning summary", text.lower())
        self.assertIn("DKIM", text)  # absence also explained

    def test_hardest_mechanism(self):
        lines = ["mx; spf=pass smtp.mailfrom=a.com; dkim=pass header.d=a.com; "
                 "dmarc=softfail header.from=a.com"]
        rep = dmarc.parse_authentication_results(lines)
        self.assertEqual(dmarc.hardest_mechanism(rep), "dmarc")


def _fake_parsed(from_="", reply_to="", headers=None):
    return parser.ParsedEmail(
        source="t.eml", is_msg=False, headers=headers or [],
        subject="", from_=from_, sender="", reply_to=reply_to, to="", cc="",
        date="", message_id="", authentication_results=[], received=[],
        body_present=False,
    )


class TestFlags(unittest.TestCase):
    def test_reply_to_mismatch_flagged(self):
        p = _fake_parsed(
            from_="PayPal Security Team <alerts@paypa1-account-verify.click>",
            reply_to="security.reply-desk@confirm-you-account.click",
        )
        v = flags.check_reply_to(p)
        levels = [f.level for f in v]
        self.assertIn("high", levels)

    def test_matching_reply_to_not_flagged(self):
        p = _fake_parsed(
            from_="Sam <sam@hotmail.com>", reply_to="sam@hotmail.com"
        )
        v = flags.check_reply_to(p)
        self.assertEqual(v, [])

    def test_mailing_list_reply_to_downgraded(self):
        p = _fake_parsed(
            from_="Sam <sam@hotmail.com>",
            reply_to="club@lists.example.org",
            headers=[("List-Id", "Chess Club <chess-club.lists.example.org>")],
        )
        v = flags.check_reply_to(p)
        self.assertEqual(v[0].level, "low")

    def test_brand_impersonation(self):
        v = flags.check_display_name(
            '"PayPal Security Team" <alerts@paypa1-account-verify.click>'
        )
        self.assertTrue(any(f.level in ("high", "medium") for f in v))

    def test_legit_brand_not_flagged(self):
        v = flags.check_display_name('"PayPal Team" <service@paypal.com>')
        self.assertFalse(any("Brand" in f.title for f in v))

    def test_verdict_labels(self):
        p = parser.parse_file(SAMPLES / "phishing.eml")
        rep = dmarc.parse_authentication_results(p.authentication_results)
        v = flags.analyze(p, rep)
        self.assertEqual(v.label, "likely spoofed")

        p2 = parser.parse_file(SAMPLES / "legitimate.eml")
        rep2 = dmarc.parse_authentication_results(p2.authentication_results)
        v2 = flags.analyze(p2, rep2)
        self.assertEqual(v2.label, "appears legitimate")

    def test_forward_list_not_called_spoofed(self):
        # even a DMARC pass can't wipe the Reply-To veto below 'appears legitimate'
        p = parser.parse_file(SAMPLES / "club-forward.eml")
        rep = dmarc.parse_authentication_results(p.authentication_results)
        v = flags.analyze(p, rep)
        self.assertNotEqual(v.label, "likely spoofed")


class TestReport(unittest.TestCase):
    def test_json_serializable_and_shape(self):
        p = parser.parse_file(SAMPLES / "legitimate.eml")
        rep = dmarc.parse_authentication_results(p.authentication_results)
        tl = tl_mod.build(p)
        v = report.build_verdict(p, rep, tl)
        data = report.analysis_dict(p, rep, tl, v)
        self.assertEqual(data["subject"], "This week in Example")
        self.assertIn("timeline", data)
        self.assertTrue(data["authentication"]["present"])
        self.assertIn("dmarc", data["authentication"]["results"])
        self.assertEqual(data["authentication"]["results"]["dmarc"], "pass")
        out = report.to_json(data)
        import json

        parsed_back = json.loads(out)
        self.assertEqual(parsed_back["tool"], "mailtimeline")
        self.assertIn("privacy", parsed_back)


class TestCli(unittest.TestCase):
    def test_cli_text(self):
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main([str(SAMPLES / "phishing.eml")])
        self.assertEqual(code, 0)
        text = buf.getvalue()
        self.assertIn("MAILTIMELINE", text)
        self.assertIn("VERDICT", text)
        self.assertIn("Timeline", text)
        self.assertIn("plain English", text)

    def test_cli_json_stdout(self):
        import io
        import contextlib
        import json

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(
                [str(SAMPLES / "legitimate.eml"), "--json", "-"]
            )
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["subject"], "This week in Example")

    def test_cli_json_file(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "r.json"
            code = cli.main(
                [str(SAMPLES / "legitimate.eml"), "--quiet", "--json", str(out)]
            )
            self.assertEqual(code, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["verdict"]["label"], "appears legitimate")

    def test_cli_missing_file(self):
        import io
        import contextlib

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(["missing.eml"])
        self.assertEqual(code, 1)
        self.assertIn("not found", err.getvalue())

    def test_process_file_good_and_bad(self):
        ok = process_file(SAMPLES / "phishing.eml")
        self.assertIsNone(ok[2])
        bad = process_file(HERE / "empty.eml") if (HERE / "empty.eml").exists() else None
        if bad:
            self.assertIsNotNone(bad[2])


if __name__ == "__main__":
    unittest.main()
