"""Tests for uptime_check.py. Standard library only; no network."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from unittest import mock

import uptime_check as uc

SECRET = "uptime-secret-value"
T0 = datetime(2026, 9, 24, 3, 0, tzinfo=timezone.utc)
HEALTH = uc.Target("orders-health", "https://orders.example.test/health", (200,), {"ok": True})
LOGIN = uc.Target("orders-login", "https://orders.example.test/", (302, 303), {}, "/login")
PAGE = uc.Target("www-setup", "https://www.example.test/setup", (200,), {})


class Sites:
    """Fake fetcher: url -> (status, headers, body) or an exception."""

    def __init__(self) -> None:
        self.responses: dict[str, object] = {
            HEALTH.url: (200, {}, json.dumps({"ok": True, "store": "ok", "revision": "abcdef012345"}).encode()),
            LOGIN.url: (303, {"location": "/login"}, b""),
            PAGE.url: (200, {}, b"<html>setup</html>"),
        }
        self.calls: list[str] = []

    def __call__(self, url: str):
        self.calls.append(url)
        value = self.responses.get(url, (404, {}, b"not found"))
        if isinstance(value, Exception):
            raise value
        return value


class Relay:
    def __init__(self) -> None:
        self.alerts: list[dict] = []
        self.up = True

    def __call__(self, alert: dict):
        self.alerts.append(alert)
        return (True, "email=True telegram=True") if self.up else (False, "relay HTTP 502")


class CheckTests(unittest.TestCase):
    def test_json_login_redirect_and_page_expectations(self) -> None:
        sites = Sites()
        for target in (HEALTH, LOGIN, PAGE):
            self.assertTrue(uc.check(target, sites).ok, target.name)
        self.assertIn("store=ok", uc.check(HEALTH, sites).detail)

    def test_store_outage_wrong_redirect_and_no_response_fail(self) -> None:
        sites = Sites()
        sites.responses[HEALTH.url] = (503, {}, json.dumps({"ok": False, "store": "fail"}).encode())
        sites.responses[LOGIN.url] = (302, {"location": "https://evil.example/"}, b"")
        sites.responses[PAGE.url] = TimeoutError("timed out")
        self.assertEqual(uc.check(HEALTH, sites).detail, "HTTP 503; store=fail")
        self.assertIn("Location=https://evil.example/", uc.check(LOGIN, sites).detail)
        self.assertEqual(uc.check(PAGE, sites).detail, "no response (TimeoutError)")

    def test_ok_false_with_200_still_fails(self) -> None:
        sites = Sites()
        sites.responses[HEALTH.url] = (200, {}, json.dumps({"ok": False}).encode())
        result = uc.check(HEALTH, sites)
        self.assertFalse(result.ok)
        self.assertIn("ok=false", result.detail)

    def test_response_bodies_never_reach_the_detail(self) -> None:
        sites = Sites()
        sites.responses[PAGE.url] = (500, {}, b"secret-looking stack trace")
        sites.responses[HEALTH.url] = (200, {}, json.dumps({"ok": True, "store": "<script>x</script>"}).encode())
        self.assertNotIn("stack trace", uc.check(PAGE, sites).detail)
        self.assertNotIn("script", uc.check(HEALTH, sites).detail)


class RunTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sites = Sites()
        self.relay = Relay()
        self.state: dict = {"targets": {}}
        self.out = io.StringIO()

    def tick(self, minutes: int, **kwargs) -> bool:
        with contextlib.redirect_stdout(self.out):
            return uc.run(
                "SW-TEST",
                [HEALTH, LOGIN, PAGE],
                self.state,
                T0 + timedelta(minutes=minutes),
                fetcher=self.sites,
                sender=self.relay,
                **kwargs,
            )

    def test_all_green_sends_nothing(self) -> None:
        self.assertTrue(self.tick(0))
        self.assertEqual(self.relay.alerts, [])
        self.assertEqual(len(self.sites.calls), 3)

    def test_one_blip_is_ignored(self) -> None:
        self.sites.responses[PAGE.url] = (502, {}, b"")
        self.tick(0)
        self.sites.responses[PAGE.url] = (200, {}, b"")
        self.tick(5)
        self.assertEqual(self.relay.alerts, [])
        self.assertNotIn("since", self.state["targets"]["www-setup"])

    def test_down_alerts_once_then_recovers_once(self) -> None:
        self.sites.responses[HEALTH.url] = (503, {}, json.dumps({"ok": False, "store": "fail"}).encode())
        for minute in (0, 5, 10, 15):
            self.assertTrue(self.tick(minute))
        self.assertEqual([a["kind"] for a in self.relay.alerts], ["uptime_down"])
        down = self.relay.alerts[0]
        self.assertEqual(down["id"], "up-orders-health-20260924T030000Z")
        self.assertEqual(down["tenantId"], "SW-TEST")
        self.assertIn("2 check(s) in a row", down["summary"])
        self.assertLessEqual(len(down["summary"]), uc.SUMMARY_CHARS)

        self.sites.responses[HEALTH.url] = (200, {}, json.dumps({"ok": True, "store": "ok"}).encode())
        self.tick(20)
        self.tick(25)
        self.assertEqual([a["kind"] for a in self.relay.alerts], ["uptime_down", "uptime_recovered"])
        self.assertEqual(self.relay.alerts[1]["id"], "upok-orders-health-20260924T030000Z")
        self.assertIn("4 check(s)", self.relay.alerts[1]["summary"])

    def test_every_alert_id_is_one_the_relay_accepts(self) -> None:
        long_name = uc.Target("a" * 30, "https://x.example.test/", (200,), {})
        self.sites.responses[long_name.url] = (500, {}, b"")
        with contextlib.redirect_stdout(self.out):
            uc.run("SW-TEST", [long_name], self.state, T0, min_failures=1, fetcher=self.sites, sender=self.relay)
        self.sites.responses[long_name.url] = (200, {}, b"")
        with contextlib.redirect_stdout(self.out):
            uc.run("SW-TEST", [long_name], self.state, T0 + timedelta(minutes=5), fetcher=self.sites, sender=self.relay)
        self.assertEqual(len(self.relay.alerts), 2)
        for alert in self.relay.alerts:
            self.assertRegex(alert["id"], r"^[A-Za-z0-9_-]{8,64}$")

    def test_an_undelivered_alert_fails_the_run_and_retries_next_time(self) -> None:
        self.sites.responses[PAGE.url] = (500, {}, b"")
        self.relay.up = False
        self.tick(0)
        self.assertFalse(self.tick(5))
        self.assertNotIn("alerted", self.state["targets"]["www-setup"])
        self.relay.up = True
        self.assertTrue(self.tick(10))
        self.assertEqual(self.relay.alerts[-1]["id"], "up-www-setup-20260924T030000Z")
        self.assertEqual(len({a["id"] for a in self.relay.alerts}), 1, "the retry reuses the incident id")

    def test_no_relay_fails_the_run_only_when_an_alert_is_due(self) -> None:
        with contextlib.redirect_stdout(self.out):
            self.assertTrue(uc.run("SW-TEST", [PAGE], self.state, T0, fetcher=self.sites, sender=None))
            self.sites.responses[PAGE.url] = (500, {}, b"")
            uc.run("SW-TEST", [PAGE], self.state, T0 + timedelta(minutes=5), fetcher=self.sites, sender=None)
            self.assertFalse(
                uc.run("SW-TEST", [PAGE], self.state, T0 + timedelta(minutes=10), fetcher=self.sites, sender=None)
            )
        self.assertIn("relay not configured", self.out.getvalue())

    def test_drill_fail_alerts_on_the_first_failure_and_recover_clears_it(self) -> None:
        targets = [HEALTH, LOGIN, PAGE]
        self.tick(0, drill=uc.drill_target("fail", targets))
        self.assertEqual([a["kind"] for a in self.relay.alerts], ["uptime_down"])
        self.assertTrue(self.relay.alerts[0]["id"].startswith("up-drill-"))
        self.assertIn("/__stonewave-uptime-drill", self.sites.calls[-1])
        self.tick(5)  # scheduled runs leave the drill's state alone
        self.tick(10, drill=uc.drill_target("recover", targets))
        self.assertEqual([a["kind"] for a in self.relay.alerts], ["uptime_down", "uptime_recovered"])
        self.assertEqual(self.sites.calls[-1], HEALTH.url)

    def test_a_second_fail_drill_alerts_even_if_the_first_never_cleared(self) -> None:
        targets = [HEALTH, LOGIN, PAGE]
        self.tick(0, drill=uc.drill_target("fail", targets))
        self.state["targets"].pop("drill")  # what main() does before each fail drill
        self.tick(30, drill=uc.drill_target("fail", targets))
        ids = [a["id"] for a in self.relay.alerts if a["kind"] == "uptime_down"]
        self.assertEqual(len(ids), 2)
        self.assertNotEqual(ids[0], ids[1])


class FetchTests(unittest.TestCase):
    def test_one_get_no_redirect_followed_and_the_monitor_agent_sent(self) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        seen: list[tuple[str, str, str | None]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                seen.append((self.command, self.path, self.headers.get("User-Agent")))
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, headers, _ = uc.fetch(f"http://127.0.0.1:{server.server_port}/", timeout=5)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual((status, headers.get("location")), (302, "/login"))
        self.assertEqual(seen, [("GET", "/", uc.USER_AGENT)])
        self.assertTrue(uc.USER_AGENT.startswith("stonewave-uptime/"))


class SignatureTests(unittest.TestCase):
    def test_matches_a_vector_computed_by_the_relays_node_crypto(self) -> None:
        # Expected value from Node: createHmac("sha256", "vector-secret").update(`${t}.${body}`),
        # the same call the relay's verifier makes.
        body = '{"id":"alert-0001","tenantId":"SW-TEST","kind":"test","summary":"vector","at":"2026-09-23T00:00:00Z"}'
        self.assertEqual(
            uc.sign("vector-secret", body, 1790000000),
            "t=1790000000,v1=8b1a6f9e2ddc9e12ee2889504c6599f7d61c01d500cd29b37caee52d1eaa227f",
        )

    def test_post_signs_the_exact_body_and_reads_channels(self) -> None:
        seen = {}

        class Resp:
            status = 200

            def read(self, _n=-1):
                return b'{"ok":true,"email":true,"telegram":false}'

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def opener(request, timeout):
            seen["body"] = request.data.decode()
            seen["sig"] = request.get_header("X-sp-alert-signature")
            seen["url"] = request.full_url
            return Resp()

        alert = {"id": "up-x-20260924T030000Z", "tenantId": "SW-TEST", "kind": "uptime_down", "summary": "s", "at": "t"}
        delivered, note = uc.post_alert("https://relay.example.test/ops-alert", SECRET, alert, opener)
        self.assertEqual((delivered, note), (True, "email=True telegram=False"))
        t = int(seen["sig"].split(",")[0][2:])
        self.assertEqual(seen["sig"], uc.sign(SECRET, seen["body"], t))
        self.assertEqual(json.loads(seen["body"]), alert)

    def test_relay_errors_are_not_delivered(self) -> None:
        def refused(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", Message(), io.BytesIO())

        def down(request, timeout):
            raise ConnectionRefusedError()

        alert = {"id": "up-x-20260924T030000Z", "tenantId": "T-1", "kind": "uptime_down", "summary": "", "at": ""}
        self.assertEqual(uc.post_alert("https://r.example.test", SECRET, alert, refused), (False, "relay HTTP 401"))
        self.assertEqual(
            uc.post_alert("https://r.example.test", SECRET, alert, down), (False, "relay unreachable (ConnectionRefusedError)")
        )


class ConfigAndMainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def write_targets(self, data: dict) -> Path:
        path = self.dir / "targets.json"
        path.write_text(json.dumps(data))
        return path

    def test_the_committed_targets_file_is_valid(self) -> None:
        tenant, targets = uc.load_targets(Path(__file__).with_name("targets.json"))
        self.assertEqual(tenant, "SW-UPTIME")
        self.assertEqual([t.name for t in targets], ["orders-health", "orders-login", "www"])
        for target in targets:
            self.assertTrue(target.url.startswith("https://"))

    def test_bad_configs_are_refused(self) -> None:
        good = {"name": "a-site", "url": "https://a.example.test/"}
        for bad in (
            {"tenant": "x", "targets": [good]},
            {"tenant": "SW-1", "targets": [{"name": "Bad Name", "url": "https://a.example.test/"}]},
            {"tenant": "SW-1", "targets": [{"name": "drill", "url": "https://a.example.test/"}]},
            {"tenant": "SW-1", "targets": [{"name": "a-site", "url": "http://a.example.test/"}]},
            {"tenant": "SW-1", "targets": [good, good]},
            {"tenant": "SW-1", "targets": [dict(good, enabled=False)]},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                uc.load_targets(self.write_targets(bad))

    def test_main_never_prints_the_secret_and_saves_state(self) -> None:
        targets = self.write_targets({"tenant": "SW-1", "targets": [{"name": "a-site", "url": "https://a.example.test/"}]})
        state = self.dir / "state" / "state.json"
        out = io.StringIO()
        env = {"SP_ALERT_URL": "https://relay.example.test/ops-alert", "SP_ALERT_SECRET": SECRET, "UPTIME_DRILL": "none"}
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(uc, "fetch", return_value=(500, {}, b"")) as fetched, \
             mock.patch.object(uc, "post_alert", return_value=(True, "delivered")) as post, \
             contextlib.redirect_stdout(out):
            self.assertEqual(uc.main(["--targets", str(targets), "--state", str(state)], now=T0), 0)
        fetched.assert_called_once_with("https://a.example.test/")
        self.assertNotIn(SECRET, out.getvalue())
        self.assertIn("no saved state", out.getvalue())
        self.assertEqual(post.call_count, 1, "no saved state: the first failure alerts")
        self.assertEqual(json.loads(state.read_text())["targets"]["a-site"]["alerted"], "up-a-site-20260924T030000Z")

    def test_bad_drill_value_or_config_exits_1(self) -> None:
        targets = self.write_targets({"tenant": "SW-1", "targets": [{"name": "a-site", "url": "https://a.example.test/"}]})
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"UPTIME_DRILL": "explode"}), contextlib.redirect_stdout(out):
            self.assertEqual(uc.main(["--targets", str(targets), "--state", str(self.dir / "s.json")]), 1)
        with contextlib.redirect_stdout(out):
            self.assertEqual(uc.main(["--targets", str(self.dir / "missing.json"), "--state", str(self.dir / "s.json")]), 1)

    def test_a_corrupt_state_file_starts_fresh(self) -> None:
        path = self.dir / "state.json"
        path.write_text("{not json")
        self.assertEqual(uc.load_state(path), ({"targets": {}}, False))
        uc.save_state(path, {"targets": {"a": {}}})
        self.assertEqual(uc.load_state(path), ({"targets": {"a": {}}}, True))

    def test_with_saved_state_a_single_failure_waits_for_a_second(self) -> None:
        targets = self.write_targets({"tenant": "SW-1", "targets": [{"name": "a-site", "url": "https://a.example.test/"}]})
        state = self.dir / "state.json"
        uc.save_state(state, {"targets": {}})
        env = {"SP_ALERT_URL": "https://relay.example.test/ops-alert", "SP_ALERT_SECRET": SECRET, "UPTIME_DRILL": "none"}
        with mock.patch.dict(os.environ, env), mock.patch.object(uc, "fetch", return_value=(500, {}, b"")), \
             mock.patch.object(uc, "post_alert", return_value=(True, "delivered")) as post, \
             contextlib.redirect_stdout(io.StringIO()):
            uc.main(["--targets", str(targets), "--state", str(state)], now=T0)
            self.assertEqual(post.call_count, 0)
            uc.main(["--targets", str(targets), "--state", str(state)], now=T0 + timedelta(minutes=5))
            self.assertEqual(post.call_count, 1)

    def test_fallback_drill_fails_the_run_without_reaching_any_relay(self) -> None:
        targets = self.write_targets({"tenant": "SW-1", "targets": [{"name": "a-site", "url": "https://a.example.test/"}]})
        state = self.dir / "state.json"
        uc.save_state(state, {"targets": {}})
        seen = []

        def post(url, secret, alert, opener=None):
            seen.append(url)
            return False, "relay unreachable (URLError)"

        out = io.StringIO()
        env = {"SP_ALERT_URL": "https://relay.example.test/ops-alert", "SP_ALERT_SECRET": SECRET, "UPTIME_DRILL": "fallback"}
        with mock.patch.dict(os.environ, env), mock.patch.object(uc, "fetch", return_value=(200, {}, b"")), \
             mock.patch.object(uc, "post_alert", side_effect=post), contextlib.redirect_stdout(out):
            self.assertEqual(uc.main(["--targets", str(targets), "--state", str(state)], now=T0), 1)
        self.assertEqual(seen, [uc.UNREACHABLE_RELAY])
        self.assertNotIn(SECRET, out.getvalue())


if __name__ == "__main__":
    unittest.main()
