"""`yobiru dashboard`: the read-only summary of one data home, its local page, and the sender's sent log."""
import datetime as dt
import http.client
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from support.pkg import REPO

SCRIPTS = REPO / "plugins" / "yobiru" / "scripts"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = load("tailmsg_dashboard_under_test", REPO / "tailmsg.py")
dash = load("yobiru_dashboard_under_test", SCRIPTS / "yobiru_dashboard.py")
NOW = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.timezone.utc).timestamp()
HOME_MINI = "home-mini.tail0000.ts.net"
MINI_ID = "miniStable1CNTRL"


def at(hours_ago):
    return dash.iso(NOW - hours_ago * 3600)


def inbox(home, mid, peer, hours_ago, text="hi", **extra):
    env = {"v": 1, "id": mid, "from": peer.get("node"), "to": "work-mini.relay", "ts": at(hours_ago), "kind": "msg",
           "text": text, "agent": "codex", "from_agent": "grok"}
    env.update(extra.pop("env", {}))
    rec = {"envelope": env, "received": {"at": at(hours_ago), "peer": peer, "agent": "codex", "agent_status": "known",
                                         "wake": {"requested": "now", "effective": "now", "reason": "as requested"},
                                         "node": "work-mini.relay"}}
    rec.update(extra)
    (home / "inbox" / (mid + ".json")).write_text(json.dumps(rec))


def build_home(home):
    """One data home with traffic to three peers over both transports, a ledger, a log and receiver health."""
    (home / "inbox").mkdir(parents=True)
    (home / "relay").mkdir()
    (home / "config.json").write_text(json.dumps({"relay": "on", "self_agent": "codex", "default_agent": "codex"}))
    (home / "relay" / "device.json").write_text(json.dumps({"relay": "https://relay.example", "name": "work-mini",
                                                            "token": "secret-token", "secret_key": "k"}))
    (home / "relay" / "trusted.json").write_text(json.dumps({"grok": {}, "spare": {}}))
    grok = {"node": "grok.relay", "transport": "relay", "stable_id": "relay-abc"}
    inbox(home, "in00000001", grok, 1, acked_at=at(0.5),
          wake_delivery={"ok": True, "agent": "codex", "attempts": 1})
    inbox(home, "in00000002", grok, 2, wake_delivery={"ok": False, "attempts": 3, "error": "exit 1"})
    inbox(home, "in00000003", grok, 3, text="x" * 900)
    inbox(home, "in00000004", grok, 400)                                              # outside a 7-day window
    # A pull request arrives from its sender's StableID; the receipt still names the device.
    inbox(home, "in00000005", {"node": HOME_MINI, "stable_id": MINI_ID}, 4,
          env={"from": core.stable_peer_id(MINI_ID), "request": {"timeout_seconds": 60, "transport": "pull"}})
    (home / "inbox" / "broken.json").write_text("{")
    ctx = SimpleNamespace(home=home)
    for mid, to, transport, status, error, hours in (("out0000001", "grok.relay", "relay", 202, None, 1.5),
                                                     ("out0000002", HOME_MINI, "tailscale", None, "TransportError", 5),
                                                     ("out0000003", "grok.relay", "relay", 202, None, 6)):
        env = {"id": mid, "ts": at(hours), "to": to, "kind": "msg", "text": "reply " + mid, "agent": "grok",
               "fetch": [{"name": "a.txt", "size": 10}]}
        if mid == "out0000003":
            env.update(kind="request", request={"timeout_seconds": 60})
        core.record_sent(ctx, env, transport, status, error)
    with open(str(home / "sent.jsonl"), "a") as f:
        f.write("not json\n")
    db = core.request_db(ctx)
    with db:
        db.execute("INSERT INTO requests(direction,id,peer,port,envelope,deadline,state) VALUES(?,?,?,?,?,?,?)",
                   ("incoming", "in00000005", core.stable_peer_id(MINI_ID), 7766,
                    json.dumps({"ts": at(4), "text": "pull job", "agent": "codex"}), at(3), "running"))
        db.execute("INSERT INTO requests(direction,id,peer,port,envelope,deadline,state) VALUES(?,?,?,?,?,?,?)",
                   ("outgoing", "out0000003", "grok.relay", 0, json.dumps({"ts": at(6), "text": "job"}), at(5), "completed"))
        db.execute("INSERT INTO requests(direction,id,peer,port,envelope,deadline,state) VALUES(?,?,?,?,?,?,?)",
                   ("outgoing", "old0000001", "grok.relay", 0, json.dumps({"ts": at(900), "text": "old"}), at(899), "completed"))
        db.execute("INSERT INTO response_outbox(id,request_id,peer,port,envelope,attempts,next_attempt,last_error) "
                   "VALUES(?,?,?,?,?,?,?,?)", ("resp000001", "in00000005", core.stable_peer_id(MINI_ID), 7766, "{}", 2,
                                               NOW + 30, "TransportError: timed out"))
    db.close()
    (home / "maintenance.json").write_text(json.dumps({"status": "healthy", "written_at": at(0.01), "reasons": []}))
    (home / "serve.log").write_text("2026-10-28 11:00:00 message in00000001 from grok.relay\n"
                                    "2026-10-28 11:01:00 wake in00000002 @codex exec failed (attempt 3/3): exit 1\n"
                                    "2026-10-28 11:02:00 access rejected: stranger.relay not_allowed\n")


class SummaryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name) / "home"
        build_home(self.home)
        self.s = dash.summary(self.home, 7, now=NOW)

    def messages(self):
        return {m["id"]: m for m in self.s["messages"]}

    def test_messages_both_directions_with_their_status(self):
        m = self.messages()
        self.assertEqual(set(m), {"in00000001", "in00000002", "in00000003", "in00000005",
                                  "out0000001", "out0000002", "out0000003"})
        self.assertEqual([x["id"] for x in self.s["messages"]][:2], ["in00000001", "out0000001"])   # newest first
        self.assertEqual(m["in00000001"]["status"], "processed")
        self.assertEqual(m["in00000002"]["status"], "wake_failed")
        self.assertEqual(m["in00000002"]["wake_error"], "exit 1")
        self.assertEqual(m["in00000003"]["status"], "pending")
        self.assertEqual(len(m["in00000003"]["text"]), dash.PREVIEW)
        self.assertEqual(m["in00000005"]["status"], "running")                  # tracked: the ledger state
        self.assertEqual(m["out0000001"]["status"], "delivered")
        self.assertEqual(m["out0000002"]["status"], "send_failed")
        self.assertEqual(m["out0000003"]["status"], "completed")
        self.assertEqual((m["out0000001"]["files"], m["out0000001"]["bytes"]), (1, 10))
        self.assertEqual(self.s["unreadable"], {"inbox": 1, "sent": 1})

    def test_peers_by_device_with_the_pull_sender_named(self):
        peers = {p["peer"]: p for p in self.s["peers"]}
        self.assertEqual(set(peers), {"grok.relay", HOME_MINI, "spare.relay"})
        self.assertEqual((peers["grok.relay"]["in"], peers["grok.relay"]["out"], peers["grok.relay"]["problems"]), (3, 2, 1))
        self.assertEqual(peers["grok.relay"]["transport"], "relay")
        self.assertTrue(peers["grok.relay"]["trusted"])
        self.assertEqual((peers[HOME_MINI]["label"], peers[HOME_MINI]["transport"]), ("home-mini", "tailscale"))
        self.assertEqual((peers[HOME_MINI]["in"], peers[HOME_MINI]["out"], peers[HOME_MINI]["problems"]), (1, 1, 1))
        self.assertEqual(peers["spare.relay"]["in"] + peers["spare.relay"]["out"], 0)
        self.assertEqual(self.s["outbox"][0]["peer"], HOME_MINI)
        self.assertEqual({r["peer"] for r in self.s["requests"]}, {HOME_MINI, "grok.relay"})
        self.assertEqual({(r["peer"], r["transport"]) for r in self.s["requests"]},
                         {(HOME_MINI, "tailscale"), ("grok.relay", "relay")})
        self.assertEqual(self.s["outbox"][0]["transport"], "tailscale")
        self.assertEqual({m["transport"] for m in self.s["messages"] if m["peer"] == "grok.relay"}, {"relay"})

    def test_requests_outbox_log_and_device(self):
        self.assertEqual({r["id"] for r in self.s["requests"]}, {"in00000005", "out0000003"})   # old final one left out
        self.assertEqual(self.s["outbox"][0]["attempts"], 2)
        self.assertEqual(len(self.s["log"]), 2)
        self.assertEqual(self.s["me"]["relay"], "work-mini.relay")
        self.assertEqual(self.s["me"]["node"], "work-mini.relay")
        self.assertEqual(self.s["receiver"]["status"], "healthy")
        self.assertTrue(self.s["sent_log"])
        self.assertNotIn("secret-token", json.dumps(self.s))

    def test_a_wider_window_and_stale_health(self):
        s = dash.summary(self.home, 30, now=NOW + 3600)
        self.assertIn("in00000004", {m["id"] for m in s["messages"]})
        self.assertEqual(s["receiver"]["status"], "stale")

    def test_an_empty_home_reads_without_creating_anything(self):
        empty = self.home.parent / "empty"
        empty.mkdir()
        s = dash.summary(empty, 7, now=NOW)
        self.assertEqual((s["messages"], s["peers"], s["sent_log"]), ([], [], False))
        self.assertEqual(sorted(os.listdir(str(empty))), [])


class SentLogTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.ctx = SimpleNamespace(home=Path(tmp.name))

    def env(self, n):
        return {"id": "m%07d" % n, "ts": "2026-10-28T00:00:00Z", "to": "grok.relay", "kind": "msg", "text": "t" * 600}

    def test_one_private_line_per_send(self):
        core.record_sent(self.ctx, self.env(1), "relay", 202)
        path = self.ctx.home / core.SENT_LOG
        row = json.loads(path.read_text())
        self.assertEqual((row["id"], row["transport"], row["status"], row["error"]), ("m0000001", "relay", 202, None))
        self.assertEqual(len(row["text"]), core.INBOX_PREVIEW)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_trimmed_to_its_newer_half(self):
        old = core.SENT_LOG_BYTES
        core.SENT_LOG_BYTES = 8000
        self.addCleanup(setattr, core, "SENT_LOG_BYTES", old)
        for n in range(20):
            core.record_sent(self.ctx, self.env(n), "relay", 202)
        path = self.ctx.home / core.SENT_LOG
        ids = [json.loads(line)["id"] for line in path.read_text().splitlines()]
        self.assertLess(len(ids), 20)
        self.assertEqual(ids[-1], "m0000019")
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_an_unwritable_home_never_fails_the_send(self):
        self.ctx.home = self.ctx.home / "missing"
        core.record_sent(self.ctx, self.env(1), "relay", 202)


class PageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.home = Path(cls.tmp.name) / "home"
        build_home(cls.home)
        cls.server, cls.url = dash.start(cls.home)
        cls.port = cls.server.server_address[1]
        cls.token = cls.url.split("t=", 1)[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def get(self, path, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("GET", path, skip_host=True)
        conn.putheader("Host", host or "127.0.0.1:%d" % self.port)
        conn.endheaders()
        r = conn.getresponse()
        body = r.read()
        conn.close()
        return r, body

    def test_page_and_summary_behind_the_token(self):
        self.assertTrue(self.url.startswith("http://127.0.0.1:"))
        r, body = self.get("/?t=" + self.token)
        self.assertEqual(r.status, 200)
        self.assertIn(b"Yobiru", body)
        self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
        r, body = self.get("/api/summary?t=%s&days=30" % self.token)
        self.assertEqual(r.status, 200)
        data = json.loads(body)
        self.assertEqual(data["days"], 30)
        self.assertIn("grok.relay", {p["peer"] for p in data["peers"]})

    def test_refused_without_the_token_or_with_another_host(self):
        self.assertEqual(self.get("/api/summary")[0].status, 403)
        self.assertEqual(self.get("/api/summary?t=wrong")[0].status, 403)
        self.assertEqual(self.get("/api/summary?t=" + self.token, host="evil.example:%d" % self.port)[0].status, 403)
        self.assertEqual(self.get("/nothing?t=" + self.token)[0].status, 404)


class CommandTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPTS / "yobiru.py")] + list(args),
                              capture_output=True, text=True, timeout=60)

    def test_json_once_and_a_missing_setup(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            build_home(home)
            r = self.run_cli("--home", str(home), "dashboard", "--json", "--days", "90")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["days"], 90)
            r = self.run_cli("--home", str(Path(tmp) / "none"), "dashboard", "--json")
            self.assertEqual(r.returncode, 2)
            self.assertIn("setup", r.stderr)
            self.assertFalse((Path(tmp) / "none").exists())


if __name__ == "__main__":
    unittest.main()
