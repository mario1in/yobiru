"""The self-hosted relay (relay.py, docs/RELAY_DESIGN.md), loopback only and without Tailscale.

The unit tests run a relay server on a thread in this process and check sealing, replay, impersonation, trust,
invites and revocation. The loopback tests run the unpacked plugin: a relay server, and two relay-only receivers
whose PATH has no tailscale at all. Nothing here touches the real Tailscale, port 7766, ~/.tailmsg or another
machine.
"""
import argparse
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from support.pkg import REPO, Package, free_port


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


relay = load("relay_under_test", REPO / "relay.py")
core = load("tailmsg_relay_under_test", REPO / "tailmsg.py")
core.log = lambda *args: None

ADAPTER = """#!/bin/sh
printf '%%s %%s\\n' "$TAILMSG_AGENT" "$TAILMSG_MSG_ID" >> '%s'
"""


def wait_for(cond, timeout=15.0, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


class RelayUnitTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.server_home = self.root / "relay"
        relay.cmd_server(argparse.Namespace(relay_home=str(self.server_home), server_cmd="init", bind="127.0.0.1",
                                            port=0))
        self.registry = relay.Registry(self.server_home)
        cfg = relay.server_config(self.server_home)
        self.hub = relay.Hub()
        handler = relay.make_server_handler(self.registry, self.hub, cfg["relay_id"])
        handler.log_message = lambda *args: None
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        self.dev = {name: self.join(name) for name in ("alpha", "bravo", "charlie")}
        self.trust("alpha", "bravo")
        self.trust("bravo", "alpha")

    def join(self, name):
        home = self.root / name
        relay.cmd_join(argparse.Namespace(home=str(home), url=self.url, name=name,
                                          invite=self.registry.invite(name)))
        return relay.Device(home)

    def device_cmd(self, who, cmd, **fields):
        return relay.cmd_device(argparse.Namespace(home=str(self.root / who), cmd=cmd, **fields))

    def trust(self, who, peer):
        self.device_cmd(who, "trust", name=peer, fingerprint=relay.e2e().fingerprint(self.dev[peer].public))

    def frame(self, sender, to, body=b'{"text": "secret words"}', frame_id=None):
        frame_id = frame_id or relay.secrets.token_urlsafe(18)
        key = self.dev[sender].trusted_key(to) or self.dev[to].public
        sealed = self.dev[sender].seal(key, frame_id, "request", {
            "from": sender, "to": to, "method": "POST", "path": "/msg",
            "headers": {"Content-Type": "application/json"}, "body": relay.e2e().b64e(body)})
        return {"frame_id": frame_id, "from": sender, "sealed": sealed}

    def refused(self, code, fn, *args):
        with self.assertRaises(relay.RelayError) as caught:
            fn(*args)
        self.assertEqual(code, caught.exception.code)
        return caught.exception

    def test_frame_opens_once_and_the_relay_sees_only_ciphertext(self):
        frame = self.frame("alpha", "bravo")
        self.assertNotIn("secret words", json.dumps(frame))
        request, sender, key = self.dev["bravo"].open_request(frame)
        self.assertEqual(("POST", "/msg", b'{"text": "secret words"}', "alpha", self.dev["alpha"].public),
                         (request["method"], request["path"], request["body"], sender, key))
        self.refused("replayed", self.dev["bravo"].open_request, frame)

    def test_changed_moved_or_relabelled_frames_are_refused(self):
        frame = self.frame("alpha", "bravo")
        changed = dict(frame, sealed=dict(frame["sealed"]))
        ct = changed["sealed"]["ct"]
        changed["sealed"]["ct"] = ct[:-2] + ("A" if ct[-2] != "A" else "B") + ct[-1]
        self.refused("frame_unopened", self.dev["bravo"].open_request, changed)
        self.refused("frame_unopened", self.dev["bravo"].open_request, dict(frame, frame_id="x" * 24))
        self.trust("bravo", "charlie")          # a trusted third device cannot pass off alpha's frame as its own
        self.refused("frame_unopened", self.dev["bravo"].open_request, dict(frame, **{"from": "charlie"}))
        # Nor can a request be replayed to its own sender as the answer.
        self.refused("frame_unopened", self.dev["alpha"].open, frame["sealed"], "bravo", self.dev["bravo"].public,
                     frame["frame_id"], "response")

    def test_untrusted_senders_and_peers_are_refused(self):
        self.refused("sender_not_trusted", self.dev["bravo"].open_request, self.frame("charlie", "bravo"))
        self.refused("not_trusted", self.dev["charlie"].exchange, "bravo", "GET", "/health")
        self.device_cmd("bravo", "untrust", name="alpha")
        self.refused("sender_not_trusted", self.dev["bravo"].open_request, self.frame("alpha", "bravo"))

    def test_trust_requires_the_fingerprint_shown_on_that_device(self):
        wrong = relay.e2e().fingerprint(self.dev["bravo"].public)
        self.refused("fingerprint_mismatch", lambda: self.device_cmd("charlie", "trust", name="alpha", fingerprint=wrong))
        own = relay.e2e().fingerprint(self.dev["charlie"].public)
        self.refused("self", lambda: self.device_cmd("charlie", "trust", name="charlie", fingerprint=own))
        listed = {d["name"]: d["trust"] for d in self.device_cmd("alpha", "directory")["devices"]}
        self.assertEqual({"alpha": "untrusted", "bravo": "trusted", "charlie": "untrusted"}, listed)

    def test_invites_are_single_use_and_bound_to_one_name(self):
        code = self.registry.invite("delta")
        args = dict(url=self.url, invite=code)
        self.refused("bad_invite", relay.cmd_join, argparse.Namespace(home=str(self.root / "x"), name="echo", **args))
        relay.cmd_join(argparse.Namespace(home=str(self.root / "delta"), name="delta", **args))
        self.refused("bad_invite", relay.cmd_join, argparse.Namespace(home=str(self.root / "y"), name="delta", **args))
        self.refused("exists", relay.cmd_join, argparse.Namespace(home=str(self.root / "delta"), name="delta", **args))

    def test_revoked_devices_are_refused_and_unreachable(self):
        self.trust("alpha", "charlie")
        self.registry.revoke("charlie")
        self.refused("unauthorized", self.dev["charlie"].directory)
        self.assertNotIn("charlie", [d["name"] for d in self.dev["alpha"].directory()])
        self.refused("unknown_device", self.dev["alpha"].exchange, "charlie", "GET", "/health")

    def test_offline_peer_fails_fast_and_delivery_is_known(self):
        started = time.monotonic()
        error = self.refused("peer_offline", self.dev["alpha"].exchange, "bravo", "GET", "/health")
        self.assertFalse(error.unknown)
        self.assertLess(time.monotonic() - started, 5)

    def test_exchange_round_trip_through_the_relay(self):
        stop = threading.Event()

        def answer_forever():
            while not stop.is_set():
                for frame in self.dev["bravo"].poll(1):
                    request, sender, key = self.dev["bravo"].open_request(frame)
                    self.dev["bravo"].answer(frame["frame_id"], sender, key, 200,
                                             {"Content-Type": "application/json"}, b'{"echo": ' + request["body"] + b"}")
        answering = threading.Thread(target=answer_forever, daemon=True)
        answering.start()
        self.addCleanup(answering.join, 5)      # cleanups run last-in first-out: stop, then join, then shutdown
        self.addCleanup(stop.set)
        self.assertTrue(wait_for(lambda: self.hub.online("bravo")))
        status, headers, body = self.dev["alpha"].exchange("bravo", "POST", "/msg", b'"hi"',
                                                          {"Content-Type": "application/json"})
        self.assertEqual((200, {"echo": "hi"}), (status, json.loads(body)))

    def test_unauthenticated_requests_are_refused_before_their_body(self):
        import http.client
        for path, length in (("/v1/exchange", relay.MAX_BODY_BYTES), ("/v1/join", 64 * 1024)):
            c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
            c.putrequest("POST", path)
            c.putheader("Content-Type", "application/json")
            c.putheader("Content-Length", str(length))
            c.endheaders()                       # no body is sent: the answer must not wait for one
            self.assertIn(c.getresponse().status, (401, 413))
            c.close()

    def test_only_https_or_loopback_http(self):
        self.assertEqual("https://relay.example.com", relay.check_url("https://relay.example.com/"))
        self.assertEqual("http://127.0.0.1:7790", relay.check_url("http://127.0.0.1:7790"))
        self.refused("bad_url", relay.check_url, "http://relay.example.com")
        self.refused("bad_url", relay.check_url, "https://relay.example.com/path")


class TailmsgRelayIdentityTests(unittest.TestCase):
    def test_a_tailscale_name_never_passes_for_a_relay_device(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "config.json").write_text("{}")
            ctx = core.Ctx(temp)
            ctx.ts = lambda *args, **kw: json.dumps({"Node": {"Name": "alpha.relay."}})
            self.assertIsNone(ctx.whois_uncached("100.64.0.9"))

    def test_relay_identity_follows_the_access_policy(self):
        ident = core.relay_ident("alpha", "ab" * 16)
        self.assertEqual((True, "tailnet"), core.access_decision({}, ident))
        self.assertEqual((False, "denied"), core.access_decision({"deny": ["alpha.relay"]}, ident))
        self.assertEqual((True, "allowlist"), core.access_decision({"allow": ["alpha.relay"]}, ident))
        self.assertEqual((False, "not_allowed"), core.access_decision({"allow": ["bravo.relay"]}, ident))
        self.assertTrue(core.access_decision({"allow": [core.peer_identity(ident)]}, ident)[0])

    def test_config_relay_mode_is_validated(self):
        self.assertEqual("only", core.parse_config({"relay": "only"})[0]["relay"])
        with self.assertRaises(RuntimeError):
            core.parse_config({"relay": "maybe"})


class RelayRuntimeAndDoctorTests(unittest.TestCase):
    """install-runtime carries the relay files with the runtime; doctor checks a relay-only home without Tailscale."""

    @classmethod
    def setUpClass(cls):
        cls.pkg = Package()
        cls.user = cls.pkg.new_home("runtime user")

    @classmethod
    def tearDownClass(cls):
        cls.pkg.cleanup()

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(dir=str(self.pkg.root), prefix="home "))
        (self.home / "config.json").write_text(json.dumps({"relay": "only"}))

    def run_json(self, *args):
        r = self.pkg.run(["--home", str(self.home)] + list(args) + ["--json"], self.user)
        return r, json.loads(r.stdout)

    def companions(self, res):
        return {c["name"]: c["state"] for c in res["companions"]}

    def test_install_runtime_writes_the_relay_files_with_the_runtime(self):
        scripts = self.pkg.plugin / "scripts"
        r, res = self.run_json("install-runtime")
        self.assertEqual({"relay.py": "absent", "public_bots/bot_e2e.py": "absent"}, self.companions(res))
        self.assertFalse((self.home / "relay.py").exists(), "a dry run writes nothing")
        r, res = self.run_json("install-runtime", "--apply")
        self.assertEqual((0, "install"), (r.returncode, res["action"]))
        self.assertEqual({"relay.py": "written", "public_bots/bot_e2e.py": "written"}, self.companions(res))
        for name in ("relay.py", "public_bots/bot_e2e.py"):
            self.assertEqual((scripts / name).read_bytes(), (self.home / name).read_bytes())
        (self.home / "relay.py").unlink()            # an already current runtime still gets a missing relay file
        r, res = self.run_json("install-runtime", "--apply")
        self.assertEqual(("none", "written", "current"), (res["action"], self.companions(res)["relay.py"],
                                                          self.companions(res)["public_bots/bot_e2e.py"]))

    def test_a_refused_runtime_gets_no_relay_files(self):
        (self.home / "tailmsg.py").write_text("# a different running receiver\n")
        r, res = self.run_json("install-runtime", "--apply")
        self.assertEqual((1, "refused"), (r.returncode, res["action"]))
        self.assertFalse((self.home / "relay.py").exists())

    def test_doctor_checks_a_relay_only_home_without_tailscale(self):
        (self.home / "tailmsg.py").write_bytes(self.pkg.core.read_bytes())       # runtime without its relay files
        r, res = self.run_json("doctor")
        checks = {c["check"]: c for c in res["checks"]}
        self.assertEqual("info", checks["tailscale"]["status"])
        self.assertIn("not used", checks["tailscale"]["detail"])
        self.assertEqual("info", checks["receiver"]["status"])
        self.assertEqual("error", checks["relay"]["status"])
        self.assertIn("relay join", checks["relay"]["fix"])
        self.assertEqual("error", checks["relay-runtime"]["status"])
        self.assertIn("install-runtime", checks["relay-runtime"]["fix"])
        self.pkg.run(["--home", str(self.home), "install-runtime", "--apply"], self.user)
        r, res = self.run_json("doctor")
        self.assertNotIn("relay-runtime", [c["check"] for c in res["checks"]])


class RelayLoopbackTests(unittest.TestCase):
    """alpha and bravo talk only through the relay: no tailscale on PATH, no listening receiver port."""

    @classmethod
    def setUpClass(cls):
        cls.pkg = pkg = Package()
        cls.user = pkg.new_home("relay user")
        cls.procs = []
        cls.wake_log = pkg.root / "codex wake.log"
        adapter = pkg.root / "codex wake.sh"
        adapter.write_text(ADAPTER % cls.wake_log)
        adapter.chmod(0o755)
        relay_home, port = pkg.root / "relay data", free_port()
        cls.run_ok(["relay", "server", "init", "--relay-home", str(relay_home), "--port", str(port)])
        cls.start(["relay", "server", "serve", "--relay-home", str(relay_home)], "relay")
        url = "http://127.0.0.1:%d" % port
        cls.home = {"alpha": pkg.root / "alpha data", "bravo": pkg.root / "bravo data"}
        configs = {"alpha": {"relay": "only", "self_agent": "grok", "default_agent": "grok", "agents": {"grok": {}}},
                   "bravo": {"relay": "only", "self_agent": "codex", "default_agent": "codex",
                             "agents": {"codex": {"wake_adapter": {"type": "exec", "argv": [str(adapter)]}}},
                             "wake_policy": {"default_max": "batch", "peers": {"alpha.relay": "now"}}}}
        for name, cfg in configs.items():
            cls.home[name].mkdir()
            (cls.home[name] / "config.json").write_text(json.dumps(cfg))
            if not wait_for(lambda: cls.try_invite(relay_home, name), timeout=10):
                raise RuntimeError("relay server did not start")
            cls.run_ok(["--home", str(cls.home[name]), "relay", "join", url, "--name", name,
                        "--invite", cls.invites[name]])
        fp = {name: cls.run_json(["--home", str(cls.home[name]), "relay", "whoami"])["fingerprint"]
              for name in cls.home}
        cls.run_ok(["--home", str(cls.home["alpha"]), "relay", "trust", "bravo", "--fingerprint", fp["bravo"]])
        cls.run_ok(["--home", str(cls.home["bravo"]), "relay", "trust", "alpha", "--fingerprint", fp["alpha"]])
        # alpha runs the bundled tailmsg.py; bravo runs like a service: the runtime install-runtime copied into
        # its data home, with the relay files next to it.
        cls.start(["--home", str(cls.home["alpha"]), "serve"], "alpha")
        cls.run_ok(["--home", str(cls.home["bravo"]), "install-runtime", "--apply"])
        cls.start([str(cls.home["bravo"] / "tailmsg.py"), "--home", str(cls.home["bravo"]), "serve"], "bravo",
                  launcher=False)
        for name, peer in (("alpha", "bravo"), ("bravo", "alpha")):
            if not wait_for(lambda: cls.ping(name, peer) == 200, timeout=20):
                cls.tearDownClass()
                raise RuntimeError("%s cannot reach %s through the relay" % (name, peer))

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except OSError:
                pass
            p.wait(timeout=10)
        cls.procs = []
        cls.pkg.cleanup()

    @classmethod
    def run_ok(cls, args):
        r = cls.pkg.run(args, cls.user)
        if r.returncode != 0:
            raise AssertionError("%s failed:\n%s%s" % (args, r.stdout, r.stderr))
        return r

    @classmethod
    def run_json(cls, args):
        return json.loads(cls.run_ok(args).stdout.splitlines()[-1])

    @classmethod
    def try_invite(cls, relay_home, name):
        r = cls.pkg.run(["relay", "server", "invite", "--relay-home", str(relay_home), name], cls.user)
        if r.returncode == 0:
            cls.invites = getattr(cls, "invites", {})
            cls.invites[name] = json.loads(r.stdout)["invite"]
        return r.returncode == 0

    @classmethod
    def start(cls, args, name, launcher=True):
        log = open(str(cls.pkg.root / ("%s.log" % name)), "w")
        cmd = ["/bin/sh", str(cls.pkg.launcher)] if launcher else [sys.executable]
        cls.procs.append(subprocess.Popen(cmd + args, env=cls.pkg.env(cls.user),
                                          cwd=str(cls.pkg.work), stdout=log, stderr=subprocess.STDOUT,
                                          start_new_session=True))
        log.close()

    @classmethod
    def ping(cls, who, peer):
        r = cls.pkg.run(["--home", str(cls.home[who]), "relay", "ping", peer], cls.user)
        return json.loads(r.stdout)["status"] if r.returncode == 0 else None

    def tm(self, who, *args):
        return self.pkg.run(["--home", str(self.home[who])] + list(args), self.user)

    def tm_json(self, who, *args):
        r = self.tm(who, *args)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        return json.loads(r.stdout.splitlines()[-1] if args[0] in ("send", "reply") else r.stdout)

    def inbox(self, who):
        d = self.home[who] / "inbox"
        return [json.loads(p.read_text()) for p in sorted(d.glob("*.json"))] if d.is_dir() else []

    def wakes(self):
        return self.wake_log.read_text().splitlines() if self.wake_log.exists() else []

    def test_1_message_wakes_codex_and_the_reply_comes_back(self):
        self.assertFalse((self.pkg.bin / "tailscale").exists())
        out = self.tm_json("alpha", "send", "bravo.relay/codex", "please review", "--wake", "now")
        self.assertEqual((202, "bravo.relay", "codex"), (out["status"], out["to"], out["agent"]))
        mid = out["id"]
        self.assertTrue(wait_for(lambda: self.wakes() == ["codex %s" % mid]), self.wakes())
        rec = self.tm_json("bravo", "show", mid)
        peer = rec["received"]["peer"]
        self.assertEqual(("alpha.relay", "relay", "now"), (peer["node"], peer["transport"],
                                                           rec["received"]["wake"]["effective"]))
        self.assertNotIn("ip", peer)
        self.assertEqual("grok", rec["envelope"]["from_agent"])

        rep = self.tm_json("bravo", "reply", mid, "done, thanks")
        self.assertEqual((202, "grok"), (rep["status"], rep["agent"]))
        replies = [x for x in self.inbox("alpha") if x["envelope"].get("reply_to") == mid]
        self.assertEqual(["bravo.relay"], [x["received"]["peer"]["node"] for x in replies])

    def status(self, who, mid, *extra):
        return self.tm_json(who, "request", "status", mid, "--json", *extra)

    def test_2_info_advertises_requests_and_attachments_are_still_refused(self):
        info = self.run_json(["--home", str(self.home["alpha"]), "relay", "info", "bravo"])
        self.assertEqual((200, "bravo.relay"), (info["status"], info["response"]["node"]))
        self.assertLessEqual({"request-lifecycle-v1", "request-pull-v1"}, set(info["response"]["capabilities"]))
        before = len(self.inbox("bravo"))
        report = self.pkg.root / "notes.txt"
        report.write_text("notes")
        for args in (("send", "bravo.relay", "with a file"), ("request", "send", "bravo.relay/codex", "with a file")):
            r = self.tm("alpha", *(args + ("--file", str(report))))
            self.assertNotEqual(0, r.returncode)
            self.assertIn("attachments are not carried", r.stderr)
        self.assertEqual(before, len(self.inbox("bravo")))

    def test_3_untrusting_a_sender_refuses_its_next_message(self):
        before = len(self.inbox("bravo"))
        self.run_ok(["--home", str(self.home["bravo"]), "relay", "untrust", "alpha"])
        try:
            r = self.tm("alpha", "send", "bravo.relay", "are you there?")
            self.assertNotEqual(0, r.returncode)
            self.assertIn("peer_refused", r.stderr)
            self.assertNotIn("Delivery is unknown", r.stderr)
            self.assertEqual(before, len(self.inbox("bravo")))
        finally:
            fp = self.run_json(["--home", str(self.home["alpha"]), "relay", "whoami"])["fingerprint"]
            self.run_ok(["--home", str(self.home["bravo"]), "relay", "trust", "alpha", "--fingerprint", fp])


    def test_4_a_push_request_reports_its_receipt_start_and_result(self):
        out = self.tm_json("alpha", "request", "send", "bravo.relay/codex", "run the tests", "--wake", "now")
        self.assertEqual((202, "accepted", "bravo.relay"), (out["status"], out["submission"], out["to"]))
        mid = out["id"]
        self.assertTrue(wait_for(lambda: "codex %s" % mid in self.wakes()), self.wakes())
        self.assertEqual("alpha.relay", self.status("bravo", mid, "--direction", "incoming")["peer"])
        # bravo's receiver pushes each response back through the relay; alpha's receiver records it.
        self.assertTrue(wait_for(lambda: self.status("alpha", mid)["state"] == "received", timeout=20))
        self.tm_json("bravo", "request", "respond", mid, "started", "--state", "running")
        self.assertTrue(wait_for(lambda: self.status("alpha", mid)["state"] == "running", timeout=20))
        report = self.pkg.root / "results.txt"
        report.write_text("all green")
        r = self.tm("bravo", "reply", mid, "see the file", "--file", str(report))
        self.assertNotEqual(0, r.returncode)
        self.assertIn("attachments are not carried", r.stderr)
        self.assertTrue(self.tm_json("bravo", "reply", mid, "all green")["queued"])
        self.assertTrue(wait_for(lambda: self.status("alpha", mid)["state"] == "completed", timeout=20))
        done = self.status("alpha", mid, "--refresh")
        self.assertEqual(("ok", "completed", "all green", True),
                         (done["refresh"], done["state"], done["response"]["text"], done["outcome_known"]))

    def test_5_a_pull_request_result_waits_for_refresh(self):
        out = self.tm_json("alpha", "request", "send", "bravo.relay/codex", "summarise the logs",
                           "--transport", "pull")
        self.assertEqual((202, "accepted", "pull"), (out["status"], out["submission"], out["transport"]))
        mid = out["id"]
        kid = relay.fingerprint_kid(self.run_json(["--home", str(self.home["alpha"]), "relay", "whoami"])["fingerprint"])
        owner = "node:" + ("relay-" + kid).encode("ascii").hex()
        self.assertEqual(owner, self.status("bravo", mid, "--direction", "incoming")["peer"])
        resumed = self.tm_json("alpha", "request", "resume", mid)      # the same request again: a duplicate
        self.assertEqual((200, "accepted"), (resumed["status"], resumed["submission"]))
        self.assertTrue(self.tm_json("bravo", "reply", mid, "three warnings")["stored"])
        self.assertNotIn(self.status("alpha", mid)["state"], ("received", "completed"))   # nothing is pushed
        done = self.status("alpha", mid, "--refresh")
        self.assertEqual(("ok", "completed", "three warnings"),
                         (done["refresh"], done["state"], done["response"]["text"]))
        # A sender whose key bravo no longer trusts cannot read the status, even with the request ID.
        self.run_ok(["--home", str(self.home["bravo"]), "relay", "untrust", "alpha"])
        try:
            again = self.status("alpha", mid, "--refresh")
            self.assertEqual("unavailable", again["refresh"])
            self.assertIn("peer_refused", again["refresh_error"])
        finally:
            fp = self.run_json(["--home", str(self.home["alpha"]), "relay", "whoami"])["fingerprint"]
            self.run_ok(["--home", str(self.home["bravo"]), "relay", "trust", "alpha", "--fingerprint", fp])


if __name__ == "__main__":
    unittest.main()
