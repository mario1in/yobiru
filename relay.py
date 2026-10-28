#!/usr/bin/env python3
"""relay - carry tailmsg protocol v1 between your own devices over outbound HTTPS (relay-v1).

A relay you host routes sealed frames between the devices you enrolled. It keeps no messages: a frame waits in
memory only while its sender waits for the answer, as with a direct connection. It cannot open, change or forge
a frame: each one is sealed with public_bots/bot_e2e.py for the receiver's X25519 key and authenticated by the
sender's, and a device exchanges frames only with peers whose fingerprints it trusted explicitly. Device names
appear to tailmsg as NAME.relay. See docs/RELAY_DESIGN.md. Python 3.8+ stdlib only.

  relay.py server init    --relay-home DIR [--port 7790] [--bind 127.0.0.1]
  relay.py server serve   --relay-home DIR
  relay.py server invite  --relay-home DIR NAME          one-time code for one device, valid one hour
  relay.py server devices --relay-home DIR
  relay.py server revoke  --relay-home DIR NAME
  relay.py --home HOME join URL --name NAME --invite CODE
  relay.py --home HOME whoami | directory | trusted
  relay.py --home HOME trust NAME --fingerprint FP | untrust NAME
  relay.py --home HOME ping NAME | info NAME
"""
import argparse, collections, datetime as dt, hashlib, http.client, importlib.util, ipaddress, json, os
import re, secrets, sqlite3, ssl, sys, threading, time, urllib.parse
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = 1
SUFFIX = ".relay"                   # tailmsg node name of a relay device: NAME.relay
DEFAULT_PORT = 7790
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
FRAME_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}\Z")
PATH_RE = re.compile(r"^/[\x21-\x7e]{0,2047}\Z")
METHODS = ("GET", "POST")           # request uploads (PUT) wait for phase 3
MAX_FRAME_BYTES = 2 << 20           # sealed ciphertext per frame
MAX_BODY_BYTES = MAX_FRAME_BYTES * 2  # JSON request to the relay (base64 and envelope overhead)
POLL_WAIT_MAX = 25
POLL_BATCH = 16
EXCHANGE_TIMEOUT_MAX = 60
OFFLINE_AFTER = 40                  # seconds without a poll before a device counts as offline
QUEUE_MAX = 64
INVITE_TTL = 3600
CLOCK_SKEW = 300
REPLAY_TTL = 600

_e2e = None


def e2e():
    """public_bots/bot_e2e.py next to this file (the same sealing as Friends; nothing else of Friends is used)."""
    global _e2e
    if _e2e is None:
        path = Path(__file__).parent / "public_bots" / "bot_e2e.py"
        spec = importlib.util.spec_from_file_location("yobiru_relay_e2e", str(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _e2e = module
    return _e2e


class RelayError(RuntimeError):
    """`code` is stable for callers; `unknown` is True when the peer may already have handled the frame."""

    def __init__(self, code, detail=None, unknown=False):
        RuntimeError.__init__(self, "%s%s" % (code, ": " + detail if detail else ""))
        self.code, self.unknown = code, unknown


def iso(t=None):
    return (t or dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text):
    return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def write_private(path, obj):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(4))
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(obj, stream, indent=2, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(str(temporary), str(path))


def read_json(path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def check_name(name):
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise RelayError("bad_name", "a device name is one DNS label: a-z, 0-9 and inner '-'")
    return name


def check_url(url):
    """https, or plain http only to this machine (local tests and a proxy on the same host)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("https", "http") or not u.hostname or u.path not in ("", "/") or u.query or u.fragment:
        raise RelayError("bad_url", "the relay URL is https://HOST[:PORT]")
    if u.scheme == "http":
        try:
            loopback = u.hostname == "localhost" or ipaddress.ip_address(u.hostname).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise RelayError("bad_url", "plain http is only allowed to a loopback address; use https")
    return "%s://%s" % (u.scheme, u.netloc)


def fingerprint_kid(text):
    kid = re.sub(r"\s+", "", str(text)).lower()
    if not re.fullmatch(r"[0-9a-f]{32}", kid):
        raise RelayError("bad_fingerprint", "a fingerprint is 32 hex digits (spaces are ignored)")
    return kid


def context(relay_id, from_kid, to_kid, frame_id, kind):
    # Binds the relay, both keys, the frame and its direction: a frame cannot be moved to another peer,
    # answer another request or be turned around.
    return ["yobiru-relay-v%d" % VERSION, relay_id, from_kid, to_kid, frame_id, kind]


# ---------------------------------------------------------------- server
class Registry(object):
    """Enrolled devices and invites in relay.sqlite3; the admin commands write it while the server runs."""

    def __init__(self, home):
        self.home = Path(home).expanduser()
        self.path = self.home / "relay.sqlite3"

    def db(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def create(self):
        with closing(self.db()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS devices (name TEXT NOT NULL, public_key TEXT NOT NULL,
                    token_sha256 TEXT NOT NULL UNIQUE, created TEXT NOT NULL, revoked TEXT);
                CREATE UNIQUE INDEX IF NOT EXISTS active_name ON devices(name) WHERE revoked IS NULL;
                CREATE TABLE IF NOT EXISTS invites (code_sha256 TEXT PRIMARY KEY, name TEXT NOT NULL,
                    expires REAL NOT NULL, used TEXT);""")
        os.chmod(str(self.path), 0o600)

    def device(self, token):
        with closing(self.db()) as db:
            return db.execute("SELECT * FROM devices WHERE token_sha256=? AND revoked IS NULL",
                              (digest(token),)).fetchone()

    def active(self, name=None):
        with closing(self.db()) as db:
            if name is not None:
                return db.execute("SELECT * FROM devices WHERE name=? AND revoked IS NULL", (name,)).fetchone()
            return db.execute("SELECT * FROM devices WHERE revoked IS NULL ORDER BY name").fetchall()

    def invite(self, name):
        code = secrets.token_urlsafe(24)
        with closing(self.db()) as db, db:
            db.execute("INSERT INTO invites VALUES (?, ?, ?, NULL)", (digest(code), check_name(name),
                                                                       time.time() + INVITE_TTL))
        return code

    def join(self, code, name, public_key):
        token = secrets.token_urlsafe(32)
        with closing(self.db()) as db, db:
            row = db.execute("SELECT * FROM invites WHERE code_sha256=?", (digest(code),)).fetchone()
            if row is None or row["used"] or row["expires"] < time.time() or row["name"] != name:
                raise RelayError("bad_invite", "unknown, used or expired invite, or another name")
            if db.execute("SELECT 1 FROM devices WHERE name=? AND revoked IS NULL", (name,)).fetchone():
                raise RelayError("name_taken", "revoke the existing device of this name first")
            db.execute("UPDATE invites SET used=? WHERE code_sha256=?", (iso(), digest(code)))
            db.execute("INSERT INTO devices VALUES (?, ?, ?, ?, NULL)", (name, public_key, digest(token), iso()))
        return token

    def revoke(self, name):
        with closing(self.db()) as db, db:
            return db.execute("UPDATE devices SET revoked=? WHERE name=? AND revoked IS NULL",
                              (iso(), name)).rowcount


class Hub(object):
    """In-memory routing only. A frame lives while its sender waits; nothing is written to disk."""

    def __init__(self):
        self.cond = threading.Condition()
        self.queues, self.pending, self.seen, self.polling = {}, {}, {}, {}

    def online(self, name):
        return self.polling.get(name, 0) > 0 or time.monotonic() - self.seen.get(name, -1e9) <= OFFLINE_AFTER

    def exchange(self, sender, target, frame_id, sealed, timeout):
        with self.cond:
            if frame_id in self.pending:
                return 409, {"error": "duplicate_frame"}
            if not self.online(target):
                return 503, {"error": "peer_offline"}
            queue = self.queues.setdefault(target, collections.deque())
            if len(queue) >= QUEUE_MAX:
                return 429, {"error": "peer_busy"}
            item = (frame_id, sender, sealed)
            entry = self.pending[frame_id] = {"to": target, "answer": None, "taken": False}
            queue.append(item)
            self.cond.notify_all()
            end = time.monotonic() + timeout
            while entry["answer"] is None and time.monotonic() < end:
                self.cond.wait(end - time.monotonic())
            del self.pending[frame_id]
            if entry["answer"] is not None:
                return entry["answer"]
            if not entry["taken"]:
                queue.remove(item)
            return 504, {"error": "peer_timeout", "taken": entry["taken"]}

    def poll(self, name, wait):
        with self.cond:
            self.polling[name] = self.polling.get(name, 0) + 1
            try:
                queue = self.queues.setdefault(name, collections.deque())
                end = time.monotonic() + wait
                while not queue and time.monotonic() < end:
                    self.cond.wait(end - time.monotonic())
                frames = []
                while queue and len(frames) < POLL_BATCH:
                    frame_id, sender, sealed = queue.popleft()
                    self.pending[frame_id]["taken"] = True
                    frames.append({"frame_id": frame_id, "from": sender, "sealed": sealed})
                return frames
            finally:
                self.polling[name] -= 1
                self.seen[name] = time.monotonic()

    def answer(self, name, frame_id, result):
        with self.cond:
            entry = self.pending.get(frame_id)
            if entry is None or entry["to"] != name or not entry["taken"] or entry["answer"] is not None:
                return False
            entry["answer"] = result
            self.cond.notify_all()
            return True


def make_server_handler(registry, hub, relay_id):
    class H(BaseHTTPRequestHandler):
        server_version = "yobiru-relay/%d" % VERSION
        sys_version = ""

        def log_message(self, fmt, *args):
            print("relay:", fmt % args, file=sys.stderr, flush=True)

        def reply(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def body(self, limit):
            try:
                n = int(self.headers.get("Content-Length") or "-1")
            except ValueError:
                n = -1
            if not 0 <= n <= limit or not (self.headers.get("Content-Type") or "").startswith("application/json"):
                self.close_connection = True
                self.reply(413 if n > limit else 400, {"error": "bad_request"})
                return None
            try:
                obj = json.loads(self.rfile.read(n).decode("utf-8"))
            except ValueError:
                obj = None
            if not isinstance(obj, dict):
                self.reply(400, {"error": "bad_request"})
                return None
            return obj

        def device(self):
            auth = self.headers.get("Authorization") or ""
            row = registry.device(auth[7:]) if auth.startswith("Bearer ") and len(auth) < 200 else None
            if row is None:
                self.reply(401, {"error": "unauthorized"})
            return row

        def sealed_ok(self, sealed):
            error = e2e().envelope_error(sealed, MAX_FRAME_BYTES)
            if error:
                self.reply(400, {"error": "bad_frame", "detail": error})
            return error is None

        def do_GET(self):
            if self.path == "/v1/health":
                return self.reply(200, {"ok": True, "relay": "yobiru-relay", "v": VERSION, "relay_id": relay_id})
            if self.path == "/v1/directory":
                if self.device() is None:
                    return
                return self.reply(200, {"relay_id": relay_id, "devices": [
                    {"name": row["name"], "public_key": row["public_key"], "kid": e2e().kid(row["public_key"]),
                     "online": hub.online(row["name"])} for row in registry.active()]})
            self.reply(404, {"error": "not_found"})

        def do_POST(self):
            route = self.path
            if route not in ("/v1/join", "/v1/poll", "/v1/answer", "/v1/exchange"):
                return self.reply(404, {"error": "not_found"})
            # Authenticate before reading a large body; only a small join request is read unauthenticated.
            me = self.device() if route != "/v1/join" else None
            if route != "/v1/join" and me is None:
                return
            body = self.body(MAX_BODY_BYTES if me is not None else 16 * 1024)
            if body is None:
                return
            if route == "/v1/join":
                try:
                    name = check_name(body.get("name"))
                    if e2e().key_error(body.get("public_key")):
                        raise RelayError("bad_key")
                    token = registry.join(str(body.get("invite") or ""), name, body["public_key"])
                except RelayError as exc:
                    return self.reply(409 if exc.code == "name_taken" else 403, {"error": exc.code})
                return self.reply(201, {"name": name, "token": token, "relay_id": relay_id})
            if route == "/v1/poll":
                wait = body.get("wait_s", POLL_WAIT_MAX)
                wait = min(max(wait, 0), POLL_WAIT_MAX) if type(wait) in (int, float) else POLL_WAIT_MAX
                return self.reply(200, {"frames": hub.poll(me["name"], wait)})
            frame_id = body.get("frame_id")
            if not isinstance(frame_id, str) or not FRAME_ID_RE.match(frame_id):
                return self.reply(400, {"error": "bad_frame"})
            if route == "/v1/answer":
                if "error" in body:
                    code = body["error"] if isinstance(body["error"], str) and re.fullmatch(r"[a-z_]{1,40}", body["error"]) else "refused"
                    result = (502, {"error": "peer_refused", "detail": code})
                elif self.sealed_ok(body.get("sealed")):
                    result = (200, {"sealed": body["sealed"]})
                else:
                    return
                answered = hub.answer(me["name"], frame_id, result)
                return self.reply(200 if answered else 404, {"ok": answered})
            target = body.get("to")
            timeout = body.get("timeout_s", 15)
            if not isinstance(target, str) or registry.active(target) is None:
                return self.reply(404, {"error": "unknown_device"})
            if type(timeout) not in (int, float) or not 0 < timeout <= EXCHANGE_TIMEOUT_MAX:
                return self.reply(400, {"error": "bad_timeout"})
            if not self.sealed_ok(body.get("sealed")):
                return
            status, result = hub.exchange(me["name"], target, frame_id, body["sealed"], timeout)
            self.reply(status, result)

    return H


def server_config(home):
    cfg = read_json(Path(home).expanduser() / "relay.json")
    if not isinstance(cfg, dict):
        raise RelayError("not_initialized", "run `relay server init --relay-home %s` first" % home)
    return cfg


def cmd_server(a):
    home = Path(a.relay_home).expanduser()
    registry = Registry(home)
    if a.server_cmd == "init":
        if (home / "relay.json").exists():
            raise RelayError("exists", "%s already holds a relay" % home)
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(str(home), 0o700)
        registry.create()
        write_private(home / "relay.json", {"bind": a.bind, "port": a.port, "relay_id": secrets.token_hex(16)})
        return {"initialized": str(home), "bind": a.bind, "port": a.port}
    cfg = server_config(home)
    if a.server_cmd == "invite":
        return {"name": a.name, "invite": registry.invite(a.name), "expires_in_s": INVITE_TTL}
    if a.server_cmd == "devices":
        return {"devices": [{"name": r["name"], "fingerprint": e2e().fingerprint(r["public_key"]),
                             "created": r["created"]} for r in registry.active()]}
    if a.server_cmd == "revoke":
        if not registry.revoke(check_name(a.name)):
            raise RelayError("unknown_device", a.name)
        return {"revoked": a.name}
    hub = Hub()
    srv = ThreadingHTTPServer((cfg["bind"], int(cfg["port"])), make_server_handler(registry, hub, cfg["relay_id"]))
    srv.daemon_threads = True
    print(json.dumps({"listening": "http://%s:%d" % srv.server_address[:2]}), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return None


# ---------------------------------------------------------------- device
class Device(object):
    """This machine's enrollment (HOME/relay/device.json) and the peers it trusts (HOME/relay/trusted.json)."""

    def __init__(self, home):
        self.dir = Path(home).expanduser() / "relay"
        cfg = read_json(self.dir / "device.json")
        if not isinstance(cfg, dict):
            raise RelayError("not_joined", "no %s; run `relay join` on this device" % (self.dir / "device.json"))
        self.url, self.name, self.token = cfg["relay"], cfg["name"], cfg["token"]
        self.secret, self.public, self.relay_id = cfg["secret_key"], cfg["public_key"], cfg["relay_id"]
        self.kid = e2e().kid(self.public)
        self._seen, self._seen_lock = {}, threading.Lock()

    @property
    def node(self):
        return self.name + SUFFIX

    def unchanged(self):
        """False once device.json names another key or device than this process started with."""
        cfg = read_json(self.dir / "device.json") or {}
        return cfg.get("name") == self.name and cfg.get("public_key") == self.public

    def canonical(self, host):
        """'work-mini.relay' (any case, trailing dot) -> its device name."""
        h = str(host).lower().rstrip(".")
        if not h.endswith(SUFFIX):
            raise RelayError("bad_name", "%r is not a NAME.relay address" % host)
        return check_name(h[:-len(SUFFIX)])

    def trusted(self):
        return read_json(self.dir / "trusted.json", {}) or {}

    def trusted_key(self, name):
        entry = self.trusted().get(name)
        return entry.get("public_key") if isinstance(entry, dict) else None

    # -------- the relay's own API
    def call(self, method, path, body=None, timeout=20):
        u = urllib.parse.urlsplit(self.url)
        conn = http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=ssl.create_default_context()) \
            if u.scheme == "https" else http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
        headers = {"Authorization": "Bearer " + self.token}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=data, headers=headers)
            response = conn.getresponse()
            raw = response.read(MAX_BODY_BYTES + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise RelayError("relay_unreachable", "%s %s: %s" % (method, path, exc), unknown=path == "/v1/exchange")
        finally:
            conn.close()
        try:
            obj = json.loads(raw.decode("utf-8"))
        except ValueError:
            obj = None
        if response.status == 401:
            raise RelayError("unauthorized", "the relay refused this device's credential (revoked?)")
        return response.status, obj if isinstance(obj, dict) else {}

    def directory(self):
        status, body = self.call("GET", "/v1/directory")
        if status != 200 or body.get("relay_id") != self.relay_id or not isinstance(body.get("devices"), list):
            raise RelayError("bad_directory", "HTTP %d or another relay" % status)
        return body["devices"]

    # -------- frames
    def seal(self, peer_key, frame_id, kind, fields):
        plain = dict(fields, v=VERSION, kind=kind, frame_id=frame_id, ts=iso())
        return e2e().seal(e2e().canonical(plain), self.secret, [peer_key],
                          context(self.relay_id, self.kid, e2e().kid(peer_key), frame_id, kind))

    def open(self, sealed, peer, peer_key, frame_id, kind):
        try:
            plain = json.loads(e2e().open_sealed(sealed, self.secret, peer_key,
                                                 context(self.relay_id, e2e().kid(peer_key), self.kid, frame_id, kind)))
            ts = parse_iso(plain["ts"])
        except Exception:
            raise RelayError("frame_unopened", "not sealed by %s's trusted key for this frame" % peer)
        if (not isinstance(plain, dict) or plain.get("v") != VERSION or plain.get("kind") != kind or
                plain.get("frame_id") != frame_id or plain.get("from") != peer or plain.get("to") != self.name):
            raise RelayError("frame_mismatch")
        if abs((dt.datetime.now(dt.timezone.utc) - ts).total_seconds()) > CLOCK_SKEW:
            raise RelayError("clock_skew", "frame time differs by more than %d s; check both clocks" % CLOCK_SKEW)
        return plain

    def exchange(self, peer, method, path, body=b"", headers=None, timeout=15):
        """One HTTP exchange with a trusted peer through the relay -> (status, headers, body bytes)."""
        peer_key = self.trusted_key(check_name(peer))
        if not peer_key:
            raise RelayError("not_trusted", "%s is not trusted here; compare fingerprints, then `relay trust %s`"
                             % (peer, peer))
        frame_id = secrets.token_urlsafe(18)
        sealed = self.seal(peer_key, frame_id, "request", {
            "from": self.name, "to": peer, "method": method, "path": path, "headers": headers or {},
            "body": e2e().b64e(body)})
        timeout = min(max(1, int(timeout)), EXCHANGE_TIMEOUT_MAX)
        status, answer = self.call("POST", "/v1/exchange", {"to": peer, "frame_id": frame_id, "timeout_s": timeout,
                                                           "sealed": sealed}, timeout=timeout + 15)
        if status != 200:
            code = answer.get("error") or "relay_http_%d" % status
            detail = answer.get("detail")
            raise RelayError(code, detail, unknown=code == "peer_timeout" and answer.get("taken") is not False)
        try:
            plain = self.open(answer.get("sealed"), peer, peer_key, frame_id, "response")
            out_headers = plain["headers"] if isinstance(plain.get("headers"), dict) else {}
            return int(plain["status"]), out_headers, e2e().b64d(plain["body"])
        except RelayError as exc:
            raise RelayError(exc.code, "answer could not be verified", unknown=True)
        except (KeyError, TypeError, ValueError):
            raise RelayError("frame_mismatch", "malformed answer", unknown=True)

    def poll(self, wait=POLL_WAIT_MAX):
        status, body = self.call("POST", "/v1/poll", {"wait_s": wait}, timeout=wait + 15)
        if status != 200 or not isinstance(body.get("frames"), list):
            raise RelayError("relay_http_%d" % status)
        return body["frames"]

    def open_request(self, frame):
        """A polled frame -> (request fields, sender name, sender key). Raises RelayError to refuse it."""
        if not isinstance(frame, dict) or not FRAME_ID_RE.match(str(frame.get("frame_id"))):
            raise RelayError("bad_frame")
        sender = check_name(frame.get("from"))
        sender_key = self.trusted_key(sender)
        if not sender_key or sender == self.name:
            raise RelayError("sender_not_trusted", sender)
        req = self.open(frame.get("sealed"), sender, sender_key, frame["frame_id"], "request")
        headers = req.get("headers")
        if (req.get("method") not in METHODS or not isinstance(req.get("path"), str) or not PATH_RE.match(req["path"])
                or not isinstance(headers, dict) or set(headers) - {"Content-Type"} or
                not all(isinstance(v, str) and len(v) <= 200 and "\r" not in v and "\n" not in v
                        for v in headers.values())):
            raise RelayError("bad_request")
        try:
            req["body"] = e2e().b64d(req.get("body"))
        except Exception:
            raise RelayError("bad_request")
        now = time.monotonic()
        with self._seen_lock:
            self._seen = {k: t for k, t in self._seen.items() if t > now}
            key = (sender, frame["frame_id"])
            if key in self._seen:
                raise RelayError("replayed", frame["frame_id"])
            self._seen[key] = now + REPLAY_TTL
        return req, sender, sender_key

    def answer(self, frame_id, sender, sender_key, status, headers, body):
        sealed = self.seal(sender_key, frame_id, "response", {"from": self.name, "to": sender, "status": status,
                                                             "headers": headers, "body": e2e().b64e(body)})
        self.call("POST", "/v1/answer", {"frame_id": frame_id, "sealed": sealed})

    def refuse(self, frame_id, code):
        if isinstance(frame_id, str) and FRAME_ID_RE.match(frame_id):
            self.call("POST", "/v1/answer", {"frame_id": frame_id, "error": code})


def cmd_join(a):
    home = Path(a.home).expanduser()
    path = home / "relay" / "device.json"
    if path.exists():
        raise RelayError("exists", "%s already holds an enrollment; it is never replaced" % path)
    url, name = check_url(a.url), check_name(a.name)
    secret, public = e2e().generate()
    probe = Device.__new__(Device)
    probe.url, probe.token = url, ""
    status, body = probe.call("POST", "/v1/join", {"invite": a.invite, "name": name, "public_key": public})
    if status != 201 or body.get("name") != name or not body.get("token") or not body.get("relay_id"):
        raise RelayError(body.get("error") or "join_failed", "HTTP %d" % status)
    write_private(path, {"relay": url, "name": name, "token": body["token"], "relay_id": body["relay_id"],
                         "secret_key": secret, "public_key": public, "joined": iso()})
    return {"joined": url, "name": name, "node": name + SUFFIX, "fingerprint": e2e().fingerprint(public)}


def cmd_device(a):
    if a.cmd == "join":
        return cmd_join(a)
    device = Device(a.home)
    if a.cmd == "whoami":
        return {"name": device.name, "node": device.node, "relay": device.url,
                "fingerprint": e2e().fingerprint(device.public)}
    trusted = device.trusted()
    if a.cmd == "trusted":
        return {"trusted": [{"name": n, "node": n + SUFFIX, "fingerprint": e2e().fingerprint(e["public_key"]),
                             "trusted_at": e.get("trusted_at")} for n, e in sorted(trusted.items())]}
    if a.cmd == "directory":
        out = []
        for d in device.directory():
            pinned = (trusted.get(d.get("name")) or {}).get("public_key")
            out.append({"name": d.get("name"), "fingerprint": e2e().fingerprint(d["public_key"]),
                        "online": d.get("online"), "self": d.get("name") == device.name,
                        "trust": "trusted" if pinned == d["public_key"] else "key_changed" if pinned else "untrusted"})
        return {"devices": out}
    if a.cmd == "trust":
        name, kid = check_name(a.name), fingerprint_kid(a.fingerprint)
        if name == device.name:
            raise RelayError("self", "a device does not trust itself")
        entry = next((d for d in device.directory() if d.get("name") == name), None)
        if entry is None:
            raise RelayError("unknown_device", name)
        if e2e().key_error(entry.get("public_key")) or e2e().kid(entry["public_key"]) != kid:
            raise RelayError("fingerprint_mismatch", "the relay lists another key for %s; do not trust it" % name)
        trusted[name] = {"public_key": entry["public_key"], "trusted_at": iso()}
        write_private(device.dir / "trusted.json", trusted)
        return {"trusted": name, "node": name + SUFFIX, "fingerprint": e2e().fingerprint(entry["public_key"])}
    if a.cmd == "untrust":
        if trusted.pop(check_name(a.name), None) is None:
            raise RelayError("not_trusted", a.name)
        write_private(device.dir / "trusted.json", trusted)
        return {"untrusted": a.name}
    path = "/health" if a.cmd == "ping" else "/info"
    status, _, body = device.exchange(a.name, "GET", path, timeout=10)
    try:
        body = json.loads(body.decode("utf-8"))
    except ValueError:
        body = {"raw": body[:200].decode("utf-8", "replace")}
    return {"peer": a.name + SUFFIX, "status": status, "response": body}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="relay", description="tailmsg over a self-hosted relay (relay-v1)")
    ap.add_argument("--home", default=os.environ.get("TAILMSG_HOME", "~/.tailmsg"))
    sp = ap.add_subparsers(dest="cmd", required=True)
    srv = sp.add_parser("server", help="run and administer the relay (on the relay host)")
    ss = srv.add_subparsers(dest="server_cmd", required=True)
    for name in ("init", "serve", "invite", "devices", "revoke"):
        p = ss.add_parser(name)
        p.add_argument("--relay-home", required=True)
        if name == "init":
            p.add_argument("--port", type=int, default=DEFAULT_PORT)
            p.add_argument("--bind", default="127.0.0.1")
        if name in ("invite", "revoke"):
            p.add_argument("name")
    p = sp.add_parser("join", help="enroll this device with a one-time invite")
    p.add_argument("url")
    p.add_argument("--name", required=True)
    p.add_argument("--invite", required=True)
    for name in ("whoami", "directory", "trusted"):
        sp.add_parser(name)
    p = sp.add_parser("trust", help="trust a device after comparing its fingerprint on that device")
    p.add_argument("name")
    p.add_argument("--fingerprint", required=True)
    for name in ("untrust", "ping", "info"):
        sp.add_parser(name).add_argument("name")
    a = ap.parse_args(argv)
    try:
        out = cmd_server(a) if a.cmd == "server" else cmd_device(a)
    except RelayError as exc:
        print("relay: error: %s" % exc, file=sys.stderr)
        return 2
    if out is not None:
        print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
