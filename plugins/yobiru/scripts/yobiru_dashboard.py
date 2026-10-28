"""`yobiru dashboard`: a read-only local page of this device's message traffic.

Everything comes from the data home: the inbox (messages received), sent.jsonl (messages this machine sent,
written by tailmsg since the dashboard was added), the request ledger (tracked requests and the responses
waiting to be pushed back), maintenance.json (receiver health) and the tail of serve.log. Nothing is written,
nothing is sent to a peer, and the page is served on 127.0.0.1 only, behind a token in its URL.
"""
import argparse
import datetime as dt
import json
import re
import secrets
import sqlite3
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DAYS, MAX_DAYS = 7, 90
MAX_ROWS = 5000                     # newest rows per source kept in one summary
PREVIEW = 500                       # characters of message text per row (tailmsg's INBOX_PREVIEW)
LOG_TAIL = 256 << 10                # bytes of serve.log read for its recent problems
LOG_LINES = 60
LOG_ALERT = re.compile(r"WARNING|failed|rejected|gave up|error|could not|stopped|refused", re.I)
HEALTH_STALE = 180                  # seconds after which maintenance.json no longer says the receiver is up
FINAL = ("completed", "failed", "rejected", "blocked", "timed_out")


def parse_ts(value):
    """ISO time (tailmsg writes ...Z) -> epoch seconds, or None."""
    if not isinstance(value, str):
        return None
    try:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).timestamp()


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None


def node_key(node):
    return node.lower().rstrip(".") if isinstance(node, str) and node.strip(".") else "unknown"


def label_of(node):
    """grok.relay stays whole; a Tailscale name shows its host label, as `tailscale status` does."""
    if node.endswith(".relay") or node.startswith("node:") or node == "unknown":
        return node
    return node.split(".")[0]


def transport_of(node, hint=None):
    return "relay" if hint == "relay" or node.endswith(".relay") else "tailscale"


def preview(text):
    return text[:PREVIEW] if isinstance(text, str) else ""


def file_stats(files):
    files = [f for f in files if isinstance(f, dict)] if isinstance(files, list) else []
    return len(files), sum(f["size"] for f in files if isinstance(f.get("size"), int))


def incoming_status(rec):
    received, delivery = rec.get("received") or {}, rec.get("wake_delivery")
    if rec.get("acked_at"):
        return "processed"
    if isinstance(delivery, dict) and delivery.get("ok") is False:
        return "wake_failed"
    if received.get("agent_status") == "unknown":
        return "unknown_agent"
    if isinstance(delivery, dict) and delivery.get("ok"):
        return "woken"
    return "pending"


def read_inbox(home, since, aliases):
    """Messages received -> rows; also learns which `node:<hex>` ids (pull senders) belong to which name."""
    rows, unreadable = [], 0
    directory = home / "inbox"
    try:
        paths = sorted(directory.glob("*.json"))
    except OSError:
        paths = []
    for path in paths:
        rec = read_json(path)
        if not isinstance(rec, dict) or not isinstance(rec.get("envelope"), dict):
            unreadable += 1
            continue
        env, received = rec["envelope"], rec.get("received") or {}
        peer = received.get("peer") if isinstance(received.get("peer"), dict) else {}
        node = node_key(peer.get("node") or env.get("from"))
        if isinstance(peer.get("stable_id"), str):
            aliases["node:" + peer["stable_id"].encode("utf-8").hex()] = node
        if isinstance(env.get("from"), str) and env["from"].startswith("node:"):
            aliases[env["from"].lower()] = node
        at = parse_ts(received.get("at")) or parse_ts(env.get("ts"))
        if at is None or at < since:
            continue
        count, size = file_stats(env.get("fetch") or (env.get("request") or {}).get("uploads"))
        wake, delivery = received.get("wake") or {}, rec.get("wake_delivery")
        rows.append({"dir": "in", "id": env.get("id"), "at": iso(at), "peer": node,
                     "transport": transport_of(node, peer.get("transport")), "agent": received.get("agent"),
                     "from_agent": env.get("from_agent"), "kind": env.get("kind"), "text": preview(env.get("text")),
                     "files": count, "bytes": size, "reply_to": env.get("reply_to"),
                     "tracked": isinstance(env.get("request"), dict), "wake": wake.get("effective"),
                     "wake_reason": wake.get("reason"),
                     "wake_error": delivery.get("error") if isinstance(delivery, dict) else None,
                     "acked_at": rec.get("acked_at"), "status": incoming_status(rec),
                     "self": node_key(received.get("node")) if received.get("node") else None})
    return rows[-MAX_ROWS:], unreadable


def read_sent(home, since):
    rows, unreadable = [], 0
    try:
        lines = (home / "sent.jsonl").read_bytes().splitlines()
    except OSError:
        return rows, unreadable, False
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            unreadable += 1
            continue
        at = parse_ts(r.get("ts")) if isinstance(r, dict) else None
        if at is None:
            unreadable += 1
            continue
        if at < since:
            continue
        node = node_key(r.get("to"))
        ok = r.get("status") in (200, 202) and not r.get("error")
        rows.append({"dir": "out", "id": r.get("id"), "at": iso(at), "peer": node,
                     "transport": transport_of(node, r.get("transport")), "agent": r.get("agent"),
                     "from_agent": r.get("from_agent"), "kind": r.get("kind"), "text": preview(r.get("text")),
                     "files": r.get("files") or 0, "bytes": r.get("bytes") or 0, "reply_to": r.get("reply_to"),
                     "tracked": bool(r.get("tracked")), "http": r.get("status"), "error": r.get("error"),
                     "status": "delivered" if ok else "send_failed"})
    return rows[-MAX_ROWS:], unreadable, True


def read_ledger(home, since, now):
    """Tracked requests in the window (or still open), and responses not yet pushed back. Opened read-only."""
    path = home / "requests" / "ledger.sqlite3"
    out = {"requests": [], "outbox": [], "pushed": 0, "error": None}
    if not path.is_file():
        return out
    try:
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    except sqlite3.Error as exc:
        out["error"] = str(exc)
        return out
    db.row_factory = sqlite3.Row
    try:
        columns = {row[1] for row in db.execute("PRAGMA table_info(requests)")}
        for row in db.execute("SELECT * FROM requests ORDER BY rowid DESC LIMIT ?", (MAX_ROWS,)):
            try:
                env = json.loads(row["envelope"])
            except ValueError:
                env = {}
            ts = parse_ts(env.get("ts"))
            if row["state"] in FINAL and (ts is None or ts < since):
                continue
            item = {"direction": row["direction"], "id": row["id"], "peer": node_key(row["peer"]),
                    "state": row["state"], "submission": row["submission"], "deadline": row["deadline"],
                    "timed_out_at": row["timed_out_at"], "ts": env.get("ts"), "agent": env.get("agent"),
                    "text": preview(env.get("text")),
                    "pull": (env.get("request") or {}).get("transport") == "pull"}
            for name in ("received_at", "started_at", "final_at"):
                item[name] = row[name] if name in columns else None
            out["requests"].append(item)
        for row in db.execute("SELECT request_id, peer, attempts, next_attempt, last_error FROM response_outbox "
                              "WHERE delivered_at IS NULL ORDER BY next_attempt LIMIT ?", (MAX_ROWS,)):
            out["outbox"].append({"request_id": row["request_id"], "peer": node_key(row["peer"]),
                                  "attempts": row["attempts"], "last_error": row["last_error"],
                                  "next_attempt": iso(max(row["next_attempt"], now)) if row["next_attempt"] else None})
        out["pushed"] = db.execute("SELECT COUNT(*) FROM response_outbox WHERE delivered_at>=?", (iso(since),)).fetchone()[0]
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    finally:
        db.close()
    return out


def read_log(home):
    """The most recent serve.log lines that report a problem."""
    path = home / "serve.log"
    try:
        with path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - LOG_TAIL))
            data = f.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()[1 if size > LOG_TAIL else 0:]
    return [line[:400] for line in lines if LOG_ALERT.search(line)][-LOG_LINES:]


def receiver_health(home, now):
    m = read_json(home / "maintenance.json")
    if not isinstance(m, dict):
        return {"status": "unknown", "written_at": None, "reasons": []}
    written = parse_ts(m.get("written_at"))
    status = m.get("status") or "unknown"
    if written is None or now - written > HEALTH_STALE:
        status = "stale"
    return {"status": status, "written_at": m.get("written_at"), "started_at": m.get("started_at"),
            "reasons": [str(r) for r in m.get("reasons") or []][:10]}


def summary(home, days=DAYS, now=None):
    home = Path(home)
    now = now if now is not None else dt.datetime.now(dt.timezone.utc).timestamp()
    days = max(1, min(int(days), MAX_DAYS))
    since = now - days * 86400
    cfg = read_json(home / "config.json") or {}
    aliases = {}
    incoming, bad_inbox = read_inbox(home, since, aliases)
    outgoing, bad_sent, sent_log = read_sent(home, since)
    ledger = read_ledger(home, since, now)
    # A pull sender is known by its StableID; show the name its own messages arrived under.
    for item in incoming + outgoing + ledger["requests"] + ledger["outbox"]:
        item["peer"] = aliases.get(item["peer"], item["peer"])
        item.setdefault("transport", transport_of(item["peer"]))
    states = {(r["direction"], r["id"]): r["state"] for r in ledger["requests"]}
    for row in incoming:
        state = states.get(("incoming", row["id"]))
        if row["tracked"] and state:
            row["status"] = state
    for row in outgoing:
        state = states.get(("outgoing", row["id"]))
        if row["tracked"] and state and row["status"] == "delivered":
            row["status"] = state
    device = read_json(home / "relay" / "device.json") or {}
    trusted = read_json(home / "relay" / "trusted.json") or {}
    selves = [r["self"] for r in incoming if r.get("self")]
    me = {"node": selves[-1] if selves else None,
          "relay": device.get("name") + ".relay" if isinstance(device.get("name"), str) else None,
          "relay_url": device.get("relay") if isinstance(device.get("relay"), str) else None,
          "relay_mode": cfg.get("relay", "off"), "port": cfg.get("port", 7766),
          "self_agent": cfg.get("self_agent"), "default_agent": cfg.get("default_agent"),
          "agents": sorted(cfg.get("agents") or {}) if isinstance(cfg.get("agents"), dict) else []}
    peers = {}

    def peer(node, transport):
        return peers.setdefault(node, {"peer": node, "label": label_of(node), "transport": transport,
                                       "in": 0, "out": 0, "problems": 0, "files": 0, "bytes": 0, "last": None,
                                       "trusted": False})

    problems = ("wake_failed", "unknown_agent", "send_failed", "failed", "rejected", "blocked", "timed_out")
    for row in incoming + outgoing:
        p = peer(row["peer"], row["transport"])
        p[row["dir"]] += 1
        p["problems"] += row["status"] in problems
        p["files"] += row["files"]
        p["bytes"] += row["bytes"]
        p["last"] = max(p["last"] or "", row["at"])
    if isinstance(trusted, dict):
        for name in trusted:
            if isinstance(name, str):
                peer(node_key(name + ".relay"), "relay")["trusted"] = True
    for row in incoming:
        row.pop("self", None)
    messages = sorted(incoming + outgoing, key=lambda r: r["at"], reverse=True)[:MAX_ROWS]
    return {"generated_at": iso(now), "since": iso(since), "days": days, "home": str(home), "me": me,
            "receiver": receiver_health(home, now), "sent_log": sent_log,
            "peers": sorted(peers.values(), key=lambda p: (-(p["in"] + p["out"]), p["label"])),
            "messages": messages, "requests": ledger["requests"], "outbox": ledger["outbox"],
            "pushed": ledger["pushed"], "log": read_log(home),
            "unreadable": {"inbox": bad_inbox, "sent": bad_sent}, "ledger_error": ledger["error"]}


def make_handler(home, token, page):
    class H(BaseHTTPRequestHandler):
        server_version = "yobiru-dashboard"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def send(self, code, body, kind):
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; "
                             "style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            # The Host check keeps a web page that rebinds its own name to 127.0.0.1 from reading the summary.
            port = self.server.server_address[1]
            if self.headers.get("Host") not in ("127.0.0.1:%d" % port, "localhost:%d" % port):
                return self.send(403, b"forbidden\n", "text/plain; charset=utf-8")
            url = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(url.query)
            if not secrets.compare_digest(query.get("t", [""])[0], token):
                return self.send(403, b"open the link `yobiru dashboard` printed\n", "text/plain; charset=utf-8")
            if url.path == "/":
                return self.send(200, page, "text/html; charset=utf-8")
            if url.path == "/api/summary":
                try:
                    days = int(query.get("days", [DAYS])[0])
                except ValueError:
                    days = DAYS
                body = json.dumps(summary(home, days), ensure_ascii=False).encode("utf-8")
                return self.send(200, body, "application/json; charset=utf-8")
            return self.send(404, b"not found\n", "text/plain; charset=utf-8")

    return H


def start(home, port=0):
    """-> (server, url). The caller runs serve_forever."""
    token = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(Path(home), token, PAGE.encode("utf-8")))
    server.daemon_threads = True
    return server, "http://127.0.0.1:%d/?t=%s" % (server.server_address[1], token)


def main(home, argv):
    ap = argparse.ArgumentParser(prog="yobiru dashboard", allow_abbrev=False,
        description="Read-only local page of this device's traffic: messages received and sent, tracked "
                    "requests, responses waiting to be pushed back, receiver health and recent problems. "
                    "Served on 127.0.0.1 only; nothing is written or sent to a peer.")
    ap.add_argument("--port", type=int, default=0, help="local port (default: any free port)")
    ap.add_argument("--days", type=int, default=DAYS, help="how far back --json reads (the page has its own picker)")
    ap.add_argument("--json", action="store_true", help="print the summary once and exit")
    ap.add_argument("--no-open", action="store_true", help="do not open a browser")
    a = ap.parse_args(argv)
    if not 1 <= a.days <= MAX_DAYS:
        ap.error("--days must be 1..%d" % MAX_DAYS)
    if not (Path(home) / "config.json").is_file():
        print("error: no config.json in %s; run `yobiru setup` first or pass --home" % home, file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(summary(home, a.days), ensure_ascii=False, indent=2))
        return 0
    try:
        server, url = start(home, a.port)
    except OSError as exc:
        print("error: cannot listen on 127.0.0.1:%d: %s" % (a.port, exc), file=sys.stderr)
        return 2
    print(json.dumps({"dashboard": url, "home": str(home)}), flush=True)
    print("Ctrl-C stops it.", file=sys.stderr, flush=True)
    if not a.no_open:
        threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


PAGE = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Yobiru Dashboard</title>
<style>
:root {
  color-scheme: light;
  --bg: #f6f6f4; --surface: #fcfcfb; --surface-2: #f0efec; --border: #e3e2dd;
  --text: #0b0b0b; --text-2: #52514e; --muted: #7a7974;
  --in: #2a78d6; --out: #eb6834; --idle: #c9c8c2;
  --good: #0ca30c; --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
  --select: #2a78d6;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --bg: #121211; --surface: #1a1a19; --surface-2: #242422; --border: #34342f;
    --text: #f0efec; --text-2: #c3c2b7; --muted: #8f8e86;
    --in: #3987e5; --out: #d95926; --idle: #4a4a45; --select: #3987e5;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #121211; --surface: #1a1a19; --surface-2: #242422; --border: #34342f;
  --text: #f0efec; --text-2: #c3c2b7; --muted: #8f8e86;
  --in: #3987e5; --out: #d95926; --idle: #4a4a45; --select: #3987e5;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans", "Noto Sans CJK SC", sans-serif; }
main { max-width: 1180px; margin: 0 auto; padding: 20px 16px 48px; }
header { display: flex; flex-wrap: wrap; gap: 12px 24px; align-items: flex-end; justify-content: space-between; margin-bottom: 16px; }
h1 { font-size: 20px; margin: 0; letter-spacing: -0.01em; }
h2 { font-size: 15px; margin: 0; }
.sub { color: var(--text-2); font-size: 13px; display: flex; flex-wrap: wrap; gap: 4px 14px; margin-top: 4px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
select, input[type=search], button { font: inherit; font-size: 13px; color: var(--text); background: var(--surface);
  border: 1px solid var(--border); border-radius: 6px; padding: 5px 9px; }
button { cursor: pointer; }
button:hover { background: var(--surface-2); }
label.check { display: inline-flex; gap: 6px; align-items: center; font-size: 13px; color: var(--text-2); cursor: pointer; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 16px; min-width: 0; }
.card-head { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.hint { color: var(--muted); font-size: 12px; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 16px; }
.kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; }
.kpi .v { font-size: 26px; font-weight: 600; font-variant-numeric: tabular-nums; line-height: 1.2; }
.kpi .k { color: var(--text-2); font-size: 12px; }
.kpi .n { color: var(--muted); font-size: 12px; margin-top: 2px; }
.pill { display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; border-radius: 999px; border: 1px solid var(--border);
  background: var(--surface); font-size: 13px; }
.badge { display: inline-flex; align-items: center; gap: 5px; white-space: nowrap; font-size: 12px; color: var(--text); }
.ico { display: inline-grid; place-items: center; width: 15px; height: 15px; border-radius: 50%; color: #fff; font-size: 10px; font-weight: 700; line-height: 1; flex: none; }
.t-good { background: var(--good); } .t-bad { background: var(--critical); } .t-warn { background: var(--warning); color: #0b0b0b; }
.t-serious { background: var(--serious); color: #0b0b0b; } .t-active { background: var(--muted); } .t-none { background: var(--idle); }
.grid2 { display: grid; grid-template-columns: minmax(0, 3fr) minmax(0, 2fr); gap: 16px; }
@media (max-width: 860px) { .grid2 { grid-template-columns: minmax(0, 1fr); } }
.legend { display: flex; flex-wrap: wrap; gap: 4px 14px; font-size: 12px; color: var(--text-2); align-items: center; }
.legend svg { vertical-align: middle; margin-right: 5px; }
.via { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; line-height: 16px; padding: 0 6px; border-radius: 4px; white-space: nowrap; color: var(--text); }
.via-tailscale { background: var(--surface-2); border: 1px solid var(--border); }
.via-relay { border: 1px dashed var(--text-2); }
.sw { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 5px; vertical-align: -1px; }
svg text { fill: var(--text); }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { text-align: left; font-weight: 500; color: var(--text-2); font-size: 12px; padding: 6px 8px; border-bottom: 1px solid var(--border); white-space: nowrap; }
td { padding: 7px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr.row { cursor: pointer; }
tr.row:hover td { background: var(--surface-2); }
td.text { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-2); }
td.nowrap { white-space: nowrap; }
.num { font-variant-numeric: tabular-nums; text-align: right; }
.dir-in { color: var(--in); font-weight: 600; } .dir-out { color: var(--out); font-weight: 600; }
tr.detail td { background: var(--surface-2); }
.detail-grid { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 14px; font-size: 12px; }
.detail-grid dt { color: var(--muted); } .detail-grid dd { margin: 0; overflow-wrap: anywhere; }
.full { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 13px; color: var(--text); margin: 0 0 10px; }
.empty { color: var(--muted); padding: 18px 4px; text-align: center; font-size: 13px; }
.note { background: var(--surface-2); border-radius: 8px; padding: 8px 12px; font-size: 12px; color: var(--text-2); margin-bottom: 12px; }
pre.log { margin: 0; max-height: 260px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; color: var(--text-2); }
.more { margin-top: 10px; text-align: center; }
#tip { position: fixed; pointer-events: none; z-index: 10; background: var(--surface); color: var(--text); border: 1px solid var(--border);
  border-radius: 8px; padding: 8px 10px; font-size: 12px; box-shadow: 0 4px 16px rgba(0,0,0,.12); display: none; max-width: 280px; }
#tip b { font-weight: 600; }
.peer-card { cursor: pointer; }
.err { color: var(--critical); }
</style>
</head>
<body>
<main>
  <header>
    <div>
      <h1 id="title">Yobiru</h1>
      <div class="sub" id="sub"></div>
    </div>
    <div class="controls">
      <span id="health"></span>
      <select id="days" aria-label="range"></select>
      <label class="check"><input type="checkbox" id="auto"> <span id="auto-l"></span></label>
      <button id="refresh"></button>
    </div>
  </header>
  <div id="error" class="note err" hidden></div>
  <div class="kpis" id="kpis"></div>
  <div class="grid2">
    <section class="card">
      <div class="card-head"><h2 id="flow-h"></h2><div class="legend" id="flow-legend"></div></div>
      <div id="flow"></div>
    </section>
    <section class="card">
      <div class="card-head"><h2 id="act-h"></h2><div class="legend" id="act-legend"></div></div>
      <div id="activity"></div>
    </section>
  </div>
  <section class="card">
    <div class="card-head">
      <h2 id="msg-h"></h2>
      <div class="controls">
        <select id="f-peer"></select>
        <select id="f-via"></select>
        <select id="f-dir"></select>
        <label class="check"><input type="checkbox" id="f-bad"> <span id="f-bad-l"></span></label>
        <input type="search" id="f-q">
      </div>
    </div>
    <div id="sent-note" class="note" hidden></div>
    <div class="table-wrap" id="messages"></div>
  </section>
  <section class="card">
    <div class="card-head"><h2 id="req-h"></h2><span class="hint" id="req-hint"></span></div>
    <div class="table-wrap" id="requests"></div>
  </section>
  <div class="grid2">
    <section class="card">
      <div class="card-head"><h2 id="ob-h"></h2><span class="hint" id="ob-hint"></span></div>
      <div class="table-wrap" id="outbox"></div>
    </section>
    <section class="card">
      <div class="card-head"><h2 id="log-h"></h2><span class="hint">serve.log</span></div>
      <div id="log"></div>
    </section>
  </div>
</main>
<div id="tip" role="tooltip"></div>
<script>
"use strict";
const ZH = /^zh/i.test(navigator.language || "");
const L = ZH ? {
  title: "Yobiru 看板", refresh: "刷新", auto: "自动刷新", updated: "更新于", relayMode: "中继", home: "数据目录",
  days: d => d === 1 ? "最近 24 小时" : "最近 " + d + " 天",
  kIn: "收到", kOut: "发出", kPending: "待处理", kBad: "有问题", kOpen: "进行中的请求", kOutbox: "待回推",
  nIn: "条消息", nOut: "条消息", nPending: "还没确认处理", nBad: "失败、拒绝或超时", nOpen: "tracked request", nOutbox: "结果还没推回对方",
  flow: "设备之间的消息流", act: "消息量", msgs: "消息", reqs: "Tracked request", outbox: "待回推的结果", log: "最近的问题",
  me: "本机", inL: "收到", outL: "发出", allPeers: "所有设备", allDirs: "收和发", dirIn: "只看收到", dirOut: "只看发出",
  badOnly: "只看有问题", search: "搜索内容、ID、agent", time: "时间", dir: "方向", peer: "设备", agent: "Agent",
  content: "内容", files: "附件", status: "状态", state: "状态", submitted: "发出时间", deadline: "截止",
  attempts: "尝试", nextTry: "下次尝试", lastErr: "上次错误", request: "Request",
  noMsgs: "这段时间没有消息。", noReqs: "没有进行中或这段时间的 tracked request。", noOutbox: "没有待回推的结果。", noLog: "日志里没有最近的问题。",
  noPeers: "这段时间没有和任何设备通信。", more: "再显示 200 条", shown: (a, b) => "显示 " + a + " / " + b + " 条",
  sentNote: "这台设备还没有发件记录：升级后发出的消息才会记下来，在那之前只能看到收到的消息。",
  hIn: "收", hOut: "发", id: "ID", kind: "类型", wake: "唤醒", wakeErr: "唤醒错误", error: "错误", replyTo: "回复", acked: "确认处理",
  transport: "传输", bytes: "大小", relay: "中继网关", tailscale: "Tailscale", allVia: "所有传输方式", split: (r, t) => "中继网关 " + r + " · Tailscale " + t, lastSeen: "最近", trusted: "已信任", problems: "有问题",
  pushed: n => "这段时间已推回 " + n + " 条", openFirst: "进行中的排在前面",
  health: { healthy: "接收端正常", degraded: "接收端降级", stale: "接收端没在运行", unknown: "接收端状态未知" },
  loadErr: "读取失败：", noPeerTraffic: "没有往来", ago: s => s < 60 ? "刚刚" : s < 3600 ? Math.floor(s / 60) + " 分钟前" : s < 86400 ? Math.floor(s / 3600) + " 小时前" : Math.floor(s / 86400) + " 天前",
  st: { pending: "待处理", woken: "已唤醒", processed: "已处理", wake_failed: "唤醒失败", unknown_agent: "未知 agent",
        delivered: "已送达", send_failed: "发送失败", received: "已接收", running: "执行中", completed: "已完成",
        failed: "失败", rejected: "被拒绝", blocked: "已拦截", timed_out: "超时" }
} : {
  title: "Yobiru Dashboard", refresh: "Refresh", auto: "Auto refresh", updated: "Updated", relayMode: "Relay", home: "Data home",
  days: d => d === 1 ? "Last 24 hours" : "Last " + d + " days",
  kIn: "Received", kOut: "Sent", kPending: "Pending", kBad: "Problems", kOpen: "Open requests", kOutbox: "To push back",
  nIn: "messages", nOut: "messages", nPending: "not yet acked", nBad: "failed, rejected or timed out", nOpen: "tracked requests", nOutbox: "results not yet delivered",
  flow: "Message flow between devices", act: "Volume", msgs: "Messages", reqs: "Tracked requests", outbox: "Results waiting to be pushed back", log: "Recent problems",
  me: "This device", inL: "Received", outL: "Sent", allPeers: "All devices", allDirs: "Both directions", dirIn: "Received only", dirOut: "Sent only",
  badOnly: "Problems only", search: "Search text, ID, agent", time: "Time", dir: "Dir", peer: "Device", agent: "Agent",
  content: "Content", files: "Files", status: "Status", state: "State", submitted: "Sent", deadline: "Deadline",
  attempts: "Attempts", nextTry: "Next try", lastErr: "Last error", request: "Request",
  noMsgs: "No messages in this range.", noReqs: "No open tracked requests and none in this range.", noOutbox: "Nothing waiting to be pushed back.", noLog: "No recent problems in the log.",
  noPeers: "No traffic with any device in this range.", more: "Show 200 more", shown: (a, b) => a + " of " + b + " shown",
  sentNote: "No sent log on this device yet: messages sent after the upgrade are recorded; before that, only received messages show.",
  hIn: "in", hOut: "out", id: "ID", kind: "Kind", wake: "Wake", wakeErr: "Wake error", error: "Error", replyTo: "Reply to", acked: "Acked",
  transport: "Via", bytes: "Size", relay: "Relay", tailscale: "Tailscale", allVia: "Any transport", split: (r, t) => "Relay " + r + " · Tailscale " + t, lastSeen: "Last", trusted: "trusted", problems: "problems",
  pushed: n => n + " pushed back in this range", openFirst: "open ones first",
  health: { healthy: "Receiver healthy", degraded: "Receiver degraded", stale: "Receiver not running", unknown: "Receiver status unknown" },
  loadErr: "Could not load: ", noPeerTraffic: "no traffic", ago: s => s < 60 ? "just now" : s < 3600 ? Math.floor(s / 60) + " min ago" : s < 86400 ? Math.floor(s / 3600) + " h ago" : Math.floor(s / 86400) + " d ago",
  st: { pending: "Pending", woken: "Woken", processed: "Processed", wake_failed: "Wake failed", unknown_agent: "Unknown agent",
        delivered: "Delivered", send_failed: "Send failed", received: "Received", running: "Running", completed: "Completed",
        failed: "Failed", rejected: "Rejected", blocked: "Blocked", timed_out: "Timed out" }
};
const TONE = { pending: "warn", woken: "active", processed: "good", wake_failed: "bad", unknown_agent: "bad", delivered: "good",
  send_failed: "bad", received: "active", running: "active", completed: "good", failed: "bad", rejected: "bad", blocked: "bad",
  timed_out: "bad", prepared: "active" };
const ICON = { good: "✓", bad: "✕", warn: "!", active: "•", serious: "!", none: "–" };
const BAD = new Set(["wake_failed", "unknown_agent", "send_failed", "failed", "rejected", "blocked", "timed_out"]);
const FINAL = new Set(["completed", "failed", "rejected", "blocked", "timed_out"]);
const TOKEN = new URLSearchParams(location.search).get("t") || "";
const store = { get(k, d) { try { const v = localStorage.getItem("yobiru." + k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } },
                set(k, v) { try { localStorage.setItem("yobiru." + k, JSON.stringify(v)); } catch (e) {} } };
const S = { days: store.get("days", 7), auto: store.get("auto", true), peer: "", via: "", dir: "", bad: false, q: "", limit: 200, open: new Set(), data: null };
const $ = id => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v; else if (k.startsWith("on")) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) n.append(k instanceof Node ? k : String(k));
  return n;
}
function sv(tag, attrs, ...kids) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined) continue;
    if (k.startsWith("on")) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined) n.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return n;
}
function badge(code) {
  const tone = TONE[code] || "active";
  return el("span", { class: "badge" }, el("span", { class: "ico t-" + tone, "aria-hidden": "true" }, ICON[tone]), L.st[code] || code);
}
function via(t) {
  return el("span", { class: "via via-" + (t === "relay" ? "relay" : "tailscale") }, t === "relay" ? "⇄ " + L.relay : "◆ " + L.tailscale);
}
const DASH = { relay: "7 4", tailscale: null };
function lineSample(dash) {
  return sv("svg", { width: 22, height: 8, "aria-hidden": "true" }, sv("line", { x1: 1, x2: 21, y1: 4, y2: 4, stroke: "var(--text-2)", "stroke-width": 2, "stroke-dasharray": dash }));
}
const shown = r => (!S.peer || r.peer === S.peer) && (!S.via || r.transport === S.via);
const pad = n => String(n).padStart(2, "0");
function fmt(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  return pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
}
function ago(iso) { return iso ? L.ago(Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)) : "–"; }
function size(b) { return !b ? "" : b < 1024 ? b + " B" : b < 1 << 20 ? (b / 1024).toFixed(1) + " KB" : (b / 1048576).toFixed(1) + " MB"; }
function label(peer) { const p = (S.data.peers || []).find(x => x.peer === peer); return p ? p.label : peer; }

const tip = $("tip");
function showTip(ev, rows) {
  tip.replaceChildren(...rows.map((r, i) => el("div", null, i === 0 ? el("b", null, r) : r)));
  tip.style.display = "block";
  const w = tip.offsetWidth, h = tip.offsetHeight;
  let x = ev.clientX + 14, y = ev.clientY + 14;
  if (x + w > innerWidth - 8) x = ev.clientX - w - 14;
  if (y + h > innerHeight - 8) y = ev.clientY - h - 14;
  tip.style.left = Math.max(8, x) + "px"; tip.style.top = Math.max(8, y) + "px";
}
function hideTip() { tip.style.display = "none"; }

function filtered() {
  const q = S.q.trim().toLowerCase();
  return S.data.messages.filter(m => shown(m) && (!S.dir || m.dir === S.dir) && (!S.bad || BAD.has(m.status)) &&
    (!q || [m.text, m.id, m.agent, m.from_agent, m.peer, label(m.peer)].some(v => v && String(v).toLowerCase().includes(q))));
}

function renderHeader() {
  const d = S.data, me = d.me;
  document.title = L.title;
  $("title").textContent = L.title + " · " + (me.relay || (me.node ? me.node.split(".")[0] : "?"));
  const sub = [];
  if (me.node && !me.node.endsWith(".relay")) sub.push(el("span", null, "Tailscale ", el("span", { class: "mono" }, me.node)));
  if (me.relay) sub.push(el("span", null, L.relayMode + " ", el("span", { class: "mono" }, me.relay), " (" + me.relay_mode + ")"));
  sub.push(el("span", null, L.home + " ", el("span", { class: "mono" }, d.home)));
  sub.push(el("span", null, L.updated + " " + new Date(d.generated_at).toLocaleTimeString()));
  $("sub").replaceChildren(...sub);
  const h = d.receiver, tone = { healthy: "good", degraded: "serious", stale: "warn" }[h.status] || "none";
  const title = [h.written_at ? L.updated + " " + ago(h.written_at) : "", ...(h.reasons || [])].filter(Boolean).join(" · ");
  $("health").replaceChildren(el("span", { class: "pill", title },
    el("span", { class: "ico t-" + tone, "aria-hidden": "true" }, ICON[tone]), L.health[h.status] || L.health.unknown));
}

function renderKpis() {
  const d = S.data, inc = d.messages.filter(m => m.dir === "in"), out = d.messages.filter(m => m.dir === "out");
  const split = rows => L.split(rows.filter(m => m.transport === "relay").length, rows.filter(m => m.transport !== "relay").length);
  const items = [
    [L.kIn, inc.length, split(inc)], [L.kOut, d.sent_log ? out.length : "–", d.sent_log ? split(out) : L.nOut],
    [L.kPending, inc.filter(m => m.status === "pending" || m.status === "woken").length, L.nPending],
    [L.kBad, d.messages.filter(m => BAD.has(m.status)).length, L.nBad],
    [L.kOpen, d.requests.filter(r => !FINAL.has(r.state)).length, L.nOpen],
    [L.kOutbox, d.outbox.length, L.nOutbox]];
  $("kpis").replaceChildren(...items.map(([k, v, n]) => el("div", { class: "kpi" }, el("div", { class: "k" }, k), el("div", { class: "v" }, v), el("div", { class: "n" }, n))));
}

function renderFlow() {
  const box = $("flow"), peers = S.data.peers;
  $("flow-legend").replaceChildren(
    el("span", null, el("span", { class: "sw", style: "background:var(--out)" }), L.outL),
    el("span", null, el("span", { class: "sw", style: "background:var(--in)" }), L.inL),
    el("span", null, lineSample(null), L.tailscale), el("span", null, lineSample(DASH.relay), L.relay));
  if (!peers.length) { box.replaceChildren(el("div", { class: "empty" }, L.noPeers)); return; }
  const W = Math.max(300, box.clientWidth), rowH = 62, top = 12, H = Math.max(120, top * 2 + peers.length * rowH);
  const meW = Math.min(180, Math.round(W * 0.3)), peerW = Math.min(240, Math.round(W * 0.38)), meX = 0, px = W - peerW;
  const meY = H / 2, max = Math.max(1, ...peers.map(p => Math.max(p.in, p.out)));
  const width = n => n ? 1.5 + 4.5 * Math.sqrt(n / max) : 1;
  const svg = sv("svg", { width: W, height: H, viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": L.flow });
  const defs = sv("defs");
  for (const [id, color] of [["a-out", "var(--out)"], ["a-in", "var(--in)"], ["a-idle", "var(--idle)"]])
    defs.append(sv("marker", { id, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto", markerUnits: "userSpaceOnUse" },
      sv("path", { d: "M0,1 L10,5 L0,9 z", fill: color })));
  svg.append(defs);
  const x1 = meX + meW + 4, x2 = px - 6;
  peers.forEach((p, i) => {
    const py = top + i * rowH + rowH / 2, dim = (S.peer && S.peer !== p.peer) || (S.via && S.via !== p.transport) ? 0.25 : 1;
    const curve = (ya, yb, rev) => {
      const a = rev ? [x2, yb] : [x1, ya], b = rev ? [x1, ya] : [x2, yb], mx = (x1 + x2) / 2;
      return "M" + a[0] + "," + a[1] + " C" + mx + "," + a[1] + " " + mx + "," + b[1] + " " + b[0] + "," + b[1];
    };
    const g = sv("g", { opacity: dim });
    const lines = [["out", meY - 5, py - 7, false], ["in", meY + 5, py + 7, true]];
    for (const [dir, ya, yb, rev] of lines) {
      const n = p[dir], color = n ? "var(--" + dir + ")" : "var(--idle)";
      const d = curve(ya, yb, rev);
      g.append(sv("path", { d, fill: "none", stroke: color, "stroke-width": width(n), "stroke-linecap": "round",
        "stroke-dasharray": n ? DASH[p.transport] : "2 4", "marker-end": "url(#" + (n ? "a-" + dir : "a-idle") + ")" }));
      const hit = sv("path", { d, fill: "none", stroke: "transparent", "stroke-width": 14, style: "cursor:pointer" });
      hit.addEventListener("mousemove", ev => showTip(ev, [(dir === "out" ? L.me + " → " + p.label : p.label + " → " + L.me),
        L.transport + ": " + (p.transport === "relay" ? L.relay : L.tailscale), (dir === "out" ? L.outL : L.inL) + " " + n]));
      hit.addEventListener("mouseleave", hideTip);
      hit.addEventListener("click", () => pickPeer(p.peer));
      g.append(hit);
      const t = rev ? 0.3 : 0.7, u = 1 - t, mx = (x1 + x2) / 2, sx = rev ? x2 : x1, ex = rev ? x1 : x2, sy = rev ? yb : ya, ey = rev ? ya : yb;
      const lx = u * u * u * sx + 3 * u * u * t * mx + 3 * u * t * t * mx + t * t * t * ex;
      const ly = u * u * u * sy + 3 * u * u * t * sy + 3 * u * t * t * ey + t * t * t * ey + (dir === "out" ? -7 : 15);
      g.append(sv("text", { x: lx, y: ly, "text-anchor": "middle", "font-size": 12, "font-weight": 600,
        style: "paint-order:stroke;stroke:var(--surface);stroke-width:4px;fill:var(--text-2)" }, (dir === "out" ? "↑" : "↓") + n));
    }
    const card = sv("g", { class: "peer-card", transform: "translate(" + px + "," + (py - 24) + ")" });
    card.append(sv("rect", { width: peerW, height: 48, rx: 8, fill: "var(--surface-2)",
      stroke: S.peer === p.peer ? "var(--select)" : "var(--border)", "stroke-width": S.peer === p.peer ? 2 : 1 }));
    card.append(sv("text", { x: 12, y: 20, "font-size": 13, "font-weight": 600, "data-fit": peerW - (p.problems ? 40 : 20) }, p.label));
    const relay = p.transport === "relay", tag = sv("g", { "data-via": "", transform: "translate(12,28)" });
    tag.append(sv("rect", { height: 15, rx: 3, fill: relay ? "none" : "var(--surface)", stroke: relay ? "var(--text-2)" : "var(--border)",
      "stroke-dasharray": relay ? "3 2" : null }), sv("text", { x: 6, y: 11, "font-size": 10.5, "font-weight": 500 }, relay ? "⇄ " + L.relay : "◆ " + L.tailscale));
    card.append(tag, sv("text", { y: 39, "font-size": 11, style: "fill:var(--muted)", "data-after": "" }, p.last ? ago(p.last) : L.noPeerTraffic));
    if (p.problems) {
      const b = sv("g", { transform: "translate(" + (peerW - 14) + ",14)" });
      b.append(sv("circle", { r: 8, fill: "var(--critical)" }), sv("text", { "text-anchor": "middle", y: 4, "font-size": 10, "font-weight": 700, style: "fill:#fff" }, p.problems > 99 ? "99" : p.problems));
      card.append(b);
    }
    card.addEventListener("mousemove", ev => showTip(ev, [p.peer, L.transport + ": " + (p.transport === "relay" ? L.relay : L.tailscale), L.inL + " " + p.in + " · " + L.outL + " " + p.out,
      (p.files ? L.files + " " + p.files + " (" + size(p.bytes) + ")" : null), (p.problems ? L.problems + " " + p.problems : null),
      (p.trusted ? L.relay + " " + L.trusted : null), (p.last ? L.lastSeen + " " + fmt(p.last) : null)].filter(Boolean)));
    card.addEventListener("mouseleave", hideTip);
    card.addEventListener("click", () => pickPeer(p.peer));
    g.append(card);
    svg.append(g);
  });
  const me = S.data.me, meName = me.relay || (me.node ? me.node.split(".")[0] : L.me);
  const mg = sv("g", { transform: "translate(" + meX + "," + (meY - 30) + ")" });
  mg.append(sv("rect", { width: meW, height: 60, rx: 10, fill: "var(--surface)", stroke: "var(--text-2)", "stroke-width": 1.5 }));
  mg.append(sv("text", { x: 12, y: 24, "font-size": 11, style: "fill:var(--muted)" }, L.me));
  mg.append(sv("text", { x: 12, y: 44, "font-size": 14, "font-weight": 600, "data-fit": meW - 20 }, meName));
  mg.addEventListener("mousemove", ev => showTip(ev, [L.me, me.node, me.relay].filter(Boolean)));
  mg.addEventListener("mouseleave", hideTip);
  svg.append(mg);
  box.replaceChildren(svg);
  for (const tag of svg.querySelectorAll("g[data-via]")) {
    const w = tag.querySelector("text").getComputedTextLength() + 12;
    tag.querySelector("rect").setAttribute("width", w);
    const after = tag.parentNode.querySelector("text[data-after]");
    after.setAttribute("x", 12 + w + 6);
    after.setAttribute("data-fit", peerW - w - 32);
  }
  fit(svg);
}

function fit(svg) {
  // Shorten each marked label until it fits its box; the full name stays in the tooltip.
  for (const t of svg.querySelectorAll("text[data-fit]")) {
    const max = +t.getAttribute("data-fit"), full = t.textContent;
    let n = full.length;
    while (n > 1 && t.getComputedTextLength() > max) t.textContent = full.slice(0, --n) + "…";
  }
}

function renderActivity() {
  const box = $("activity"), days = S.data.days, hourly = days === 1, now = new Date(S.data.generated_at);
  $("act-legend").replaceChildren(
    el("span", null, el("span", { class: "sw", style: "background:var(--in)" }), L.inL),
    el("span", null, el("span", { class: "sw", style: "background:var(--out)" }), L.outL));
  const buckets = [], n = hourly ? 24 : days;
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(now);
    if (hourly) { d.setMinutes(0, 0, 0); d.setHours(d.getHours() - i); } else { d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i); }
    buckets.push({ start: d.getTime(), in: 0, out: 0 });
  }
  for (const m of S.data.messages) {
    if (!shown(m)) continue;
    const t = new Date(m.at).getTime();
    for (let i = buckets.length - 1; i >= 0; i--) if (t >= buckets[i].start) { buckets[i][m.dir]++; break; }
  }
  const W = Math.max(280, box.clientWidth), H = 200, padL = 30, padB = 22, padT = 8, cw = W - padL, ch = H - padB - padT;
  const max = Math.max(1, ...buckets.map(b => b.in + b.out)), step = Math.max(1, Math.ceil(max / 3));
  const ymax = step * 3, y = v => padT + ch - v / ymax * ch, bw = cw / buckets.length, barW = Math.max(2, Math.min(28, bw * 0.62));
  const svg = sv("svg", { width: W, height: H, viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": L.act });
  for (let k = 0; k <= 3; k++) {
    const v = k * step, yy = y(v);
    svg.append(sv("line", { x1: padL, x2: W, y1: yy, y2: yy, stroke: "var(--border)", "stroke-width": 1 }));
    svg.append(sv("text", { x: padL - 6, y: yy + 4, "text-anchor": "end", "font-size": 11, style: "fill:var(--muted)" }, v));
  }
  const every = Math.ceil(buckets.length / Math.max(2, Math.floor(cw / 56)));
  buckets.forEach((b, i) => {
    const cx = padL + bw * i + bw / 2, x = cx - barW / 2, d = new Date(b.start);
    const segs = [["in", 0, b.in], ["out", b.in, b.out]].filter(s => s[2] > 0);
    segs.forEach(([dir, base, v], j) => {
      const yTop = y(base + v), yBot = y(base) - (j > 0 ? 2 : 0), h = Math.max(1, yBot - yTop), r = j === segs.length - 1 ? Math.min(4, h, barW / 2) : 0;
      svg.append(sv("path", { fill: "var(--" + dir + ")", d: "M" + x + "," + (yTop + h) + " V" + (yTop + r) + " Q" + x + "," + yTop + " " + (x + r) + "," + yTop +
        " H" + (x + barW - r) + " Q" + (x + barW) + "," + yTop + " " + (x + barW) + "," + (yTop + r) + " V" + (yTop + h) + " Z" }));
    });
    if (i % every === 0 || i === buckets.length - 1)
      svg.append(sv("text", { x: cx, y: H - 6, "text-anchor": "middle", "font-size": 11, style: "fill:var(--muted)" },
        hourly ? pad(d.getHours()) + ":00" : pad(d.getMonth() + 1) + "-" + pad(d.getDate())));
    const hit = sv("rect", { x: padL + bw * i, y: padT, width: bw, height: ch, fill: "transparent" });
    hit.addEventListener("mousemove", ev => showTip(ev, [hourly ? fmt(d.toISOString()) : pad(d.getMonth() + 1) + "-" + pad(d.getDate()),
      L.inL + " " + b.in, L.outL + " " + b.out]));
    hit.addEventListener("mouseleave", hideTip);
    svg.append(hit);
  });
  box.replaceChildren(svg);
}

function detail(m) {
  const rows = [[L.id, m.id], [L.kind, m.kind], [L.transport, m.transport === "relay" ? L.relay : L.tailscale], [L.peer, m.peer],
    [L.agent, [m.from_agent, m.agent].filter(Boolean).join(" → ")], [L.files, m.files ? m.files + " (" + size(m.bytes) + ")" : null],
    [L.replyTo, m.reply_to], [L.wake, m.wake ? m.wake + (m.wake_reason ? " (" + m.wake_reason + ")" : "") : null],
    [L.wakeErr, m.wake_error], [L.error, m.error || (m.http && m.http !== 200 && m.http !== 202 ? "HTTP " + m.http : null)], [L.acked, m.acked_at ? fmt(m.acked_at) : null]]
    .filter(r => r[1]);
  return el("td", { colspan: 8 }, el("p", { class: "full" }, m.text || "–"),
    el("dl", { class: "detail-grid" }, rows.flatMap(([k, v]) => [el("dt", null, k), el("dd", { class: k === L.id ? "mono" : null }, v)])));
}

function renderMessages() {
  const d = S.data, all = filtered(), rows = all.slice(0, S.limit);
  $("sent-note").hidden = d.sent_log; $("sent-note").textContent = L.sentNote;
  const peerSel = $("f-peer"), cur = S.peer;
  peerSel.replaceChildren(el("option", { value: "" }, L.allPeers), ...d.peers.map(p => el("option", { value: p.peer, selected: p.peer === cur ? "" : null }, p.label)));
  if (!rows.length) { $("messages").replaceChildren(el("div", { class: "empty" }, L.noMsgs)); return; }
  const body = el("tbody");
  for (const m of rows) {
    const key = m.dir + m.id, open = S.open.has(key);
    const tr = el("tr", { class: "row", "aria-expanded": open ? "true" : "false" },
      el("td", { class: "nowrap", title: m.at }, fmt(m.at)),
      el("td", { class: "nowrap" }, el("span", { class: "dir-" + m.dir }, m.dir === "in" ? "↓ " + L.hIn : "↑ " + L.hOut)),
      el("td", { class: "nowrap" }, label(m.peer)),
      el("td", null, via(m.transport)),
      el("td", { class: "nowrap" }, [m.from_agent, m.agent].filter(Boolean).join(" → ") || "–"),
      el("td", { class: "text", title: m.text }, m.text || "–"),
      el("td", { class: "num" }, m.files || ""),
      el("td", null, badge(m.status)));
    tr.addEventListener("click", () => { open ? S.open.delete(key) : S.open.add(key); renderMessages(); });
    body.append(tr);
    if (open) body.append(el("tr", { class: "detail" }, detail(m)));
  }
  const table = el("table", null, el("thead", null, el("tr", null, [L.time, L.dir, L.peer, L.transport, L.agent, L.content, L.files, L.status].map(h => el("th", null, h)))), body);
  const foot = el("div", { class: "more" }, el("span", { class: "hint" }, L.shown(rows.length, all.length) + " "),
    all.length > rows.length ? el("button", { onclick: () => { S.limit += 200; renderMessages(); } }, L.more) : null);
  $("messages").replaceChildren(table, foot);
}

function renderRequests() {
  const reqs = S.data.requests.slice().sort((a, b) => (FINAL.has(a.state) - FINAL.has(b.state)) || String(b.ts).localeCompare(String(a.ts)))
    .filter(shown);
  $("req-hint").textContent = L.openFirst;
  if (!reqs.length) { $("requests").replaceChildren(el("div", { class: "empty" }, L.noReqs)); return; }
  $("requests").replaceChildren(el("table", null,
    el("thead", null, el("tr", null, [L.dir, L.peer, L.transport, L.state, L.submitted, L.deadline, L.agent, L.content].map(h => el("th", null, h)))),
    el("tbody", null, reqs.slice(0, 300).map(r => el("tr", null,
      el("td", { class: "nowrap" }, el("span", { class: r.direction === "incoming" ? "dir-in" : "dir-out" }, r.direction === "incoming" ? "↓ " + L.hIn : "↑ " + L.hOut)),
      el("td", { class: "nowrap", title: r.peer }, label(r.peer)),
      el("td", null, via(r.transport)),
      el("td", null, badge(r.state)),
      el("td", { class: "nowrap" }, fmt(r.ts)),
      el("td", { class: "nowrap" }, fmt(r.timed_out_at || r.deadline)),
      el("td", { class: "nowrap" }, r.agent || "–"),
      el("td", { class: "text", title: r.text }, r.text || "–"))))));
}

function renderOutbox() {
  const rows = S.data.outbox.filter(shown);
  $("ob-hint").textContent = L.pushed(S.data.pushed);
  if (!rows.length) { $("outbox").replaceChildren(el("div", { class: "empty" }, L.noOutbox)); return; }
  $("outbox").replaceChildren(el("table", null,
    el("thead", null, el("tr", null, [L.request, L.peer, L.transport, L.attempts, L.nextTry, L.lastErr].map(h => el("th", null, h)))),
    el("tbody", null, rows.map(r => el("tr", null, el("td", { class: "mono" }, r.request_id), el("td", { class: "nowrap" }, label(r.peer)), el("td", null, via(r.transport)),
      el("td", { class: "num" }, r.attempts), el("td", { class: "nowrap" }, fmt(r.next_attempt)), el("td", { class: "text", title: r.last_error || "" }, r.last_error || "–"))))));
}

function renderLog() {
  const lines = S.data.log;
  $("log").replaceChildren(lines.length ? el("pre", { class: "log mono" }, lines.slice().reverse().join("\n")) : el("div", { class: "empty" }, L.noLog));
}

function render() {
  if (!S.data) return;
  renderHeader(); renderKpis(); renderFlow(); renderActivity(); renderMessages(); renderRequests(); renderOutbox(); renderLog();
}
function pickPeer(peer) { S.peer = S.peer === peer ? "" : peer; S.limit = 200; hideTip(); render(); }

async function load() {
  try {
    const r = await fetch("/api/summary?t=" + encodeURIComponent(TOKEN) + "&days=" + S.days, { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    S.data = await r.json();
    $("error").hidden = true;
    render();
  } catch (e) {
    $("error").hidden = false; $("error").textContent = L.loadErr + e.message;
  }
}

function setup() {
  $("refresh").textContent = L.refresh; $("auto-l").textContent = L.auto; $("f-bad-l").textContent = L.badOnly;
  $("flow-h").textContent = L.flow; $("act-h").textContent = L.act; $("msg-h").textContent = L.msgs; $("req-h").textContent = L.reqs;
  $("ob-h").textContent = L.outbox; $("log-h").textContent = L.log; $("f-q").placeholder = L.search;
  const days = $("days");
  days.replaceChildren(...[1, 7, 30, 90].map(d => el("option", { value: d, selected: d === S.days ? "" : null }, L.days(d))));
  days.addEventListener("change", () => { S.days = +days.value; store.set("days", S.days); load(); });
  $("f-dir").replaceChildren(el("option", { value: "" }, L.allDirs), el("option", { value: "in" }, L.dirIn), el("option", { value: "out" }, L.dirOut));
  $("f-dir").addEventListener("change", e => { S.dir = e.target.value; S.limit = 200; renderMessages(); });
  $("f-peer").addEventListener("change", e => { S.peer = e.target.value; S.limit = 200; render(); });
  $("f-via").replaceChildren(el("option", { value: "" }, L.allVia), el("option", { value: "tailscale" }, L.tailscale), el("option", { value: "relay" }, L.relay));
  $("f-via").addEventListener("change", e => { S.via = e.target.value; S.limit = 200; render(); });
  $("f-bad").addEventListener("change", e => { S.bad = e.target.checked; S.limit = 200; renderMessages(); });
  $("f-q").addEventListener("input", e => { S.q = e.target.value; S.limit = 200; renderMessages(); });
  $("auto").checked = S.auto;
  $("auto").addEventListener("change", e => { S.auto = e.target.checked; store.set("auto", S.auto); });
  $("refresh").addEventListener("click", load);
  let t; addEventListener("resize", () => { clearTimeout(t); t = setTimeout(() => { if (S.data) { renderFlow(); renderActivity(); } }, 120); });
  setInterval(() => { if (S.auto && !document.hidden) load(); }, 15000);
  load();
}
setup();
</script>
</body>
</html>
"""
