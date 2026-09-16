#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_report_notify_vacuum_unit.py -- fast, deterministic test of the
two remaining #39 pieces (new-report notifier + VACUUM cadence), without
any network or server process.

- The stderr log line fires for every accepted report even with no
  webhook configured (pure log mode -- the default).
- The webhook path POSTs each accepted payload as JSON in the
  background: a test HTTP server records bodies, and the queue delivers
  every report without blocking the notifier call.
- A full queue drops (and counts) instead of blocking: with a size-1
  queue and a webhook that never responds, notify() still returns and
  the drop counter moves.
- A dead webhook URL never raises out of notify(): the failure is
  logged by the worker, the report itself already committed.
- Store.add_report() returns the stored received_at, and with a tiny
  vacuum_interval the DB file shrinks after trimming churn instead of
  sitting at its high-water mark; vacuum_interval=0 leaves the file
  alone.

Real on-disk SQLite, no server -- matches the existing unit-test style
(see test_reports_pagination_quota_unit.py).
"""
import contextlib
import importlib.util
import io
import json
import pathlib
import sqlite3
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ac_server", HERE / "ac_server.py")
ac_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ac_server)

FAIL = 0


def check(name, cond):
    global FAIL
    status = "\033[1;32mPASS\033[0m" if cond else "\033[1;31mFAIL\033[0m"
    print(f"  {status}  {name}")
    if not cond:
        FAIL = 1


print("=== Report notifier + VACUUM unit test (#39) ===")
print()

# --- log line fires in log-only mode (no webhook) ---
quiet = ac_server.ReportNotifier()
buf = io.StringIO()
with contextlib.redirect_stderr(buf):
    quiet.notify({"client_id": "c1", "event_type": "E",
                  "source_addr": "127.0.0.1"})
out = buf.getvalue()
check("log-only notify() emits a grep-able line",
      "new report" in out and "c1" in out and "E" in out)
check("log-only mode starts no worker thread", quiet._worker is None)

# --- webhook delivery: every payload arrives as JSON ---
received = []
arrived = threading.Event()


class HookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        received.append(json.loads(self.rfile.read(length).decode()))
        if len(received) >= 2:
            arrived.set()
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


hook = HTTPServer(("127.0.0.1", 0), HookHandler)
threading.Thread(target=hook.serve_forever, daemon=True).start()
url = "http://127.0.0.1:%d/hook" % hook.server_address[1]
web = ac_server.ReportNotifier(webhook_url=url)
buf = io.StringIO()
with contextlib.redirect_stderr(buf):
    web.notify({"client_id": "w1", "event_type": "EV1",
                "detail": "d1", "client_ts": None,
                "received_at": 1, "source_addr": "127.0.0.1"})
    web.notify({"client_id": "w2", "event_type": "EV2",
                "detail": "d2", "client_ts": 7,
                "received_at": 2, "source_addr": "127.0.0.1"})
check("notify() with a webhook still logs each line",
      buf.getvalue().count("new report") == 2)
ok = arrived.wait(timeout=10)
check("background worker POSTs every payload as JSON",
      ok and sorted(r["client_id"] for r in received) == ["w1", "w2"]
      and received[0].get("received_at") in (1, 2))
hook.shutdown()
hook.server_close()

# --- slow webhook: notify() never blocks, drops are counted ---
blocked = threading.Event()


class StallHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        blocked.wait(timeout=10)
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *a):
        pass


stall = HTTPServer(("127.0.0.1", 0), StallHandler)
threading.Thread(target=stall.serve_forever, daemon=True).start()
stall_url = "http://127.0.0.1:%d/hook" % stall.server_address[1]
small = ac_server.ReportNotifier(webhook_url=stall_url,
                                 webhook_timeout=5,
                                 notify_queue_size=1)
# Fill the size-1 queue: first payload is being POSTed (stalled), second
# sits queued, third and beyond must drop rather than block.
small.notify({"client_id": "s", "event_type": "E", "source_addr": "x"})
time.sleep(1.0)  # let the worker pick the first payload up (now stalled)
buf = io.StringIO()
start = time.monotonic()
with contextlib.redirect_stderr(buf):
    for _ in range(5):
        small.notify({"client_id": "s", "event_type": "E",
                      "source_addr": "x"})
elapsed = time.monotonic() - start
check("full queue drops instead of blocking notify()",
      elapsed < 4.0 and small.dropped >= 1)
check("drops are logged, not silent",
      "queue full" in buf.getvalue())
blocked.set()
stall.shutdown()
stall.server_close()

# --- dead webhook: failure is logged, never raised ---
dead = ac_server.ReportNotifier(webhook_url="http://127.0.0.1:1/hook",
                                webhook_timeout=1)
buf = io.StringIO()
raised = False
with contextlib.redirect_stderr(buf):
    try:
        dead.notify({"client_id": "d", "event_type": "E",
                     "source_addr": "x"})
        for _ in range(100):
            if "webhook delivery failed" in buf.getvalue():
                break
            time.sleep(0.05)
    except Exception:
        raised = True
check("dead webhook never raises out of notify()", not raised)
check("dead webhook failure is logged by the worker",
      "webhook delivery failed" in buf.getvalue())

with tempfile.TemporaryDirectory() as tmp:
    # --- add_report returns the stored received_at ---
    ts_db = str(pathlib.Path(tmp) / "ts.db")
    ts_store = ac_server.Store(ts_db)
    returned = ts_store.add_report("c", "E", "d", 42, "127.0.0.1")
    conn = sqlite3.connect(ts_db)
    try:
        row = conn.execute(
            "SELECT client_ts, received_at FROM reports").fetchone()
    finally:
        conn.close()
    check("add_report returns the stored received_at",
          row is not None and row[1] == returned
          and isinstance(returned, int))

    # --- VACUUM cadence: trimming churn stops file growth ---
    big = "x" * 1500
    vac_db = str(pathlib.Path(tmp) / "vac.db")
    vac = ac_server.Store(vac_db, max_reports_per_client=5,
                          max_total_reports=0, vacuum_interval=2)
    novac_db = str(pathlib.Path(tmp) / "novac.db")
    novac = ac_server.Store(novac_db, max_reports_per_client=5,
                            max_total_reports=0, vacuum_interval=0)
    for i in range(60):
        vac.add_report("v", "E", big, None, "127.0.0.1")
        novac.add_report("v", "E", big, None, "127.0.0.1")
    vac_size = pathlib.Path(vac_db).stat().st_size
    novac_size = pathlib.Path(novac_db).stat().st_size
    vac_free = sqlite3.connect(vac_db).execute(
        "PRAGMA freelist_count").fetchone()[0]
    novac_free = sqlite3.connect(novac_db).execute(
        "PRAGMA freelist_count").fetchone()[0]
    check("VACUUM cadence fires on trimming churn",
          vac._writes_since_vacuum < 2)
    check("vacuumed file stays below the unvacuumed high-water mark",
          vac_size < novac_size and vac_free == 0 and novac_free > 0)

    # --- vacuum_interval=0 disables; quiet DB never vacuums ---
    check("vacuum_interval=0 disables VACUUM",
          novac._writes_since_vacuum == 0)
    quiet_db = str(pathlib.Path(tmp) / "quiet.db")
    quiet_store = ac_server.Store(quiet_db, vacuum_interval=2)
    for i in range(10):
        quiet_store.add_report("q", "E", "small", None, "127.0.0.1")
    check("inserts that trim nothing never count toward VACUUM",
          quiet_store._writes_since_vacuum == 0)

print()
if FAIL:
    print("\033[1;31mSOME NOTIFY/VACUUM UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL NOTIFY/VACUUM UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)
