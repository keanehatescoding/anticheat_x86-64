#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR GPL-2.0-only
"""test_store_retention_unit.py -- fast, deterministic test of
Store.add_report()'s per-client_id row cap.

Store.add_report() previously had no retention logic at all: every report
inserted a row with nothing to ever remove it, so a single spammy or
misbehaving client could grow the reports table (and the SQLite file)
without bound (see the "ac_server.py reports table has no retention"
issue). This isolates that trimming behavior against a real on-disk
SQLite file, without a running server/network -- matches this project's
existing unit-test style (see test_ratelimiter_unit.py).
"""
import importlib.util
import pathlib
import sqlite3
import sys
import tempfile

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


def row_count(db_path, client_id):
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE client_id = ?", (client_id,)
        )
        return cur.fetchone()[0]
    finally:
        conn.close()


print("=== Store unit test: per-client_id report retention ===")
print()

with tempfile.TemporaryDirectory() as tmp:
    db_path = str(pathlib.Path(tmp) / "cap.db")
    store = ac_server.Store(db_path, max_reports_per_client=5)

    for i in range(20):
        store.add_report("capped-client", "AC_EV_PTRACE", f"detail {i}", None, "127.0.0.1")

    check(
        "rows trimmed to the configured cap (20 inserted, cap=5)",
        row_count(db_path, "capped-client") == 5,
    )

    latest = store.list_reports("capped-client", limit=10)
    check(
        "the rows kept are the most recent ones, not the oldest",
        [r["detail"] for r in latest] == [f"detail {i}" for i in range(19, 14, -1)],
    )

    other_db = str(pathlib.Path(tmp) / "other-client.db")
    other_client_store = ac_server.Store(other_db, max_reports_per_client=5)
    other_client_store.add_report("client-a", "AC_EV_PTRACE", "a", None, "127.0.0.1")
    for i in range(20):
        other_client_store.add_report("client-b", "AC_EV_PTRACE", f"b{i}", None, "127.0.0.1")
    check(
        "the cap is per-client_id, not global",
        row_count(other_db, "client-a") == 1 and row_count(other_db, "client-b") == 5,
    )

    uncapped_db = str(pathlib.Path(tmp) / "uncapped.db")
    uncapped = ac_server.Store(uncapped_db, max_reports_per_client=0)
    for i in range(20):
        uncapped.add_report("no-cap-client", "AC_EV_PTRACE", f"detail {i}", None, "127.0.0.1")
    check(
        "max_reports_per_client=0 disables the cap",
        row_count(uncapped_db, "no-cap-client") == 20,
    )

print()
if FAIL:
    print("\033[1;31mSOME STORE RETENTION UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL STORE RETENTION UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)
