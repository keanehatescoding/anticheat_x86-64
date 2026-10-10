#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR GPL-2.0-only
"""test_store_retention_unit.py -- fast, deterministic test of
Store.add_report()'s row caps.

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
import time

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
print("=== Store unit test: cap trims stay off the full-table scan (#90) ===")
print()

with tempfile.TemporaryDirectory() as tmp:
    ROWS = 100000
    big_db = str(pathlib.Path(tmp) / "big.db")
    big = ac_server.Store(
        big_db, max_reports_per_client=1000, max_total_reports=ROWS,
        vacuum_interval=0,
    )
    conn = sqlite3.connect(big_db)
    try:
        # Seed straight into the table: going through add_report() 100k
        # times is the slow path under test. 500 clients x 200 rows keeps
        # every client under its own cap while the table sits at the
        # global one.
        conn.executemany(
            "INSERT INTO reports (client_id, event_type, detail, client_ts, "
            "received_at, source_addr) VALUES (?,?,?,?,?,?)",
            (
                (f"client-{i % 500}", "AC_EV_PTRACE", f"seed {i}", None, 0,
                 "127.0.0.1")
                for i in range(ROWS)
            ),
        )
        conn.commit()

        # The plan is the deterministic half of the check: the DELETE
        # itself (the top-level plan rows, parent 0) must be an index
        # SEARCH. A SCAN there is the visit-every-row walk this guards
        # against; the subquery's own backward walk to the cutoff is fine.
        def scans_table(sql, params):
            plan = conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
            return any(
                row[1] == 0 and row[3].startswith("SCAN") for row in plan
            )

        check(
            "global trim does not full-scan the reports table",
            not scans_table(ac_server.Store._TRIM_GLOBAL_SQL, (ROWS,)),
        )
        check(
            "per-client trim does not full-scan the reports table",
            not scans_table(
                ac_server.Store._TRIM_CLIENT_SQL, ("client-0", "client-0", 1000)
            ),
        )
        oldest_before = conn.execute("SELECT MIN(id) FROM reports").fetchone()[0]
    finally:
        conn.close()

    # At the cap, so each insert evicts exactly one row. The bound is loose
    # on purpose (the old NOT IN shape took ~110ms per insert here, this
    # one a few ms including the commit) so a slow CI runner can't trip it.
    INSERTS = 20
    start = time.monotonic()
    for i in range(INSERTS):
        big.add_report("client-0", "AC_EV_PTRACE", f"new {i}", None, "127.0.0.1")
    per_insert = (time.monotonic() - start) / INSERTS
    check(
        "insert at the global cap stays under 50ms (%.1fms)" % (per_insert * 1000),
        per_insert < 0.05,
    )

    conn = sqlite3.connect(big_db)
    try:
        total = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        oldest_after = conn.execute("SELECT MIN(id) FROM reports").fetchone()[0]
    finally:
        conn.close()
    check("table held at the global cap", total == ROWS)
    check(
        "the oldest rows are the ones evicted",
        oldest_after == oldest_before + INSERTS,
    )
    check(
        "the newest rows survive the trim",
        [r["detail"] for r in big.list_reports("client-0", limit=3)]
        == [f"new {i}" for i in range(INSERTS - 1, INSERTS - 4, -1)],
    )

print()
if FAIL:
    print("\033[1;31mSOME STORE RETENTION UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL STORE RETENTION UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)
