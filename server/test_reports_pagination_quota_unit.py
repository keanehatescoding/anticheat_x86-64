#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_reports_pagination_quota_unit.py -- fast, deterministic test of
Store's global report cap and offset pagination.

Two gaps filed as High-severity server issues, both in server/ac_server.py:

- No global report-database cap across distinct client_ids: only
  --max-reports-per-client bounds one client_id, so anyone able to mint
  arbitrarily many distinct client_ids grows the SQLite file without
  bound (#26). Store(max_total_reports=...) trims oldest-first across
  the whole table on every insert.
- list_reports() hardcodes limit=200 with no offset, so history past the
  most recent 200 rows is invisible through the API (#27).
  list_reports() now takes limit=/offset= and the HTTP endpoint exposes
  them as ?limit=&offset= (clamped to MAX_LIST_LIMIT, invalid values
  rejected with 400 at the handler layer).

Real on-disk SQLite, no server/network -- matches this project's
existing unit-test style (see test_store_retention_unit.py).
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


def total_rows(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    finally:
        conn.close()


print("=== Reports unit test: global quota + pagination ===")
print()

with tempfile.TemporaryDirectory() as tmp:
    # --- global cap across distinct client_ids (#26) ---
    db_path = str(pathlib.Path(tmp) / "quota.db")
    store = ac_server.Store(
        db_path, max_reports_per_client=1000, max_total_reports=10
    )
    for i in range(7):
        store.add_report("client-a", "AC_EV_PTRACE", f"a{i}", None, "127.0.0.1")
    for i in range(7):
        store.add_report("client-b", "AC_EV_PTRACE", f"b{i}", None, "127.0.0.1")
    check(
        "global cap bounds the whole table (14 inserted, cap=10)",
        total_rows(db_path) == 10,
    )
    survivors = [
        r["detail"]
        for r in store.list_reports("client-a", limit=100)
    ] + [
        r["detail"]
        for r in store.list_reports("client-b", limit=100)
    ]
    check(
        "global trim evicts oldest-first (a0..a3 gone, newest kept)",
        sorted(survivors) == sorted(
            [f"a{i}" for i in range(4, 7)] + [f"b{i}" for i in range(7)]
        ),
    )

    # --- per-client cap still applies underneath the global one ---
    tight_db = str(pathlib.Path(tmp) / "tight.db")
    tight = ac_server.Store(
        tight_db, max_reports_per_client=5, max_total_reports=1000
    )
    for i in range(20):
        tight.add_report("capped", "AC_EV_PTRACE", f"d{i}", None, "127.0.0.1")
    check(
        "per-client cap unaffected by the global cap (20 inserted, cap=5)",
        total_rows(tight_db) == 5,
    )

    # --- 0 disables the global cap ---
    off_db = str(pathlib.Path(tmp) / "off.db")
    off = ac_server.Store(off_db, max_reports_per_client=0, max_total_reports=0)
    for i in range(30):
        off.add_report(f"client-{i}", "AC_EV_PTRACE", "x", None, "127.0.0.1")
    check(
        "max_total_reports=0 disables the global cap",
        total_rows(off_db) == 30,
    )

    # --- pagination (#27) ---
    page_db = str(pathlib.Path(tmp) / "pages.db")
    pages = ac_server.Store(page_db)
    for i in range(10):
        pages.add_report("paged", "AC_EV_PTRACE", f"detail {i}", None, "127.0.0.1")
    first = [r["detail"] for r in pages.list_reports("paged", limit=3, offset=0)]
    second = [r["detail"] for r in pages.list_reports("paged", limit=3, offset=3)]
    check(
        "limit/offset pages newest-first without overlap",
        first == ["detail 9", "detail 8", "detail 7"]
        and second == ["detail 6", "detail 5", "detail 4"],
    )
    check(
        "offset past the end returns no rows",
        pages.list_reports("paged", limit=5, offset=999) == [],
    )
    check(
        "default listing still returns the first page (limit=200)",
        len(pages.list_reports("paged")) == 10,
    )
    check(
        "huge limit is clamped to MAX_LIST_LIMIT, not passed through",
        len(pages.list_reports("paged", limit=10**9)) == 10,
    )

    # --- handler-side ?limit=&offset= validation (400 contract) ---
    handler_cls = ac_server.make_handler(
        pages,
        frozenset({"report-key-12345678"}),
        frozenset({"admin-key-12345678"}),
        ac_server.RateLimiter(10**6, 60),
    )
    check(
        "defaults without query params (200, 0)",
        handler_cls._parse_listing_params("") == (200, 0),
    )
    check(
        "explicit limit/offset parse",
        handler_cls._parse_listing_params("limit=5&offset=10") == (5, 10),
    )
    check(
        "limit above the ceiling clamps instead of erroring",
        handler_cls._parse_listing_params("limit=999999")[0]
        == ac_server.Store.MAX_LIST_LIMIT,
    )
    rejected = 0
    for bad in ("limit=abc", "limit=0", "limit=-5", "offset=-1",
                "offset=1.5", "limit=", "offset=x",
                "limit=5&limit=6", "limit=5&limit=abc", "offset=1&offset=2"):
        try:
            handler_cls._parse_listing_params(bad)
        except ValueError:
            rejected += 1
    check("non-decimal/negative/zero/repeated pagination rejected (10/10)",
          rejected == 10)

print()
if FAIL:
    print("\033[1;31mSOME REPORTS PAGINATION/QUOTA UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL REPORTS PAGINATION/QUOTA UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)
