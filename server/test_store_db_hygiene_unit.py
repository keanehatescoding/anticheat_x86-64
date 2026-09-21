#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_store_db_hygiene_unit.py -- Store SQLite hygiene from #30.

Three related checklist items, one file, no server/network:

- DB file path not protected against symlink-follow: Store() now refuses
  a symlinked --db path fail-closed instead of reading/writing (and
  chmod-ing) through it.
- PRAGMA journal_mode=WAL re-set on every connection: _connect() now
  queries the current mode first and only upgrades when not already WAL.
- No schema-migration/versioning table: fresh DBs are stamped with
  SCHEMA_VERSION via PRAGMA user_version, pre-existing version-0 DBs are
  upgraded on open, and unknown future versions refuse to open.
"""
import importlib.util
import os
import pathlib
import sqlite3
import stat
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


def user_version(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


def journal_mode(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()


print("=== Store unit test: DB hygiene (#30) ===")
print()

with tempfile.TemporaryDirectory() as tmp:
    tmp = pathlib.Path(tmp)

    # 1. Fresh DB: stamped + WAL, still fully usable.
    fresh = str(tmp / "fresh.db")
    store = ac_server.Store(fresh)
    store.add_report("c1", "E", "D", 1, "127.0.0.1")
    check("fresh DB opens and stores a report",
          len(store.list_reports("c1")) == 1)
    check("fresh DB stamped with SCHEMA_VERSION",
          user_version(fresh) == ac_server.Store.SCHEMA_VERSION)
    check("fresh DB is in WAL mode",
          str(journal_mode(fresh)).lower() == "wal")

    # 2. Symlinked DB path refused (link to a real file).
    real = str(tmp / "real.db")
    ac_server.Store(real).add_report("c", "E", "D", 1, "127.0.0.1")
    link = str(tmp / "link.db")
    os.symlink(real, link)
    try:
        ac_server.Store(link)
        refused = False
    except RuntimeError:
        refused = True
    check("symlinked --db path refused fail-closed", refused)

    # 2b. Dangling symlink refused too (lstat sees the link even when
    # the target is missing).
    dangling = str(tmp / "dangling.db")
    os.symlink(str(tmp / "does-not-exist.db"), dangling)
    try:
        ac_server.Store(dangling)
        refused_dangling = False
    except RuntimeError:
        refused_dangling = True
    check("dangling symlinked --db path refused", refused_dangling)

    # 3. Pre-existing version-0 DB (every DB created before versioning)
    # upgrades to SCHEMA_VERSION without losing rows.
    legacy = str(tmp / "legacy.db")
    conn = sqlite3.connect(legacy)
    conn.execute(
        "CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " client_id TEXT NOT NULL, event_type TEXT NOT NULL,"
        " detail TEXT NOT NULL, client_ts INTEGER,"
        " received_at INTEGER NOT NULL, source_addr TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE bans (client_id TEXT PRIMARY KEY, reason TEXT NOT NULL,"
        " banned_at INTEGER NOT NULL)"
    )
    conn.execute(
        "INSERT INTO reports (client_id, event_type, detail, client_ts,"
        " received_at, source_addr) VALUES (?,?,?,?,?,?)",
        ("legacy-client", "E", "kept", 1, 1, "127.0.0.1"),
    )
    conn.commit()
    conn.close()
    check("legacy fixture really starts at user_version 0",
          user_version(legacy) == 0)
    legacy_store = ac_server.Store(legacy)
    check("version-0 DB upgraded to SCHEMA_VERSION on open",
          user_version(legacy) == ac_server.Store.SCHEMA_VERSION)
    check("upgrade preserves existing rows",
          len(legacy_store.list_reports("legacy-client")) == 1)

    # 4. Unknown future schema refused instead of written into.
    future = str(tmp / "future.db")
    ac_server.Store(future)
    conn = sqlite3.connect(future)
    conn.execute("PRAGMA user_version=99")
    conn.commit()
    conn.close()
    try:
        ac_server.Store(future)
        refused_future = False
    except RuntimeError:
        refused_future = True
    check("unknown future schema version refused", refused_future)

    # 5. Second open on an already-WAL DB does not re-issue the WAL
    # pragma (the #30 "re-set on every connection" waste).
    calls = []
    real_sqlite_mod = ac_server.sqlite3

    class _RecConn:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *a, **k):
            calls.append(sql)
            return self._conn.execute(sql, *a, **k)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    class _RecMod:
        def connect(self, *a, **k):
            return _RecConn(real_sqlite_mod.connect(*a, **k))

        def __getattr__(self, name):
            return getattr(real_sqlite_mod, name)

    ac_server.sqlite3 = _RecMod()
    try:
        ac_server.Store(fresh)
    finally:
        ac_server.sqlite3 = real_sqlite_mod
    wal_sets = [c for c in calls if str(c).strip().lower() == "pragma journal_mode=wal"]
    check("already-WAL DB skips the redundant journal_mode=WAL set",
          wal_sets == [])

    # 5b. :memory: handles never get the WAL upgrade pragma: their mode
    # reports "memory", which the WAL check alone would treat as "not
    # WAL" and try to upgrade. (Construction only -- a :memory: Store
    # can't serve later requests anyway since every connection gets its
    # own private database.)
    mem_calls = []

    class _MemRecConn:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *a, **k):
            mem_calls.append(sql)
            return self._conn.execute(sql, *a, **k)

        def __getattr__(self, name):
            return getattr(self._conn, name)

    class _MemRecMod:
        def connect(self, *a, **k):
            return _MemRecConn(real_sqlite_mod.connect(*a, **k))

        def __getattr__(self, name):
            return getattr(real_sqlite_mod, name)

    ac_server.sqlite3 = _MemRecMod()
    try:
        ac_server.Store(":memory:")
    finally:
        ac_server.sqlite3 = real_sqlite_mod
    mem_wal_sets = [c for c in mem_calls
                    if str(c).strip().lower() == "pragma journal_mode=wal"]
    check(":memory: issues no journal_mode=WAL pragma", mem_wal_sets == [])

    # 6. _ensure_private never follows symlinks: a planted
    # <db>-wal symlink must be left alone (no chmod on the target).
    # (A planted -wal link also makes SQLite itself refuse the next
    # write with "unable to open database file" -- fail-closed at that
    # layer too -- so this asserts the narrower unit we own: the chmod
    # helper neither follows the link nor raises on it.)
    target = tmp / "outside.txt"
    target.write_text("do not touch")
    target_mode = stat.S_IMODE(os.stat(target).st_mode)
    victim = str(tmp / "victim.db")
    vst = ac_server.Store(victim)
    os.symlink(str(target), victim + "-wal")
    try:
        vst._ensure_private()
        survived = True
    except Exception:
        survived = False
    check("_ensure_private with a planted -wal symlink does not raise", survived)
    check("-wal symlink itself left in place (not replaced)",
          os.path.islink(victim + "-wal"))
    check("symlink target mode untouched (chmod did not follow)",
          stat.S_IMODE(os.stat(target).st_mode) == target_mode)

print()
if FAIL:
    print("\033[1;31mSOME STORE DB HYGIENE UNIT TESTS FAILED\033[0m")
else:
    print("\033[1;32mALL STORE DB HYGIENE UNIT TESTS PASSED\033[0m")
sys.exit(FAIL)
