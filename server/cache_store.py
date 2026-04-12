import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "cache.db"


def init_cache_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS apk_cache (
                hash TEXT PRIMARY KEY,
                ttl INTEGER NOT NULL,
                verdict TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY,
                ttl INTEGER NOT NULL,
                abuse_score INTEGER NOT NULL
            )
            """
        )
        conn.commit()


def get_cached_verdict(file_hash: str) -> dict | None:
    now = int(time.time())

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT ttl, verdict FROM apk_cache WHERE hash = ?",
            (file_hash,),
        )
        row = cursor.fetchone()

        if row is None:
            return None

        expires_at, verdict_json = row
        if int(expires_at) <= now:
            conn.execute("DELETE FROM apk_cache WHERE hash = ?", (file_hash,))
            conn.commit()
            return None

    try:
        return json.loads(verdict_json)
    except json.JSONDecodeError:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM apk_cache WHERE hash = ?", (file_hash,))
            conn.commit()
        return None


def set_cached_verdict(file_hash: str, verdict: dict, ttl_seconds: int) -> None:
    expires_at = int(time.time()) + int(ttl_seconds)
    verdict_json = json.dumps(verdict, ensure_ascii=False)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO apk_cache (hash, ttl, verdict)
            VALUES (?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                ttl = excluded.ttl,
                verdict = excluded.verdict
            """,
            (file_hash, expires_at, verdict_json),
        )
        conn.commit()


def get_cached_ip_score(ip: str) -> int | None:
    now = int(time.time())

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT ttl, abuse_score FROM ip_cache WHERE ip = ?",
            (ip,),
        )
        row = cursor.fetchone()

        if row is None:
            return None

        expires_at, abuse_score = row
        if int(expires_at) <= now:
            conn.execute("DELETE FROM ip_cache WHERE ip = ?", (ip,))
            conn.commit()
            return None

    try:
        return int(abuse_score)
    except (TypeError, ValueError):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM ip_cache WHERE ip = ?", (ip,))
            conn.commit()
        return None


def set_cached_ip_score(ip: str, abuse_score: int, ttl_seconds: int) -> None:
    expires_at = int(time.time()) + int(ttl_seconds)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO ip_cache (ip, ttl, abuse_score)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                ttl = excluded.ttl,
                abuse_score = excluded.abuse_score
            """,
            (ip, expires_at, int(abuse_score)),
        )
        conn.commit()