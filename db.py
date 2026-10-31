import os, json, threading
URL = os.environ.get("DATABASE_URL")
try:
    import psycopg
except Exception:
    psycopg = None

def enabled():
    return bool(URL and psycopg)

def _conn():
    return psycopg.connect(URL, connect_timeout=5)

def init():
    if not enabled():
        return
    try:
        with _conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS hits (
                id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ, ip TEXT, method TEXT, path TEXT,
                ua TEXT, body TEXT, category TEXT, sev TEXT, canary BOOLEAN)""")
    except Exception as e:
        print("db init error:", e, flush=True)

def _save(rec):
    try:
        body = rec["body"] if isinstance(rec["body"], str) else json.dumps(rec["body"], ensure_ascii=False)
        with _conn() as c:
            c.execute("INSERT INTO hits (ts, ip, method, path, ua, body, category, sev, canary) "
                      "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                      (rec["ts"], rec["ip"], rec["method"], rec["path"], rec["ua"], body,
                       rec["primary"], rec["sev"], rec["canary"]))
    except Exception as e:
        print("db save error:", e, flush=True)

def save(rec):
    if enabled():
        threading.Thread(target=_save, args=(rec,), daemon=True).start()

def stats():
    if not enabled():
        return {"db": "off"}
    with _conn() as c:
        total = c.execute("SELECT count(*) FROM hits").fetchone()[0]
        first = c.execute("SELECT min(ts) FROM hits").fetchone()[0]
        rows = c.execute("SELECT category, count(*) FROM hits GROUP BY category ORDER BY 2 DESC").fetchall()
    return {"total": total, "since": str(first), "by_category": dict(rows)}
