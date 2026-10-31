import os, hashlib, ssl, threading
from datetime import datetime
from urllib.parse import urlparse
import pg8000.native

SALT = os.environ.get("IP_SALT", "honeypot")

def _conn():
    u = urlparse(os.environ["DATABASE_URL"])
    ctx = ssl.create_default_context() if "." in (u.hostname or "") else None
    return pg8000.native.Connection(
        user=u.username, password=u.password, host=u.hostname,
        port=u.port or 5432, database=u.path.lstrip("/"),
        ssl_context=ctx, timeout=5)

def init():
    c = _conn()
    c.run("""CREATE TABLE IF NOT EXISTS hits (
        id SERIAL PRIMARY KEY, ts TIMESTAMPTZ, ip_masked TEXT, ip_hash TEXT,
        method TEXT, path TEXT, ua TEXT, category TEXT, sev TEXT, canary BOOLEAN)""")
    c.close()

def _mask(ip):
    p = ip.split(".")
    return ".".join(p[:3] + ["x"]) if len(p) == 4 else ip.split(":")[0] + ":x"

def _save(rec):
    try:
        c = _conn()
        c.run("""INSERT INTO hits (ts, ip_masked, ip_hash, method, path, ua, category, sev, canary)
                 VALUES (:ts, :m, :h, :me, :p, :ua, :cat, :sev, :can)""",
              ts=datetime.fromisoformat(rec["ts"]), m=_mask(rec["ip"]),
              h=hashlib.sha256((SALT + rec["ip"]).encode()).hexdigest()[:12],
              me=rec["method"], p=rec["path"], ua=rec["ua"],
              cat=rec["primary"], sev=rec["sev"], can=bool(rec["canary"]))
        c.close()
    except Exception as e:
        print("db error:", type(e).__name__, flush=True)

def save_hit(rec):
    threading.Thread(target=_save, args=(dict(rec),), daemon=True).start()
