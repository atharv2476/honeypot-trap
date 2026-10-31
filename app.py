import json, re, hashlib, datetime
from classify import classify
from alerts import handle
from flask import Flask, request, Response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10_000

SECRET_RE = re.compile(r'(?i)(pass(?:word)?|pwd|secret|token)(["\']?\s*[:=]\s*["\']?)[^&"\'\s,}]+')

def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()

def safe_body():
    # Never store raw passwords: attackers may be replaying real stolen credentials.
    try:
        if request.form:
            out = {}
            for k, v in request.form.items():
                if "pass" in k.lower() or "pwd" in k.lower():
                    out[k] = "<len=%d sha256=%s>" % (len(v), hashlib.sha256(v.encode()).hexdigest()[:8])
                else:
                    out[k] = v[:80]
            return out
        return SECRET_RE.sub(r"\1\2<redacted>", request.get_data(as_text=True)[:300])
    except Exception:
        return "<unreadable or too large>"

import db
try:
    db.init()
except Exception as e:
    print("db init skipped:", type(e).__name__, flush=True)

CANARIES = ("canary_db_pass_91af", "canary_api_key_55c2")

def canary_used():
    try:
        hdrs = " ".join(v for _, v in request.headers.items())
        blob = " ".join([request.full_path, hdrs, " ".join(request.form.values()),
                         request.get_data(as_text=True)[:2000]])
    except Exception:
        return False
    return any(c in blob for c in CANARIES)

@app.before_request
def log_hit():
    rec = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "ip": client_ip(),
        "method": request.method,
        "path": request.full_path.rstrip("?")[:300],
        "ua": request.headers.get("User-Agent", "")[:200],
        "body": safe_body() if request.method in ("POST", "PUT", "PATCH") else "",
    }
    cls = classify(rec)
    rec["primary"] = cls["primary"]
    rec["sev"] = cls["sev"]
    rec["canary"] = canary_used()
    line = json.dumps(rec, ensure_ascii=False)
    print(line, flush=True)
    try:
        with open("hits.jsonl", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    db.save_hit(rec)
    handle(rec)

LOGIN = """<!DOCTYPE html><html><head><title>ACME Admin</title></head><body>
<h2>ACME Admin Login</h2>%s
<form method="post"><input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button>Login</button></form></body></html>"""

ENV = """APP_ENV=production
DB_HOST=db.acme.internal
DB_USER=acme_admin
DB_PASSWORD=canary_db_pass_91af
API_KEY=canary_api_key_55c2
"""

GIT = """[core]
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://git.acme.internal/acme/portal.git
"""

@app.route("/")
def home():
    return "<h1>ACME Internal Portal</h1><p><a href='/login'>Staff login</a></p>"

@app.route("/login", methods=["GET", "POST"])
@app.route("/admin", methods=["GET", "POST"])
@app.route("/administrator", methods=["GET", "POST"])
@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/phpmyadmin/", methods=["GET", "POST"])
def login():
    msg = "<p style='color:red'>Invalid credentials</p>" if request.method == "POST" else ""
    return LOGIN % msg

@app.route("/.env")
def env():
    return Response(ENV, mimetype="text/plain")

@app.route("/.git/config")
def git():
    return Response(GIT, mimetype="text/plain")

@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /.env\n", mimetype="text/plain")

@app.errorhandler(404)
def nf(e):
    return "<html><body><h1>404 Not Found</h1></body></html>", 404

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050)
