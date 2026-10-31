import os, hmac
from flask import Blueprint, request, Response, render_template_string
import db

bp = Blueprint("dash", __name__)
W = ("ip_masked NOT LIKE '127.%' AND ua NOT LIKE 'Go-http-client%' "
     "AND path NOT LIKE '/dashboard%' AND ua NOT LIKE '%UptimeRobot%'")

def _ok():
    pw = os.environ.get("DASH_PASSWORD", "")
    a = request.authorization
    return bool(pw) and a is not None and hmac.compare_digest(
        (a.password or "").encode(), pw.encode())

def _q(sql):
    c = db._conn()
    try:
        return c.run(sql)
    finally:
        c.close()

PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>Honeypot</title><style>body{font:14px sans-serif;margin:12px;background:#111;color:#eee}
table{border-collapse:collapse;margin:6px 0 18px;width:100%}td,th{border-bottom:1px solid #333;
padding:4px 6px;text-align:left;word-break:break-all}h2{margin:14px 0 2px;color:#7fd}</style>
<h1>ACME honeypot</h1><p>Real hits: {{total}} | Canary used: {{canary}}</p>
{% for title, rows in sections %}<h2>{{title}}</h2><table>
{% for r in rows %}<tr>{% for v in r %}<td>{{v}}</td>{% endfor %}</tr>{% endfor %}</table>{% endfor %}
<p><small>Counts approximate: IPs rotate, bots/scanners mixed, own tests may be included.</small></p>"""

@bp.route("/dashboard")
def dashboard():
    if not _ok():
        return Response("Auth required", 401, {"WWW-Authenticate": 'Basic realm="x"'})
    try:
        total = _q(f"SELECT count(*) FROM hits WHERE {W}")[0][0]
        canary = _q(f"SELECT count(*) FROM hits WHERE canary AND {W}")[0][0]
        sections = [
          ("Categories", _q(f"SELECT category,count(*) FROM hits WHERE {W} GROUP BY 1 ORDER BY 2 DESC")),
          ("Top paths", _q(f"SELECT left(split_part(path,'?',1),60),count(*) FROM hits WHERE {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 10")),
          ("Top IPs (masked)", _q(f"SELECT ip_masked,count(*) FROM hits WHERE {W} GROUP BY 1 ORDER BY 2 DESC LIMIT 10")),
          ("Per day", _q(f"SELECT ts::date,count(*) FROM hits WHERE {W} GROUP BY 1 ORDER BY 1 DESC LIMIT 8")),
          ("Latest 20", _q(f"SELECT to_char(ts,'MM-DD HH24:MI'),ip_masked,left(path,70),category,sev FROM hits WHERE {W} ORDER BY id DESC LIMIT 20")),
        ]
    except Exception as e:
        return Response("db error: " + type(e).__name__, 500)
    html = render_template_string(PAGE, total=total, canary=canary, sections=sections)
    return Response(html, headers={
        "Cache-Control": "no-store", "X-Robots-Tag": "noindex",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
