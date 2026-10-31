import sys, json, re, collections
from urllib.parse import unquote_plus

ORDER = ["LOG4SHELL", "RCE", "SQLI", "PATH_TRAVERSAL", "XSS", "SECRET_PROBE", "CREDENTIAL_ATTEMPT",
         "ADMIN_PROBE", "CMS_PROBE", "KNOWN_SCANNER", "RECON", "UNKNOWN"]
SEV = {t: "high" for t in ORDER[:4]}
SEV.update({t: "medium" for t in ORDER[4:7]})
SEV.update({t: "low" for t in ORDER[7:10]})
SEV.update({"RECON": "info", "UNKNOWN": "info"})

CONTENT = [
 ("LOG4SHELL", re.compile(r"\$\{\s*jndi:")),
 ("RCE", re.compile(r"(;\s*(cat|ls|id|wget|curl|nc|bash|sh)\b|\|\s*(id|whoami|cat)\b|\$\(|`[^`]+`|/bin/(ba)?sh|cmd\.exe|powershell)")),
 ("SQLI", re.compile(r"(\bunion\b.{0,30}\bselect\b|\bselect\b.{0,60}\bfrom\b|'\s*or\s*'?\d|\bor\s+\d+\s*=\s*\d+|sleep\s*\(|benchmark\s*\(|information_schema|'\s*--|;\s*drop\s)")),
 ("PATH_TRAVERSAL", re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|c:\\windows)")),
 ("XSS", re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()")),
]
PATHS = [
 ("SECRET_PROBE", re.compile(r"(/\.env|/\.git/|/\.aws/|/\.ssh/|id_rsa|wp-config|/config\.(php|json|yml)|\.sql(\.gz)?$|/backup|/\.ds_store|/\.htpasswd|/server-status|/actuator/env)")),
 ("ADMIN_PROBE", re.compile(r"(/admin|/administrator|/wp-login\.php|/phpmyadmin|/manager/html|/cpanel|/login)")),
 ("CMS_PROBE", re.compile(r"(/wp-admin|/wp-content|/wp-includes|/xmlrpc\.php|/joomla|/drupal|/cgi-bin/)")),
]
TOOL = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|dirb|wpscan|acunetix|nessus|burp|hydra|feroxbuster|ffuf)")
BOT = re.compile(r"(curl/|python-requests|go-http-client|wget/|httpx|libwww|java/|okhttp|scrapy)")
RECON_PATHS = {"/", "/robots.txt", "/sitemap.xml", "/favicon.ico"}

def dec(s):
    return unquote_plus(unquote_plus(s or "")).lower()

def classify(h):
    path, ua, body = h.get("path", ""), h.get("ua", ""), h.get("body", "")
    body_s = json.dumps(body) if isinstance(body, dict) else str(body)
    text = dec(path + " " + body_s + " " + ua)
    p = dec(path.split("?")[0])
    tags = set()
    for t, rx in CONTENT:
        if rx.search(text): tags.add(t)
    for t, rx in PATHS:
        if rx.search(p): tags.add(t)
    if TOOL.search(ua.lower()): tags.add("KNOWN_SCANNER")
    if h.get("method") == "POST" and isinstance(body, dict) and "username" in body and "ADMIN_PROBE" in tags:
        tags.add("CREDENTIAL_ATTEMPT")
    if not tags:
        tags.add("RECON" if p in RECON_PATHS else "UNKNOWN")
    ordered = sorted(tags, key=ORDER.index)
    return {"tags": ordered, "primary": ordered[0], "sev": SEV[ordered[0]],
            "bot": bool(BOT.search(ua.lower())) or bool(TOOL.search(ua.lower())) or not ua}

def load(path):
    hits = []
    for line in open(path, encoding="utf-8", errors="ignore"):
        i = line.find("{")
        if i < 0: continue
        try: d = json.loads(line[i:])
        except Exception: continue
        if isinstance(d, dict) and "path" in d and "ts" in d: hits.append(d)
    return hits

def mask(ip):
    if ":" in ip: return ":".join(ip.split(":")[:3]) + ":x"
    p = ip.split(".")
    return ".".join(p[:3]) + ".x" if len(p) == 4 else ip

if __name__ == "__main__":
    hits = load(sys.argv[1] if len(sys.argv) > 1 else "hits.jsonl")
    res = [{**h, **classify(h)} for h in hits]
    n = len(res)
    print(f"Hits: {n} | unique IPs: {len({r['ip'] for r in res})} | bot-like clients: {sum(r['bot'] for r in res)}/{n}")
    print("\nBy category:")
    for t, c in collections.Counter(r["primary"] for r in res).most_common():
        print(f"  {t:20} {c}")
    print("\nBy severity:", dict(collections.Counter(r["sev"] for r in res)))
    print("\nTop paths:")
    for p, c in collections.Counter(r["path"].split("?")[0] for r in res).most_common(5):
        print(f"  {c:3} {p[:50]}")
    print("\nTop IPs (masked):")
    for ip, c in collections.Counter(mask(r["ip"]) for r in res).most_common(5):
        print(f"  {c:3} {ip}")
    print("\nHigh/medium hits:")
    for r in sorted([r for r in res if r["sev"] in ("high", "medium")], key=lambda r: r["sev"] != "high")[:15]:
        print(f"  {r['ts'][11:19]} {r['primary']:18} {mask(r['ip']):16} {r['path'][:45]}")
    json.dump(res, open("classified.json", "w"), indent=2)
    print("\nSaved: classified.json")
