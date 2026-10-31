import csv
import db
from dashboard import W

def safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in "=+-@" else v

c = db._conn()
q = lambda s: c.run(f"SELECT {s} FROM hits WHERE {W}")
print("hits:", q("count(*)")[0][0])
print("unique ip_hash:", q("count(DISTINCT ip_hash)")[0][0])
print("sessions (ip x 5min):",
      q("count(DISTINCT ip_hash || floor(extract(epoch from ts)/300)::text)")[0][0])
rows = c.run(f"SELECT ts,ip_masked,ip_hash,method,path,left(ua,80),category,sev,canary "
             f"FROM hits WHERE {W} ORDER BY id")
with open("export.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["ts","ip_masked","ip_hash","method","path","ua","category","sev","canary"])
    for r in rows:
        w.writerow([safe(x) for x in r])
c.close()
print("export.csv rows:", len(rows))
