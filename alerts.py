import os, time, threading, requests
from classify import mask

TOKEN = os.environ.get("TG_TOKEN")
CHAT = os.environ.get("TG_CHAT")
IGNORE = {x.strip() for x in os.environ.get("IGNORE_IPS", "").split(",") if x.strip()}
COOLDOWN = 1800
HOURLY_CAP = 20
_lock = threading.Lock()
_last, _sent, _capped = {}, [], [False]

def defang(s):
    return s.replace("http", "hxxp").replace("\n", " ")[:90]

def _send(text):
    if not (TOKEN and CHAT):
        return
    try:
        requests.post("https://api.telegram.org/bot" + TOKEN + "/sendMessage",
                      data={"chat_id": CHAT, "text": text}, timeout=5)
    except Exception:
        pass

def _bg(text):
    threading.Thread(target=_send, args=(text,), daemon=True).start()

def handle(rec):
    if rec["ip"] in IGNORE:
        return
    canary = rec.get("canary")
    if not canary and rec["sev"] != "high":
        return
    now = time.time()
    if canary:
        key = ("CANARY", rec["ip"], rec["path"].split("?")[0])
    else:
        key = (rec["primary"], rec["ip"])
    with _lock:
        if len(_last) > 5000:
            _last.clear()
        if now - _last.get(key, 0) < COOLDOWN:
            return
        _sent[:] = [t for t in _sent if now - t < 3600]
        if not canary and len(_sent) >= HOURLY_CAP:
            if not _capped[0]:
                _capped[0] = True
                _bg("Alert cap reached (20/hour). High-severity alerts paused.")
            return
        _capped[0] = False
        _last[key] = now
        if not canary:
            _sent.append(now)
    icon = "\U0001F6A8" if canary else "\u26A0\uFE0F"
    head = "CANARY CREDENTIAL USED" if canary else "HIGH: " + rec["primary"]
    _bg(icon + " " + head + "\nIP " + mask(rec["ip"]) + "\n" + rec["method"] + " " + defang(rec["path"])
        + "\nUA " + defang(rec["ua"])[:60])
