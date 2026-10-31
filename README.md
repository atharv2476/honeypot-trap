# Honeypot Trap

A research honeypot: a fake "vulnerable" site that logs requests from scanners and bots.

- Fake admin/login pages, `.env`, `.git/config`, `robots.txt` bait
- Every request logged as JSON
- Passwords are never stored: only their length and a short hash prefix
- Fake canary credentials in the bait `.env`

Roadmap: attack classifier, dashboard, Telegram/Discord alerts.

> Educational project. Nothing sent to this site is executed.
