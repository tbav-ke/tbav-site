# Tender Bridge Africa Ventures — site + Kenya geo-gate

A self-contained container that serves the marketing site **and** blocks visitors
from Kenya (configurable), with an IP whitelist and a secret unlock link.
Isolated by design: it's one new Coolify app + one Traefik route. It does **not**
touch Safilist, your DNS zone, or your email records.

## How the gate behaves
- **Whitelisted IPs/CIDRs** → always see the site (your office, home, etc.).
- **Anyone with the unlock cookie** → always see the site (visit the unlock link once per browser/device).
- **Visitors from a blocked country (default Kenya)** → see a tidy "not available in your region" page.
- **Country unknown** → *served the site* (fails open — a mis-located international visitor is never wrongly blocked).
- Real client IP is read as the **right-most** `X-Forwarded-For` entry (what Traefik appends), so a visitor can't spoof their country.

## Structure
```
Dockerfile            php:8.3-apache; installs geoip2; downloads DB-IP Lite country DB at build
composer.json         geoip2/geoip2
app/public/index.php  front controller + gate
app/public/.htaccess  routes every request through index.php
app/private/gate.php  pure, unit-tested gate logic
app/private/site.html the marketing site
app/private/blocked.html  the region block page
test_gate.php         29 tests (run: php test_gate.php)
```

## Configuration — set these as ENV VARS in Coolify (never commit them)
| Variable | Value |
|---|---|
| `TBAV_UNLOCK_SECRET` | *(sent separately — your private unlock key)* |
| `TBAV_WHITELIST_IPS` | *(your office + home IPs/CIDRs, space or comma separated)* |
| `TBAV_BLOCK_COUNTRIES` | `KE` |
| `TBAV_COOKIE_DAYS` | `180` |

Because the IPs and the secret live in env vars, **this repo carries no secrets**
and can be a public repository.

## Deploy on Coolify
1. New Resource → **Public Repository** → paste this repo's URL.
2. Build Pack: **Dockerfile**. Exposed port: **80**.
3. Domains: `https://tenderbridgeafrica.com` (Coolify issues Let's Encrypt TLS).
4. Add the four environment variables above.
5. Deploy.

## DNS (Hostinger hPanel → DNS zone) — one record only
- Add/point an **A** record: host `@` → `173.249.7.165` (the Contabo VPS).
- **Do not touch** the `MX` records or the `TXT` records (SPF / DKIM / DMARC) — email stays as-is.

## Verify after deploy
- From a non-Kenyan network (or VPN): site loads.
- Visit the unlock link once: cookie set, site loads from anywhere.
- Confirm a Kenyan IP is blocked (checked server-side against the GeoIP DB).
