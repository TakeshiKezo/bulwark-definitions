# Bulwark definitions

Signed threat definitions for the **Bulwark** Android security app (private, non-commercial family use).
Built every 6 hours by GitHub Actions and served via GitHub Pages:

    https://takeshikezo.github.io/bulwark-definitions/v1/manifest.json

| File | Content |
|---|---|
| `manifest.json` + `manifest.sig` | version, SHA-256 of every file, ECDSA P-256 signature (verified by the app) |
| `hash_blocklist.txt` | SHA-256 hashes of malware files / signing certificates |
| `rules.yar` | YARA rules (Bulwark subset) |
| `phishing_domains.txt` | phishing and malware domains |
| `trusted_certs.txt` | known publisher certificates |

The private signing key is never stored in this repository (secret `DEFS_SIGNING_KEY_B64`).
If any source is unavailable, or a list shrinks by more than 50 %, the build fails and the
last good set stays online.

## Data sources and licenses

| Source | License / terms |
|---|---|
| [MalwareBazaar](https://bazaar.abuse.ch) and [URLhaus](https://urlhaus.abuse.ch) by abuse.ch | free for not-for-profit use under the abuse.ch fair use principles |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | MIT License (c) Mitchell Krog, Nissar Chababy and contributors |
| [Phishing Army](https://phishing.army) | CC BY-NC 4.0 |

Bulwark is used non-commercially. Re-check all licenses before any commercial use.

## Local build

    java feeds/FeedBuilder.java --sources feeds/sources.json --base base --out site/v1 --key <dir-with-defs_private.pk8>
