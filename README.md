# Vedette

**Know early. Know exactly. Know what to do.**

Vedette is free, open-source software that tells a business, within an hour, when a device or application it uses appears on the list of vulnerabilities **being exploited in the wild**, what it has and where it is exposed, and exactly what to do about it. It does **not** sit in the network path, block traffic or replace your firewall.

*Vedette* (French): a mounted sentry posted ahead of an outpost to raise the alarm early. It watches and warns; it does not fight.

| | |
|---|---|
| Status | Web interface complete on a mock API; backend not started |
| License | Apache-2.0 for Vedette's own code; third-party components keep their own licenses (`THIRD_PARTY_NOTICES.md`) |
| Author | Kien Nguyen, as a personal project |
| Disclaimer | Provided as is, without warranty (Apache-2.0 §7–8). The author is not responsible for how you use it — only scan systems you own and are authorised to scan |

## Try it

```bash
make dev
```

Open http://localhost:5173. On first run choose **Use sample data** to look around, or set it up from scratch.

## What leaves your machine

Exactly what `PRIVACY.md` lists. Notably, an **anonymous signal is on by default** (counts of trap touches, connections to bad IPs/domains and devices by type; no names, no IP addresses, no logs). Turn it off under Settings → Privacy.

## Documentation

Product and design documents are in `docs/` (written in Vietnamese for now): `PRODUCT.md`, `USER_STORIES.md`, `MODULES.md`, `ARCHITECTURE.md`, `DATA_PIPELINE.md`, `AI_ASSISTANT.md`, `UPDATES.md`, `ROADMAP.md`, `FRONTEND.md`, `LEGAL.md`, `DECISIONS.md`. The API contract is `api/openapi.json`, generated from the web app's mock (`pnpm --dir web openapi`).

## For AI agents working in this repo

Read `CLAUDE.md` first; rules live in `.claude/rules/`.
