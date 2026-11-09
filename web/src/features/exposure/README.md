# features/exposure

Story: S-EXP-1 (domain or verified public IP → prove ownership → commitment checkbox → list subdomains, IPs, open ports, exposed admin interfaces, expiring certificates; daily snapshots and comparing two days).
LEGAL §3 rule: no scan unless ownership is verified, and the commitment ("my company owns this and I am authorized to scan it", with who and when) is recorded. The "Scan now" button is locked with a reason, and the API returns 409 `not_verified` / `expired` / `txt_missing`, or 400 `commitment_required`, if called directly.
Ownership: a domain = DNS TXT record `vedette-verify=<token>`, re-checked right before every scan (missing = blocked). A public IP = only the IP this box itself uses to reach the Internet (`POST /exposure/box-ip/verify`, no IP input), valid 90 days, `expires_at` + `validity` (valid / expiring ≤ 14 days / expired). Private, reserved and CGNAT results are refused; verification attempts are limited to 10 per hour; everything is audited.
Mock tables: `exp_targets`, `exp_snapshots`, `exp_commitments`, `exp_attempts`. DNS simulation: the first TXT check of a new domain says "not found", from the second it is found. Box egress simulation: localStorage `vedette-mock-egress` (default 203.0.113.10) is the IP the box currently egresses through.
For the scan module: `exposureTargetsStore` (kind, value, verified_at, expires_at), `exposureSnapshotsStore`, `exposureCommitmentsStore`; or `GET /api/v1/exposure/targets` and use only `scannable` targets.
Roles: add/delete target, verify box IP, commitment = admin; re-check ownership, scan now = operator; view = viewer.
Slots: none provided, none consumed.
