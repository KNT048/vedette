# Deferred from fix/ai-before-v1

- [ ] ai log digest: `asset_id` of an item is left empty (the model must not invent device ids); the box could fill it from the bad connections once the GUI wants the "View device" link on every item (S-AI-4, D-221). Owner: Emily.
- [ ] ai log digest: no schedule (cadence says "made when you ask"); an hourly/daily run for the `med`/`min` levels needs a job and a story criterion (S-AI-4). Owner: Emily.
- [ ] block-pii: secrets with no marker a pattern can tell from prose are not recognised (D-220): ` password x` under `line vty`, YAML `password: x`, a PuTTY key file body, an IOS `snmp-server host <ip> version 2c <community>` (no keyword), a FortiGate `set name "x"` inside an SNMP community block; a vendor-aware config parser if a customer needs it. Owner: Emily.
- [ ] logs L4 (PR #375) changes `Digest.BadConnections` from `[]struct{}` to the IocHit list: the adapter copies through JSON, so it needs no edit, but re-run `TestAILogDigestReadsKindsAndCountsNotLines` after that merge with a real bad connection in it. Owner: Emily.
- [ ] e2e-real: the `AI_DIGEST_501` allowances were removed from `logs.global.spec.ts` without a Playwright run (not allowed here); run `make e2e-real` on logs.global.spec.ts before merge. Owner: supervisor.
