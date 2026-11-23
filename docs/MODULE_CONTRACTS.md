# Module contracts

A contract puts **testable statements** at the boundary of each module so that anyone changing the module can read them first.

## Location
```
modules/<tên>/CONTRACT.md     INV-* / PRE-* / POST-* / FORBID-* + DEPENDS ON / DEPENDED ON BY
modules/<name>/IMPACT.md       every public function: who calls it (file:line), the consequence of changing it; who is affected when this module is switched off
modules/<name>/*_contract_test.go   one test per INV/POST
```

## Rules
1. Before changing a module: read CONTRACT + IMPACT. After changing it: every INV/POST still holds; `go test ./modules/<name>/... -run Contract`.
2. Breaking a contract on purpose → change **both** the CONTRACT and the test, and say so in the commit. Never break it silently.
3. A statement must be measurable. Wrong: "safe". Right: "`sensor-active` never scans an IP outside the approved `inv_scope` (INV-3)".
4. A new module: CONTRACT + IMPACT + MANIFEST before merge.

## System invariants (SYS-*, every module)
- SYS-1: External processes only through `core/exec` with an allowlist of binaries + argv; no shell is called with a command string.
- SYS-2: Input at the edge is validated against a schema before the service.
- SYS-3: Every mutation writes `core_audit`.
- SYS-4: Secrets only through `core/secrets` (AES-GCM), never logged, never exported.
- SYS-5: A module that is off: no route, no job, no port; the data is kept, except deletion of data past a retention period the customer has set or the product has published (CONTRACT and GUI), or past a storage cap recorded in the documentation, with an audit line for that deletion (the `Housekeeping` job of `core/jobs`).
- SYS-6: Data from feeds/logs/web/agents is untrusted: parsers fail closed, with size limits.
- SYS-7: Every network action outside the LAN (scan, fetch) must stay inside a scope whose ownership is verified or a declared feed source.
- SYS-8: AI không có tool ghi.

Template: `modules/_template/`.
