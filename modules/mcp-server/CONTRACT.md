# MCP-server Contract

> Tier: optional (off by default) · Story: S-MCP-1 · Note: this is the MCP **served by Vedette**; the AI's **outbound** MCP/connections belong to `core/conn` · Last verified: 2026-11-21 (every sentence checked against the code)
> The GUI lives under `core` (`web/src/features/core/{contract.ts,McpSection.tsx,mocks.ts}`, section `/core/mcp`). Backend: `modules/mcp-server` (package `mcpserver`), wired in `cmd/vedette/mcpserver.go`.

## Invariants (always true)
- **INV-1** **Read only**: seven fixed tools, in the order of `tools/list`: `list_assets`, `get_asset` (scope `assets`); `list_findings`, `get_finding` (scope `findings`); `lookup_cve`, `lookup_ioc`, `hot_vulnerabilities` (scope `feeds`). Each tool has an `inputSchema` (`additionalProperties: false`), an `outputSchema`, and the annotations `readOnlyHint: true`, `destructiveHint: false`. No write tool, no tool that runs commands, no path into `response` (SYS-8).
- **INV-2** Token scope ∈ {`assets`, `findings`, `feeds`}; creating a token needs ≥ 1 valid scope (400 `invalid_scopes`). `tools/list` lists only the tools in the token's scope; calling a tool outside the scope → JSON-RPC error `-32602`, the source is not read, nothing partial is returned. A scope returns only the data of the module that owns it (a `feeds` token does not see the devices that match a CVE).
- **INV-3** A token has the form `vmcp_` + 32 hex characters (128 bits); it is **returned in full exactly once** at creation; afterwards only `last4`; stored as a SHA-256 hex (SYS-4); never logged, never exported. A backup holds only the hash, so the token cannot be rebuilt.
- **INV-4** Revocation (deleting the row) takes effect on the next request; a revoked, malformed or missing token → 401 with `WWW-Authenticate: Bearer`. `last_used` is written on every tool call, and on other requests at most once a minute.
- **INV-5** The server is **reachable only from the machine's loopback**: the flag `-mcp-listen` (empty = `127.0.0.1:8765`, endpoint `http://127.0.0.1:8765/mcp`; in a container empty = `0.0.0.0:8765`); a non-loopback address → it does not start. The single exception: **inside a container** (`Config.InContainer`, cmd/vedette sees `/run/.containerenv` or `/.dockerenv`) the **unspecified address** `0.0.0.0`/`[::]` is accepted (the container's own network namespace, not the LAN) because the runtime forwards a published port to the container's address, not to its loopback; the `core` Quadlet unit and the container-only `compose.yaml` **do not pass the flag** (an older image refuses `0.0.0.0` and would not start) and publish only `127.0.0.1:8765:8765` (the host/ops golden test, `deploy/compose/compose_test.go`), and `GET /core/mcp` still reports `127.0.0.1:<port>`. Any other specific address (the LAN, the container's IP) is always refused. Exposing it beyond the host is a tunnel/proxy that the customer builds.
- **INV-6** Tool input is validated at the edge (SYS-2): only argument names in the schema, of the right type and length; CVE as `CVE-YYYY-NNNN+`, id as `^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`, an IOC is an IP or a domain by exactly the `validDomain` rule of feeds (it also accepts ASCII-form IDN TLDs such as `discord.xn--q9jyb4c`, `TestContract_INV7_AnswersFitTheirOutputSchema`). A mistake → a result with `isError: true` and an explanation so the client can fix it.
- **INV-7** The returned data consists only of assets, findings and feed lookups, by an allowlist for each field. It does **not** return: secrets, API keys, tokens, users, audit, the AI/response logs, channel configuration, raw log content, external connections, MACs, notes, who changed a status and their notes, the summary/request/response of a scan (the summary names the device: inventory data). Returned by `outputSchema`; a page ≤ 100 items, an answer ≤ 512 KiB, strings are cut (SYS-6).
- **INV-8** Admin operations (creating/revoking a token; switching on/off belongs to `core` through `PATCH /modules/mcp-server`) write `core_audit` (SYS-3), admin role. **Each `tools/call` writes one `core_audit` line** `mcp.call` (the token name, the tool, the result, the item count), written before the answer; the **arguments are not recorded**, because they are what the client asked.
- **INV-9** Protocol: Streamable HTTP, `POST` only; dual-era: either `_meta` of 2026-07-28 (the headers `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` are required and must match the body, a mismatch → 400 `-32020`; in the older era, if sent, they must match too) or `initialize` of 2025-03-26..2025-11-25; no `Mcp-Session-Id` is issued, no SSE, no batch; an `Origin` header → 403.
- **INV-10** Limits: each token 30 queued requests, refilling 30/minute, every authenticated request counts; 2,000 tool calls/day; answer slots 4 for the whole server, 2 per token, held after the body is read, waiting ≤ 2 s; at most 10 tokens (400 `too_many`). Exceeded → 429 + `Retry-After`, no audit.
- **INV-11** `GET /core/mcp` says whether the port is open (`listening`, `listen_error`); if the port is held by another program the screen warns, and the box retries every 15 seconds.

## Preconditions (before the call)
- **PRE-1** `/core/mcp*`: admin role; the `mcp-server` module on (off → 404, SYS-5). Switch on/off with `PATCH /modules/mcp-server` (admin role, `core`).
- **PRE-2** Calling a tool: the module on, a valid `Authorization: Bearer <token>` that has the tool's scope.

## Postconditions (sau khi xong)
- **POST-1** On → the port opens on loopback (in a container: the listener in its namespace; the runtime's `127.0.0.1:8765` publish holds the host-side port for as long as the container runs, and when the module is off connections to it are refused/cut); off → the port closes, open connections are cut, every token is unusable but **not deleted** (S-CORE-1).
- **POST-2** `POST /core/mcp/tokens` returns `{token, item}` (201); the list afterwards has only `item` (with `last4`).
- **POST-3** `GET /core/mcp` returns the state, the `bind`/`port`/`endpoint` of the running listener, the tokens (without secrets), the list of tools + scopes.

## Forbidden (never)
- **FORBID-1** A write tool, even "temporary" or by a privileged token.
- **FORBID-2** Returning secrets/keys/user tokens, audit, or data outside the three scopes.
- **FORBID-3** Storing a token in readable form; returning the full token a second time.
- **FORBID-4** Listening outside loopback, except the unspecified address inside a container whose unit publishes only on `127.0.0.1` (INV-5); never publishing on a LAN address.
- **FORBID-5** Using this MCP path for Vedette's own AI to call (the AI uses internal tools, `ai` INV-14); the two are separate.

## Endpoints owned
| Method | Path | Minimum role | Story |
|---|---|---|---|
| GET | `/core/mcp` | admin | S-MCP-1 |
| POST | `/core/mcp/tokens` | admin | S-MCP-1 |
| DELETE | `/core/mcp/tokens/{id}` | admin | S-MCP-1 |
| (MCP, HTTP) | `POST http://127.0.0.1:8765/mcp` | Bearer token by scope | S-MCP-1 |

The `/core/mcp*` routes sit under the `core` prefix in the GUI's `contract.ts` but belong to this module (`core/server/modules.go`). The MCP tools are not in `contract.ts`; the list and schemas in `modules/mcp-server/tools.go` are the contract.

## Tables owned
`mcp_tokens` (id, name, scopes, token_hash, last4, created_at, last_used).

## Events
- **Emits**: none. **Receives**: none. Reads inventory, findings and feeds through the port `mcpserver.Source` (`cmd/vedette/mcpserver.go`: the inventory/findings services, the feeds handler), and does not read another module's tables.

## When the module is off (SYS-5)
The port is closed, no `/core/mcp*` routes (404), no jobs. Tokens are kept but useless. An outside client/SIEM loses the connection (a connection error, not a 401). The UI says "MCP server is off" and keeps only the switch. When a source module (inventory, findings, feeds) is off → the tools of that scope return a tool error that names which module is off.

## Dependencies
- **DEPENDS ON**: `core` (admin auth, audit), soft: `inventory`, `findings`, `feeds`.
- **DEPENDED ON BY**: no module (outside users: clients/SIEMs). `core` reads the switch for privacy flow 13.

## Open questions
1. ~~Loopback inside the `core` container~~ Settled: in a container it listens on `0.0.0.0:8765`, the Quadlet unit and `compose.yaml` publish the host's `127.0.0.1:8765`. Other machines: the customer's SSH tunnel/proxy.
2. ~~Page and rate limits~~ Settled.
3. ~~Scan evidence in `get_finding`~~ Settled: only the summary, the template and the time of the check; raw request/response stays on the box.
4. ~~Table name~~ `mcp_tokens`.

## Findings view and CVE brief
- **INV-12** `list_findings` and `get_finding` rows carry `fix` (the fix of the device in one sentence, the stored fix the finding page shows) and `verification` (confirmed by a person, a safe check or the device, or not confirmed; a person is never named, INV-7: the same words the assistant gets). `lookup_cve` answers for any CVE the catalogue holds from the CVE brief: title, weaknesses, score read into words, affected versions and their origin, fixed release per release train, solution, workaround (or the sentence that none is published), references by group. `listed` is true only when an exploited list has the CVE; `entry` is null only for a CVE the catalogue does not hold. Test: `TestMCPEntryOfABriefWithAndWithoutAList`.
