# MCP-server — Change Impact Map

> Package `modules/mcp-server` (`mcpserver`); wired in `cmd/vedette/mcpserver.go`. Tests: `go test ./modules/mcp-server/... -run Contract`, `go test ./cmd/vedette -run 'MCP'`.

## Modifying: `Tools` (the tool set, schema, scope) — 3 callers
- **A customer's agent/SIEM** (outside the system): changing a tool name/returned schema → agents that are already configured break without a clear error. Adding a tool = changing the data surface that leaves the box at the user's hand: put it in an existing scope, record it in CONTRACT INV-1 and PRIVACY flow 13. `TestContract_INV7_AnswersFitTheirOutputSchema` catches an answer that drifts from the schema.
- **`McpHandlers.CoreGetCoreMcp`** (`handlers.go`): returns `tools[]` (name + scope) and `scopes[]` for `GET /core/mcp`; the contract `get /core/mcp` in `web/src/features/core/contract.ts`.
- **web/features/core/McpSection**: shows `tools[]`/`scopes[]` from `GET /core/mcp` and the label `mcp.tools.<name>` in `core.json`; adding a tool → add a label and the mock `MCP_TOOLS` in `web/src/features/core/mocks.ts`.

## Modifying: `Source` (the data gate) and `mcpSource` (cmd/vedette)
- It is a **consumer** of `inventory.Service.Devices/Device`, `findings.Service.List/Get`, `feeds.FeedHandlers.FeedsGetFeedsCveID/Search/Hot`: changing a field there does not leak out by itself (an allow list per field) but can make a field disappear here. The secret filtering lives in `mcpSource`, not in the source modules; `TestMCPServerOnTheRealWiring` checks that the MAC, notes, scan request/response and approvers do not reach the agent.

## Modifying: `authenticate`, `CleanScopes`, `hashToken`
- Changing the scope matching or the hashing → old tokens may become invalid or over-privileged; the INV-2/INV-3/INV-4 tests are mandatory.

## Modifying: `rpc.go` (the protocol)
- Changing the supported version, a required header or an error code → real MCP clients may fail to connect; `TestContract_Transport`, `TestContract_BothEras`.

## Modifying: bind/port (`-mcp-listen`, `DefaultListen`)
- Changing from loopback to another interface = a security + PRIVACY change (INV-5, FORBID-4); `New` and `parseMCPListen` refuse it, tests `TestContract_INV5_LoopbackOnly`, `TestParseMCPListen`. The flag is in `newFlags`; when left empty `parseMCPListen` chooses `0.0.0.0:8765` inside a container and `127.0.0.1:8765` outside one. The `core` Quadlet unit (`host/ops/quadlet.go`, `PublishPort=127.0.0.1:8765:8765`) and `deploy/compose/container-only/compose.yaml` (`127.0.0.1:8765:8765`) rely on that default and **pass no flag**: a new unit/compose with an old image (a rollback, a restart before the image step) must still run, and the old image refuses `0.0.0.0`. Changing the port = changing both places, `install.sh` (the free-port check), `Endpoint` (reports `127.0.0.1` + the same port) and the text on the screen; changing the unit template needs a legacy line in `host/ops/quadlet_legacy.go`. Removing `InContainer`/`inContainer` → MCP becomes unreachable again in both install types.

## Modifying: the table `mcp_tokens`
- `modules/core/export_policy.go` lists which columns of `mcp_tokens` are exported (`token_hash` is skipped); adding/changing a column → edit the export policy there. `core/server/modules.go` maps the prefix `/core/mcp` to the module (off → 404); `modules/core/handlers_privacy.go` reads the switch for flow 13, `web/src/features/core/PrivacySection.tsx` links to `/settings/mcp`; wiring in `cmd/vedette/{main,modules,handler,mcpserver}.go`.

## Modifying: `recordCall` / limits
- Dropping the audit line per call violates INV-8 (`TestContract_INV6_INV8_…`); loosening the limit raises the cap on audit lines.

## Disabling this module
- The port is closed; an outside agent/SIEM loses access. No Vedette module depends on it. Tokens and configuration are kept. Settings → Privacy flow 13 becomes `off`.

- `list_findings` rows and `get_finding` carry `urgency` (under_attack, exploited, public_exploit, critical_edge, update_recommended), filled by `cmd/vedette/mcpserver.go` from findings' layer; the description no longer calls every finding exploited. Changing a code name = changing the schema `findingRowSchema`/`findingSchema`.

## Modifying: `Finding.Fix/Verification`, `CVEEntry` brief fields
- Built by `cmd/vedette` `mcpSource` from `findingCase` (the finding view and the brief of its CVE). A new field of `findings.View` or `feeds.Brief` reaches an agent only through an allow-listed field here and in `tools.go`.
- `list_findings` leaves out the findings of devices a person ignored (`findings.Views`) and `get_finding` answers not found for them (`View.Device.Ignored`), as every list does. `TestWiringAnIgnoredDeviceIsSilentUntilItIsWatchedAgain`.
