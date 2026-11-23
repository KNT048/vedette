# Mitigation — Change Impact Map

## Modifying: `mitigation.Provider.Guidance(ctx, findings.Row)` (the "What to do" part of `GET /findings/{id}`)
- **findings** (`FindingHandlers.SetGuidance`; skipped when mitigation is off) (merged into `FindingDetail`), the SPA finding page (`FindingPage.tsx`, `Recommendation.tsx`). The types `findings.Guide`/`MitigationPack`/`AIResult` (`findings/guide.go`) are the contract of this part. Changing `FindingDetail.pack|compromise|recheck|ai|applied` means changing `findings/contract.ts` (the OpenAPI source).

## Modifying: `{IP}`/`{HOST}` (deviceReplacer)
- When there is no device or the IP is not valid, the text has `<IP>`/`<HOST>` (the mock uses `<IP-NAS>`/the IP). Pasting it into a shell by mistake is harmless: `<` is input redirection from a file that does not exist, so the command fails and runs nothing. When the host name is unsafe or absent `{HOST}` is the device IP, exactly like the mock (`hostname ?? ip`).

## Modifying: the interfaces `Verifier`, `AI`, `Vendors` (mitigation/ports.go)
- **`cmd/vedette` `packVerifier`** (installs a `Verifier` on `internal/release.VerifyContent` and the embedded release key; missing = every pack is refused): changing `Statement` must change the `release packs` signing tool (`scripts/release`) at the same time, and every signature already published stops matching, **ai** (installs `AI`: `Available`, `Run` through `ai.Service.Brief`), **inventory** (installs `Vendors.HasFirewallVendor`: `cmd/vedette/wiring.go` asks `inventory.HasDevice` with kind `firewall` or `router`, comparing the vendor case-insensitively, including the vendor of software on the device, every device type that behaves like a firewall or router). Changing a signature = changing the wiring in `cmd/vedette`. `AI` is the door of the `ai` module (`aiMitigation`); `Loader` is built in `buildServices` with `packVerifier` and runs through the `load-packs` job.

## Modifying: `Provider.SetAgents` (the "agent still reports the device" check, INV-7)
- **cmd/vedette** `agentReports` (wiring.go) is the only check, shared with `findings.FindingHandlers.SetAgents` (Updates to plan) and following the same rule as `web/src/features/findings/agentNow.ts` (the title, the steps, the "I updated it" line). Changing the rule in one place must change all three, otherwise the finding page and "How to check" say different things again.

## Modifying: general hardening (`hardening.go`, INV-8)
- The SPA `web/src/features/findings/Hardening.tsx` (`GeneralChecks`) and the mock `hardeningMock.ts`; changing `findings.Hardening` (`{software, family, checks}`) means changing `findings/contract.ts` (`GeneralHardening`). No firewall configuration is written by code any more: do not add it back without a new product decision.

## Modifying: loading packs (`Loader.Install`) and the `MitigationPack` format
- **`scripts/release`** (`packs.go`, the command `release packs`): signs the pack folder with `Statement`, reads it back with `ReadPackDir` and checks each pack with `CheckPack` (the box's own parser) before signing; changing a pack field or rule = changing both the tool and the loader. Packs ship with the signed `core` image: changing the folder `/opt/vedette/content/mitigation` or the layout of `ReadPackDir` must change `deploy/containers/core/Containerfile` and the `load-packs` job too.

## Modifying: calling `AI.Run(AIRequest)` (the skills `explain`, `mitigation-config`)
- An `*apierr.Error` from `AI.Run` is returned unchanged by the handler: `cmd/vedette` `aiMitigation.Run` does not wrap it again; change that and the finding page shows the wrong reason again.
- `AIRequest.FixedIn` and the `aiFindingData` data (the device, ports, firewalls in inventory through `inventory.DevicesOfKind`/`Device`) are what the AI knows; drop one and the answer asks again for what the page already has. `AIOutput.Configs`/`Shortened` → `findings.AIResult.configs/shortened` (contract.ts `AiResult`) → `AiOutput` in `Recommendation.tsx`.
- **ai** (group B): renaming the skill/output schema makes `ai_available` wrong and the result loses its label. The door is `cmd/vedette/ai.go` (`aiMitigation`, `aiFindingData`, `aiVulnPorts`, `aiSafeApply`) and `cmd/vedette/aipath.go` (`aiPickWalls`, `aiNetworkBlock`, the path of a device through firewalls); changing `inventory.Device`/`DevicesOfKind` means looking at these functions again.

## Modifying: `POST /findings/{id}/applied`
- The SPA ("Applied" section). Changing the item set (`ApplyItem`) = changing the packs and `mit_applied` (the `item` column has a CHECK).
- **cmd/vedette** `mitigationApplied` (wiring.go) reads `mit_applied` so `findings` keeps a finding that already has an applied item when merging devices (`ServiceConfig.Applied`): renaming the table or the `finding_id` column must change this function too.

## Disabling this module
- The "What to do" panel on the finding page goes away (`RequireModule module="mitigation"`); the "Ask my AI" button for findings disappears. `core/server/modules.go` (`/findings/{id}/applied`, `/ai`) and `web/src/lib/apiModules.ts` tie these two routes to the module; `modules/core/handlers_setup.go` (`bundleSMB`) and `web/src/features/core/bundles.ts` put it in the default bundle.
- `findings`, `notify`, `scan`, `response`, `reports` are not affected (they do not depend on `mitigation`).
- Loaded packs, the "Applied" section and AI results are kept in `mit_*`.

## Modifying: `FindingFolded(ctx, tx, lifecycle.FindingFold)` (INV-9)
- **findings** calls it through `core/lifecycle` (registered in `cmd/vedette/devicelifecycle.go`) inside the inventory's merge transaction, right before it deletes the folded finding: a new table keyed by finding id must be moved here too, or the FK cascade drops its rows on a merge. Write only through `tx`; an error rolls the merge back.

## Modifying: `AIRequest` (finding id, skill, pack flag, user), `AIOutput.Answers`
- `AIRequest` no longer carries the finding row or `FixedIn`: the AI door (`cmd/vedette` `aiMitigation`) reads the view of the finding and the brief of its CVE by id, the same sources every other reader uses, so the fixed release the AI names is the stored fix the page shows. `sanitizeAI` keeps at most four answers (text 1200 characters, eight http(s) links each) in `findings.AIResult.Answers`.
- Left as it was: `Provider.Guidance` still reads `findings.Row` (the finding page's "What to do" text); it moves with the finding page.
