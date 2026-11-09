# Deferred: feat/connections-gui (slice 13b-1)

- [ ] Mock vs real Test: the mock invents the SSH host key and a LAN/public split by host name (LAN-like hosts get `tls_sha256`, others `tls_roots`), while the backend decides by the certificate chain; the failure codes and `tls_roots` are now in the mock and the parity script, but `pin_mismatch` and `unreachable` steps exist only in the mock (they are triggered by words in the target) and are tested for the backend in `core/conn/test_test.go`.
- [ ] `modules/ai` CONTRACT/MANIFEST still mention `ai_connectors` and the 5 `/ai/connections*` endpoints: handled by PR #84 (13b-0); check after it merges. Emily's ai contract loses the 5 endpoints.

# Deferred: feat/core-conn (slice 13b-4)

- [ ] Mock vs backend, left as is (the parity script records each as a `real` block or leaves it out): (1) the mock gives a new `mcp-http` connection three made-up tools (`list_resources`, `search_docs`, `run_action`); the backend gives none until the first Test finds them (done in 13b-5), so the card is empty until then; make the mock do the same. (2) The mock accepts any 8-character "SSH key" and `Test` always succeeds; the backend parses the key (no passphrase, DSA and RSA under 2048 bits refused). (3) Schema-level checks of the generated server (an empty `username`, a user name that breaks the pattern, an unknown `kind`, a non-boolean `clear_pin`) answer `invalid` with `field` and the generic message of D-73; the mock gives its own message for the first two and `invalid_kind` for the third. The GUI never sends an empty user name (it checks first), so only the message differs.
- [ ] **13b-6 must (review of 13b-4)**: request-time allow-list matching uses the same normalisation as `under()` and refuses `\`, `%2F`, `%5C`, `%2E`; the writer refuses an unknown connection id; the claim transaction re-runs `connectionGate`; `finishItem` handles a connection that has gone while the step ran.
- [ ] `deps.HostNet` (appliance management and IPv6 addresses for `BoxAddrs`) is nil: the host client has no `StateNet` yet (host-api `state/net`, host module slice 3-3). Wire it when that call exists; `boxSources` already caches it 30 s and is tested with a fake.
- [ ] `BoxAddrs` refuses the whole subnet of every interface of the container. If core ever runs with `--network=host`, the LAN is the container's subnet and every LAN device would be refused: change source (a) before that.
- [ ] The step-deadline path of `runItem` (`unknown: true` when the context ends) has no test of its own; the sweep path is tested (`TestChangesInForceCountsAnItemWhoseOutcomeIsUnknown`).

# Deferred: feat/conn-transport (slice 13b-5)

- [ ] The real limits (15 s per call, 20 s per SSH line, 60 s per session, 5 s connect) are asserted as constants, and a hung call is ended through a short context deadline; no test waits the real 15/20/60 s. Add a test with a clock seam when the writer (13b-6) needs per-line budgets.
- [ ] Two Tests of one connection at the same time are not serialised: the second saves nothing and answers `connection_changed` when the first pinned. Fine for an admin button; the writer (13b-6) serialises per connection.
- [ ] An HTTP read below 400 passes (a 3xx is "reachable"), 401/403 is "refused the sign-in", other 4xx/5xx is "answered HTTP n": a device whose address root answers 404 cannot pass Test; the administrator moves the address to a path that answers. Revisit if devices in the field answer 404 at their root.
- [ ] The SSH algorithm list is `ssh.SupportedAlgorithms()` (stricter than the library default, which D-94 names); an old switch that only speaks `ssh-rsa`/CBC/DH-group14-SHA1 fails Test with a `device_error` that says so. The opt-in per-connection legacy list stays in `.ai/deferred/feat-response-13b.md`.
- [ ] `SSH.Run` (the line-by-line session with prompt wait and error markers) is built and tested but nothing calls it until 13b-6; Test only opens the session and reads the prompt.
