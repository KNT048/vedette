# Deferred: feat/connections-gui (slice 13b-1)

- [ ] 13b-5: the mock pins in a simplified way (a TLS pin only for LAN-like hosts, a made-up SSH host key) and answers Test with a made-up success; the real box pins per D-94 and answers Test 501 until 13b-5. Align the mock messages and the pin rules when the transports land.
- [ ] `modules/ai` CONTRACT/MANIFEST still mention `ai_connectors` and the 5 `/ai/connections*` endpoints: handled by PR #84 (13b-0); check after it merges. Emily's ai contract loses the 5 endpoints.

# Deferred: feat/core-conn (slice 13b-4)

- [ ] Mock vs backend, left as is (the parity script records each as a `real` block or leaves it out): (1) the mock gives a new `mcp-http` connection three made-up tools (`list_resources`, `search_docs`, `run_action`); the backend gives none until the first Test finds them (13b-5), so the card is empty until then; make the mock do the same. (2) The mock accepts any 8-character "SSH key" and `Test` always succeeds; the backend parses the key (no passphrase, DSA and RSA under 2048 bits refused). (3) Schema-level checks of the generated server (an empty `username`, a user name that breaks the pattern, an unknown `kind`, a non-boolean `clear_pin`) answer `invalid` with `field` and the generic message of D-73; the mock gives its own message for the first two and `invalid_kind` for the third. The GUI never sends an empty user name (it checks first), so only the message differs.
- [ ] `POST /core/connections/{id}/test` is a 501 after `connection_off`; it writes no audit row yet (`connection.test` with the pin kind, 13b-5). Remove the `notYet` entry in `modules/core/contract_matrix_test.go` then.
