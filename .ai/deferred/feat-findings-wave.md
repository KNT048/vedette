# Deferred — feat/findings-wave (Mac agent, 2026-11-15)

- [ ] W-2 root cause on the N100: why the Windows VM .128's osquery `system_info` answer had not reached the inventory (vendor stayed the passive OUI "QEMU virtual NIC"). This PR names the device from the enrolment host name (agent-intake INV-21) either way; check on the next walk whether system_info lands (Devices → .128 → vendor "QEMU", model "Standard PC …") and, if not, read the box log for "agent-intake" lines of that node. No box access in this PR.
