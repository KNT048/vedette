# F5 distro backports: follow-ups (session feat-distro-backports, 2026-11-14, D-516)

- [ ] The weekly report's grouped fix (`findings.FixedInForAll`, `GroupFix`) does not use the distribution's word yet: a packaged row still groups as kind `distro` without "Fixed in <distro version>". Needs a criterion on the D-490 story first.
- [ ] rpm distributions (RHEL, Rocky, Alma, Fedora, SUSE) have no backport data: their packaged rows stay on NVD's ranges. Candidate source: Red Hat's CSAF/VEX (one all-releases archive); needs a story and a PRIVACY row.
- [ ] A CVE CISA adds is decided by the distribution data only when the distribution file next changes (304 keeps the rows; usually within a day). If that lag shows on the N100, pull the distribution feeds after a CISA pull with new CVEs, without validators.
- [ ] A scan row (`-sV` banner) of the same product keeps a finding open even when the packaged agent row is proved patched (D-530 closes only when every software of the product proves it). Check on the N100 whether the Ubuntu dev box has such a row for OpenSSH.
