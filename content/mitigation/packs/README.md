# Confirmed mitigation packs (shipped in the core image)

Only packs a Vedette maintainer has confirmed (D-21) go here: one `<CVE>.json` per CVE, in the format of
`content/mitigation/testdata/` (status `confirmed`, `confirmed_by`, `confirmed_at`, `drafted_with`, `sources`).

`make release-packs PACKS_VERSION=2026.12.2.1` (maintainer machine, `MINISIGN_KEY` set) checks every pack with the box's own
parser, writes `VERSION`, `packs.list` (the signed statement) and `packs.minisig`, and verifies the result with the release
keys. Commit those three files with the packs, then build the core image: it copies this folder to
`/opt/vedette/content/mitigation/`, and the box loads the packs only when the signature holds (D-345..D-349).
Pack versions are dotted numbers and must grow; a box never installs an older or equal set.
