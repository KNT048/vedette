# Deferred — feat/tune-5b-windows-ubr-match (D-546, 2026-11-14)

- [ ] **N100 / lab check** (agents do not SSH or deploy; owner: Mac supervisor as tester after Trưởng deploys): a Windows lab PC with
  osquery 5.12.1 enrolled to the N100 shows a software row "Windows 11 <release>" with version 10.0.<build>.<UBR> (= `winver`) within
  minutes of enrolment; an exploited CVE whose fix is newer than the PC's UBR is a version finding (high) with "What to do" naming the
  fixed build; after installing the monthly update, within about two hours, those findings close "Not affected". Also with a Wazuh
  Windows agent (row target x64 from `os.arch`). Closes `.ai/deferred/tune-5.md` item 1 once seen (that file is TUNE-5's; its owner
  marks it).
- [ ] **Windows entries not read by revision** (owner: findings; decide when a customer meets one): CISA "Microsoft | Multiple
  Products" entries and entries whose ranges come from CVE.org (D-556) still go through `decide`, so a Windows release row with an
  unknown target gets "not checked" there instead of a version answer. Rare for Windows; measure on the N100 feed first.
- [ ] **Unverified NVD names** (owner: findings): `windows_10_1511` and `windows_10_1703` in `core/winrel` were not confirmed against
  NVD's CPE dictionary (rate limit, 2026-11-14). Only those out-of-service releases are affected; check with the N100's feed data.
