# Lab 2026-11-14: the line shapes of the pinned nuclei (kf-scan item 4, N45-1)

Why: on the N100 (n45) a deep run of 10443 was thrown away whole for one line `nucleiout: line 31: a target the job did not name`,
so 11080 and 11443 were never tested. `nucleiout.Read` now skips and counts such a line; this run records every line shape the
pinned nuclei prints, so the parser maps the job's own targets in every spelling and skips only real foreign ones.

Setup (dev box, no external network for the run):
- nuclei: the v3.11.1 release zip from GitHub, `ea63d4ae…5ab6` (zip) and `c4958814…0251` (binary), the same hashes as
  `docs/lab/2026-11-12-podman-nuclei.md` §3 (the image builds the same tag from source with patched modules only).
- `podman run --rm --network none debian:trixie-slim`: inside its own loopback a small Go program served HTTPS on 127.0.0.1:10443
  (`/` redirects to `http://127.0.0.1:11080/landing`, another port; `/far` to `http://127.0.0.2:11080/landing`, another host),
  HTTPS on 127.0.0.1:443, plain HTTP on 127.0.0.1:11080 (never named in the job) and an SSH-like banner on 127.0.0.1:10022.
- Argv: the full shape of `nucleiargv` (`-jsonl -silent -nc -duc -ni -ms -dr -nh -etags dos,intrusive,fuzz,brute-force,default-login,authenticated
  -pt http,tcp,ssl -elog /dev/stderr -c 10 -bs 1 -timeout 10 -retries 1 -or -ot -rl 20 -mhe 3`), `-u https://127.0.0.1:10443
  -u 127.0.0.1:10022 -u https://127.0.0.1:443`, lab templates: http with `redirects: true`, http with `host-redirects: true`, http
  with two named matchers, http with no match, http whose path names another port (`http://{{Hostname}}:11080/`), a
  self-contained http template to 11080, ssl (`{{Host}}:{{Port}}`), tcp banner (`{{Hostname}}`).

Results (`modules/scan/nucleiout/testdata/shapes.jsonl`, `otherport.jsonl`; 127.0.0.1 rewritten to 192.168.10.21, template paths
to the pack's directory):
- Every line is `"host":"<address>","port":"<port>"` (http, ssl and tcp alike); `url` is `https://a:p` for http on a TLS input,
  `a:p` for tcp and for http on an input without a scheme, absent for ssl.
- `-dr` wins over `redirects: true` and `host-redirects: true`: no redirect was followed, no line named 11080 or 127.0.0.2.
- `-ms` failure lines are printed with `-or -ot` (one per template and target; `lab-miss`), answering part of
  `.ai/deferred/fix-exposure-n44-walk.md` line 1.
- A template with two named matchers prints one line per matcher (`matcher-name`).
- A path naming another port gives an error line about the job's target (`failed to parse url http://a:10443:11080/landing`).
- The self-contained template printed nothing at all.
- So no line shape of 3.11.1 seen here names an address outside the job. The N100 line 31 is not reproduced; the core log
  (`sensor_active_nuclei_lines_skipped`) and the probe row now carry the first skipped line's template, host and port, so the
  next N100 deep run says which template it was.
