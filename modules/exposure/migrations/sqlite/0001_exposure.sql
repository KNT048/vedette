-- +goose Up
-- The whole schema of the exposure module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

-- A target: a domain or a public IPv4 address, as a node of a tree. A name under a domain target sits under it (parent_id) and keeps
-- its own options; an ancestor's ownership proof covers its descendants, so method stays NULL on a covered node. The schedule of a node
-- is the shared schedule exposure.target:<id>; its newest scan is its newest run.
CREATE TABLE exp_target (
    id           TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    parent_id    TEXT    REFERENCES exp_target (id) ON DELETE SET NULL,
    kind         TEXT    NOT NULL CHECK (kind IN ('domain', 'ip')),
    value        TEXT    NOT NULL UNIQUE CHECK (length(value) BETWEEN 1 AND 253),
    -- person: typed in; box: a public IP the box found as its own egress address; discovered: a name found under a domain target
    origin       TEXT    NOT NULL CHECK (origin IN ('person', 'box', 'discovered')),
    -- domains: self scans only this name, all this name and every name found under it, selected this name and the chosen names
    scope_mode   TEXT    CHECK ((kind = 'ip' AND scope_mode IS NULL) OR (kind = 'domain' AND scope_mode IS NOT NULL AND scope_mode IN ('self', 'all', 'selected'))),
    enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    method       TEXT    CHECK (method IS NULL OR (kind = 'domain' AND method = 'dns_txt') OR (kind = 'ip' AND method = 'box_egress')),
    -- domain: the value in the TXT record vedette-verify=<token> (public in DNS); IP: ''
    token        TEXT    NOT NULL CHECK ((kind = 'domain' AND length(token) = 16) OR (kind = 'ip' AND token = '')),
    verified_at  TEXT    CHECK (verified_at IS NULL OR verified_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    -- {at, ok, message}
    last_check   TEXT    CHECK (last_check IS NULL OR (json_valid(last_check) AND json_type(last_check) = 'object')),
    -- an IP typed in by a person: the token its proof file carries, and how it was proved
    ip_token     TEXT    CHECK (ip_token IS NULL OR (kind = 'ip' AND origin = 'person' AND length(ip_token) = 16)),
    proof_method TEXT    CHECK (proof_method IS NULL OR (kind = 'ip' AND origin = 'person' AND proof_method IN ('ip_file', 'ip_ptr'))),
    created_at   TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK (parent_id IS NULL OR (kind = 'domain' AND parent_id <> id))
);
CREATE INDEX exp_target_parent_idx ON exp_target (parent_id);

-- What a person accepted for a target: the scan confirmation of an administrator's first Scan now (commitment) and the testing terms
-- (terms), each with the exact text, who and how. One row of each kind at most; accepting again replaces it.
CREATE TABLE exp_consent (
    target_id  TEXT    NOT NULL REFERENCES exp_target (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('commitment', 'terms')),
    version    TEXT    NOT NULL CHECK (length(version) BETWEEN 1 AND 40),
    text       TEXT    NOT NULL CHECK (length(text) BETWEEN 1 AND 10000),
    by_name    TEXT    NOT NULL CHECK (length(by_name) BETWEEN 1 AND 320),
    user_id    TEXT    CHECK (user_id IS NULL OR length(user_id) BETWEEN 1 AND 96),
    method     TEXT    CHECK (method IS NULL OR method IN ('app', 'email', 'sso')),
    disruptive INTEGER NOT NULL DEFAULT 0 CHECK (disruptive IN (0, 1) AND (disruptive = 0 OR kind = 'terms')),
    at         TEXT    NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (target_id, kind)
) WITHOUT ROWID;

-- A name found under a domain target, with where it was found and when it was first and last seen. A name that is also its own
-- target points at it (child_target_id): that target scans it, and this one skips it.
CREATE TABLE exp_host (
    id              TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    target_id       TEXT    NOT NULL REFERENCES exp_target (id) ON DELETE CASCADE,
    name            TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
    -- ct | dns | mx | ns | wordlist | person (exposure.HostSource)
    source          TEXT    NOT NULL CHECK (length(source) BETWEEN 1 AND 40 AND source NOT GLOB '*[^a-z0-9_]*'),
    selected        INTEGER NOT NULL DEFAULT 0 CHECK (selected IN (0, 1)),
    child_target_id TEXT    REFERENCES exp_target (id) ON DELETE SET NULL,
    cname           TEXT    CHECK (cname IS NULL OR length(cname) BETWEEN 1 AND 253),
    first_seen      TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen       TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    UNIQUE (target_id, name),
    CHECK (first_seen <= last_seen)
);
CREATE INDEX exp_host_child_idx ON exp_host (child_target_id);

-- An address of a target: of a name under a domain (host_id), or the IP target itself (host_id NULL).
CREATE TABLE exp_address (
    id         INTEGER NOT NULL PRIMARY KEY,
    host_id    TEXT    REFERENCES exp_host (id) ON DELETE CASCADE,
    target_id  TEXT    NOT NULL REFERENCES exp_target (id) ON DELETE CASCADE,
    ip         TEXT    NOT NULL CHECK (length(ip) BETWEEN 2 AND 45),
    family     TEXT    NOT NULL CHECK (family IN ('ipv4', 'ipv6')),
    -- box: this box's own current IP; public: any other public address; private: never dialed
    class      TEXT    NOT NULL CHECK (class IN ('box', 'public', 'private')),
    first_seen TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen  TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK (first_seen <= last_seen)
);
CREATE UNIQUE INDEX exp_address_key ON exp_address (target_id, ifnull(host_id, ''), ip);
CREATE INDEX exp_address_host_idx ON exp_address (host_id);

-- An open port on a public address of a target, as the scans saw it: open while the scans that check its address find it, closed
-- once one that checked the address no longer did. first_seen stays from the first scan that found it.
CREATE TABLE exp_service (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    target_id   TEXT    NOT NULL REFERENCES exp_target (id) ON DELETE CASCADE,
    ip          TEXT    NOT NULL CHECK (length(ip) BETWEEN 2 AND 45),
    port        INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    proto       TEXT    NOT NULL CHECK (proto IN ('tcp', 'udp')),
    name        TEXT    NOT NULL DEFAULT '' CHECK (length(name) <= 100),
    product     TEXT    NOT NULL DEFAULT '' CHECK (length(product) <= 500),
    version     TEXT    NOT NULL DEFAULT '' CHECK (length(version) <= 500),
    cpe         TEXT    NOT NULL DEFAULT '' CHECK (length(cpe) <= 500),
    title       TEXT    NOT NULL DEFAULT '' CHECK (length(title) <= 500),
    -- {names, issuer, expires_at}: the TLS certificate the service showed
    cert        TEXT    CHECK (cert IS NULL OR (json_valid(cert) AND json_type(cert) = 'object')),
    is_web      INTEGER NOT NULL DEFAULT 0 CHECK (is_web IN (0, 1)),
    -- probed: a probe's answer named it; table: only the usual service of the port number; none: not identified
    ident       TEXT    NOT NULL CHECK (ident IN ('probed', 'table', 'none')),
    state       TEXT    NOT NULL CHECK (state IN ('open', 'closed')),
    first_seen  TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen   TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_run_id TEXT    NOT NULL CHECK (length(last_run_id) BETWEEN 1 AND 96), -- the run that last saw it; runs are pruned, so no key
    UNIQUE (target_id, ip, port, proto),
    CHECK (first_seen <= last_seen)
);
CREATE INDEX exp_service_state_idx ON exp_service (target_id, state);

-- Anything a scan reports as wrong, from any engine: open while scans report it, gone once the engine ran again and no longer did,
-- handled once a person decided (the findings vocabulary). One row per (target, engine, key, service).
CREATE TABLE exp_issue (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    target_id      TEXT    NOT NULL REFERENCES exp_target (id) ON DELETE CASCADE,
    service_id     TEXT    REFERENCES exp_service (id) ON DELETE SET NULL,
    -- surface | nuclei | zap | openvas | match (exposure.IssueEngine)
    engine         TEXT    NOT NULL CHECK (length(engine) BETWEEN 1 AND 40 AND engine NOT GLOB '*[^a-z0-9_]*'),
    key            TEXT    NOT NULL CHECK (length(key) BETWEEN 1 AND 600),
    title          TEXT    NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    severity       TEXT    NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cves           TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(cves) AND json_type(cves) = 'array'),
    -- {description, solution, evidence}: for display only
    detail         TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail) AND json_type(detail) = 'object'),
    state          TEXT    NOT NULL CHECK (state IN ('open', 'gone', 'handled')),
    -- patched | mitigated | accepted | not_relevant | false_positive (the findings vocabulary)
    resolution     TEXT    CHECK (resolution IS NULL OR (length(resolution) BETWEEN 1 AND 40 AND resolution NOT GLOB '*[^a-z0-9_]*')),
    resolved_by    TEXT    CHECK (resolved_by IS NULL OR length(resolved_by) BETWEEN 1 AND 320),
    resolved_at    TEXT    CHECK (resolved_at IS NULL OR resolved_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    note           TEXT    CHECK (note IS NULL OR length(note) BETWEEN 1 AND 500),
    accepted_until TEXT    CHECK (accepted_until IS NULL OR accepted_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    first_seen     TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen      TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_run_id    TEXT    NOT NULL CHECK (length(last_run_id) BETWEEN 1 AND 96),
    CHECK ((state = 'handled') = (resolution IS NOT NULL)),
    CHECK ((resolution IS NULL) = (resolved_by IS NULL) AND (resolution IS NULL) = (resolved_at IS NULL)),
    CHECK (accepted_until IS NULL OR resolution = 'accepted'),
    CHECK (first_seen <= last_seen)
);
CREATE UNIQUE INDEX exp_issue_key ON exp_issue (target_id, engine, key, ifnull(service_id, ''));
CREATE INDEX exp_issue_state_idx ON exp_issue (target_id, state);
CREATE INDEX exp_issue_service_idx ON exp_issue (service_id);

-- The facts of one scan of a target that are not rows: its mode and its summary ({counts, checks, not_checked}), shown on the run.
-- The run itself (state, steps, log) is the shared run.
CREATE TABLE exp_scan (
    run_id    TEXT NOT NULL PRIMARY KEY REFERENCES core_run (id) ON DELETE CASCADE,
    target_id TEXT NOT NULL REFERENCES exp_target (id) ON DELETE CASCADE,
    mode      TEXT NOT NULL CHECK (mode IN ('surface', 'deep')),
    summary   TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(summary) AND json_type(summary) = 'object')
) WITHOUT ROWID;
CREATE INDEX exp_scan_target_idx ON exp_scan (target_id);

-- The attempts people made to verify something, for the limit of 10 per hour (INV-5). Kept 24 hours.
CREATE TABLE exp_attempt (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    ts TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE TABLE exp_setting (
    id               INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    last_run_at      TEXT CHECK (last_run_at IS NULL OR last_run_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_run_ok      INTEGER CHECK (last_run_ok IS NULL OR last_run_ok IN (0, 1)),
    last_run_message TEXT CHECK (last_run_message IS NULL OR length(last_run_message) <= 1000),
    last_deep_at     TEXT CHECK (last_deep_at IS NULL OR last_deep_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_full_ok_at  TEXT CHECK (last_full_ok_at IS NULL OR last_full_ok_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), greenbone INTEGER NOT NULL DEFAULT 0 CHECK (greenbone IN (0, 1)), greenbone_by TEXT, greenbone_at TEXT, greenbone_sync_at TEXT, greenbone_sync_ok INTEGER CHECK (greenbone_sync_ok IN (0, 1)), greenbone_sync_note TEXT,
    CHECK ((last_run_at IS NULL) = (last_run_ok IS NULL) AND (last_run_at IS NULL) = (last_run_message IS NULL))
);

-- The Ignored list (INV-14): public IPs a person removed and chose not to add again, for example the address of a
-- security gateway, a VPN exit or a mobile backup line that the box sometimes uses but that is not the company's.
-- The list only blocks: detection never adds these addresses and nothing scans them. Restoring one deletes its row, which
-- lets detection add the address again; it never creates or approves a target. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE exp_ignored (
    value      TEXT NOT NULL PRIMARY KEY CHECK (length(value) BETWEEN 7 AND 15 AND value GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND value NOT GLOB '*[^0-9.]*'),
    ignored_by TEXT NOT NULL CHECK (length(ignored_by) BETWEEN 1 AND 320),
    ignored_at TEXT NOT NULL CHECK (ignored_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- What the Internet sees (INV-21): the last answer of Shodan InternetDB about one of the box's own public IPs, asked only
-- when an administrator clicks. One row per target, replaced by the next check, gone with its target; the audit log keeps every
-- request that was sent. answer is {ports, hostnames, cpes, tags, vulns}, already limited and checked when it was read (INV-10):
-- it is Shodan's claim, never a finding of Vedette. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE exp_outside (
    target_id  TEXT NOT NULL PRIMARY KEY REFERENCES exp_target (id) ON DELETE CASCADE,
    ip         TEXT NOT NULL CHECK (length(ip) BETWEEN 7 AND 15 AND ip NOT GLOB '*[^0-9.]*'),
    checked_at TEXT NOT NULL CHECK (checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    checked_by TEXT NOT NULL CHECK (length(checked_by) BETWEEN 1 AND 320),
    found      INTEGER NOT NULL CHECK (found IN (0, 1)),
    answer     TEXT NOT NULL CHECK (json_valid(answer) AND json_type(answer) = 'object')
);

CREATE INDEX exp_attempt_ts_idx ON exp_attempt (ts);

INSERT INTO exp_setting (id) VALUES (1);
