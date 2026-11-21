-- +goose Up
-- The whole schema of the agent-intake module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

CREATE TABLE intake_agent_tokens (
    id            TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    kind          TEXT NOT NULL DEFAULT 'osquery' CHECK (kind IN ('osquery')),
    token_hash    TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    last4         TEXT NOT NULL CHECK (length(last4) = 4),
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    last_received TEXT
, created_by TEXT CHECK (created_by IS NULL OR length(created_by) BETWEEN 1 AND 256), first_enrolled_at TEXT,
    -- the device a person made the token for (the device page's agent row: Create agent token, then Show setup); NULL for a token
    -- made for any machine. The device's own agent row shows it until a machine enrols with it.
    device_id     TEXT REFERENCES inv_asset (id) ON DELETE SET NULL);

CREATE INDEX intake_agent_tokens_device_idx ON intake_agent_tokens (device_id) WHERE device_id IS NOT NULL;

CREATE TABLE intake_osquery_nodes (
    id              TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    token_id        TEXT NOT NULL REFERENCES intake_agent_tokens (id) ON DELETE CASCADE,
    node_key_hash   TEXT NOT NULL UNIQUE CHECK (length(node_key_hash) = 64),
    host_identifier TEXT NOT NULL CHECK (length(host_identifier) BETWEEN 1 AND 1024),
    hostname        TEXT,
    platform        TEXT,
    osquery_version TEXT,
    enrolled_at     TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    last_result_at  TEXT,
    bound_ip        TEXT,
    bound_mac       TEXT, reported TEXT NOT NULL DEFAULT '' CHECK (length(reported) <= 64), approved_at TEXT, kernel TEXT NOT NULL DEFAULT '' CHECK (length(kernel) <= 100), win_name TEXT NOT NULL DEFAULT '' CHECK (length(win_name) <= 200), win_version TEXT NOT NULL DEFAULT '' CHECK (length(win_version) <= 40), win_target TEXT NOT NULL DEFAULT '' CHECK (win_target IN ('', 'x64', 'x86', 'arm64')), report_asked_at TEXT, software_taken_at TEXT, os_taken_at TEXT, last_call_at TEXT,
    -- The node's rhythm (nodestate.go NodeHealth): call_every_s is how often it was told to call (osquery: the config refresh the
    -- install scripts set; the package reporter: its hourly run), call_gap_s its own smoothed gap between config fetches (NULL until it has
    -- fetched its config twice), report_every_s the longest interval of the schedule the box last gave it without its speed-ups (it delivers results at least that often).
    call_every_s    INTEGER NOT NULL DEFAULT 300 CHECK (call_every_s BETWEEN 60 AND 86400),
    call_gap_s      INTEGER CHECK (call_gap_s IS NULL OR call_gap_s BETWEEN 1 AND 172800),
    report_every_s  INTEGER NOT NULL DEFAULT 3600 CHECK (report_every_s BETWEEN 60 AND 86400),
    UNIQUE (token_id, host_identifier)
);

-- The one Wazuh connection (id = 1). The password of the read-only API user is in core_secret (purpose intake_wazuh.password); password_last4 is what the API shows ("" for a password shorter than 8 characters, core/secrets keeps none).
-- tls_pin is the trust decision of the last Save: 'system' (a public authority vouched for the certificate, and must keep doing so) or
-- the hex SHA-256 of the leaf's public key (trust on first use). generation grows at every Save, so a pull that started before a Save
-- does not write its result over the new connection. next_pull is when the pull job may run next (Save sets it to now).
-- agents and packages are the counts of the last pull that finished; error is its plain-words reason when status = 'error'. A pass that
-- does not fit in one pull's 10 minutes goes on at the next tick after the agent resume_after, adding to pass_packages.
CREATE TABLE intake_wazuh (
    id                 INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    url                TEXT    NOT NULL CHECK (url GLOB 'https://*' AND length(url) <= 200),
    username           TEXT    NOT NULL CHECK (length(username) BETWEEN 1 AND 64),
    secret_id          TEXT    NOT NULL REFERENCES core_secret (id),
    password_last4     TEXT    NOT NULL CHECK (length(password_last4) IN (0, 4)),
    interval_minutes   INTEGER NOT NULL CHECK (interval_minutes IN (5, 15, 60, 360, 1440)),
    tls_pin            TEXT    NOT NULL CHECK (tls_pin = 'system' OR (length(tls_pin) = 64 AND tls_pin NOT GLOB '*[^0-9a-f]*')),
    tls_pin_first_seen TEXT    NOT NULL,
    generation         INTEGER NOT NULL DEFAULT 1,
    status             TEXT    NOT NULL DEFAULT 'never' CHECK (status IN ('never', 'connected', 'error')),
    last_sync          TEXT,
    next_pull          TEXT    NOT NULL,
    agents             INTEGER NOT NULL DEFAULT 0 CHECK (agents >= 0),
    packages           INTEGER NOT NULL DEFAULT 0 CHECK (packages >= 0),
    error              TEXT    CHECK (error IS NULL OR length(error) <= 500),
    resume_after       TEXT    CHECK (resume_after IS NULL OR (length(resume_after) BETWEEN 3 AND 10 AND resume_after NOT GLOB '*[^0-9]*')),
    pass_packages      INTEGER NOT NULL DEFAULT 0 CHECK (pass_packages >= 0),
    updated_at         TEXT    NOT NULL
);

-- One row (id = 1): when the node-prune job last ran. A node is pruned after 90 days of silence while the job runs; time the module was
-- off, or the box was down, is not silence. At the first run after a gap of more than 3 hours the job adds the gap to every node's
-- last_seen, so a restart or an upgrade no longer starts the count again and nodes of a box that is updated are still pruned.
CREATE TABLE intake_prune_clock (
    id       INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    last_run TEXT    NOT NULL
);

-- #849: the address and card of every Wazuh agent the pull delivered to the inventory, so the Devices list can tell a device Wazuh
-- reports from one osquery reports (both write source agent; osquery binds its node key, Wazuh cannot: its agent ids are per
-- manager). A row belongs to the connection generation that wrote it; readers take the saved connection's generation only, so a
-- deleted or replaced connection names no device. A completed pass deletes the agents it no longer read. seen_at is when Wazuh last
-- heard from the agent: the pull's time while Wazuh lists it active, its lastKeepAlive (never after the pull) while it lists it
-- disconnected. The device's agent state is judged by it.
CREATE TABLE intake_wazuh_agent (
    agent_id   TEXT    NOT NULL PRIMARY KEY CHECK (length(agent_id) BETWEEN 3 AND 10 AND agent_id NOT GLOB '*[^0-9]*'),
    generation INTEGER NOT NULL,
    ip         TEXT    NOT NULL CHECK (length(ip) BETWEEN 7 AND 15),
    mac        TEXT    NOT NULL DEFAULT '' CHECK (mac = '' OR length(mac) = 17),
    seen_at    TEXT    NOT NULL
);

CREATE INDEX intake_osquery_nodes_seen_idx ON intake_osquery_nodes (last_seen);
