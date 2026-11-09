-- +goose Up
-- Notify tables (docs/DATA_MODEL.md 4.4). Forward-only: no Down section. Only notify.Service writes them.
-- Differences from DATA_MODEL 4.4 are listed in modules/notify/IMPACT.md (WP-22).

-- One row per channel type, created on the first save and kept after DELETE (configured = 0) so the
-- UI always has six channels. The secrets live in core_secret; last4 is copied here when sealing
-- because notify may not read core_secret (core owns it).
CREATE TABLE notify_channel (
    type                TEXT    NOT NULL PRIMARY KEY CHECK (type IN ('telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook')),
    configured          BOOLEAN NOT NULL DEFAULT 0 CHECK (configured IN (0, 1)),
    enabled             BOOLEAN NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    fields              TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(fields)),
    secret_id           TEXT    REFERENCES core_secret (id),
    secret_last4        TEXT    CHECK (secret_last4 IS NULL OR length(secret_last4) = 4),
    app_token_secret_id TEXT    REFERENCES core_secret (id),
    app_token_last4     TEXT    CHECK (app_token_last4 IS NULL OR length(app_token_last4) = 4),
    bot_token_secret_id TEXT    REFERENCES core_secret (id),
    bot_token_last4     TEXT    CHECK (bot_token_last4 IS NULL OR length(bot_token_last4) = 4),
    min_severity        TEXT    NOT NULL DEFAULT 'medium' CHECK (min_severity IN ('critical', 'high', 'medium', 'low')),
    approvals           BOOLEAN NOT NULL DEFAULT 0 CHECK (approvals IN (0, 1)),
    last_test           TEXT    CHECK (last_test IS NULL OR json_valid(last_test)),
    rev                 INTEGER NOT NULL DEFAULT 1,  -- bumped on every change that affects sending: invalidates the cached sender
    updated_at          TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- user_id is a soft reference to core_user (notify may not read core tables; INV-7 is checked through the Users interface).
CREATE TABLE notify_approver (
    channel_type TEXT NOT NULL REFERENCES notify_channel (type) ON DELETE CASCADE,
    user_id      TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 96),
    address      TEXT NOT NULL CHECK (length(address) BETWEEN 1 AND 254),
    PRIMARY KEY (channel_type, user_id)
);

-- One row per rule object: key quiet | grouping (DATA_MODEL 5.5). A missing row means the default.
CREATE TABLE notify_setting (
    key        TEXT NOT NULL PRIMARY KEY CHECK (key IN ('quiet', 'grouping')),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) > 0)
);

CREATE TABLE notify_incident (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    kind       TEXT    NOT NULL CHECK (kind IN ('trap', 'bad_address', 'log_anomaly', 'unknown_device')),
    title      TEXT    NOT NULL CHECK (length(title) BETWEEN 1 AND 400),
    link       TEXT    NOT NULL CHECK (length(link) BETWEEN 1 AND 400),
    severity   TEXT    NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    what       TEXT    NOT NULL CHECK (length(what) <= 4000),
    action     TEXT    NOT NULL CHECK (length(action) <= 4000),
    first_seen TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen  TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    count      INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
    status     TEXT    NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'resolved')),
    handled_by TEXT,
    handled_at TEXT    CHECK (handled_at IS NULL OR handled_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    note       TEXT    CHECK (note IS NULL OR length(note) <= 2000),
    dedupe_key TEXT    NOT NULL CHECK (length(dedupe_key) = 64)
);
CREATE INDEX notify_incident_status_ix ON notify_incident (status, last_seen DESC);
-- One open incident per key (INV-10): a repeat bumps count; once resolved, the next one is a new incident.
CREATE UNIQUE INDEX notify_incident_open_uq ON notify_incident (dedupe_key) WHERE status <> 'resolved';

CREATE TABLE notify_incident_device (
    incident_id TEXT NOT NULL REFERENCES notify_incident (id) ON DELETE CASCADE,
    asset_id    TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
    PRIMARY KEY (incident_id, asset_id)
);

-- A vulnerability notice (D-52): created when it is sendable; the finding ids it covers are in notify_notice_finding.
CREATE TABLE notify_notice (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    product    TEXT NOT NULL CHECK (length(product) <= 300),
    cves       TEXT NOT NULL CHECK (json_valid(cves))
);
CREATE INDEX notify_notice_created_ix ON notify_notice (created_at);

CREATE TABLE notify_notice_finding (
    notice_id  TEXT NOT NULL REFERENCES notify_notice (id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL CHECK (length(finding_id) BETWEEN 1 AND 96),
    PRIMARY KEY (notice_id, finding_id)
);
CREATE INDEX notify_notice_finding_ix ON notify_notice_finding (finding_id);

-- One row per delivery attempt (SendRecord, INV-6). message is the channel.Message as sent, kept so a
-- resend can send it again; it never holds an approval token (the link is replaced by the in-app page).
CREATE TABLE notify_send (
    id      TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    kind    TEXT    NOT NULL CHECK (kind IN ('incident', 'vuln', 'approval')),
    ref_id  TEXT    NOT NULL CHECK (length(ref_id) BETWEEN 1 AND 128),
    channel TEXT    NOT NULL CHECK (channel IN ('telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook')),
    "to"    TEXT    NOT NULL CHECK (length("to") <= 600),
    at      TEXT    NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    ok      BOOLEAN NOT NULL CHECK (ok IN (0, 1)),
    error   TEXT    CHECK (error IS NULL OR length(error) <= 1000),
    what    TEXT    NOT NULL CHECK (length(what) <= 400),
    link    TEXT    NOT NULL CHECK (length(link) <= 400),
    message TEXT    NOT NULL CHECK (json_valid(message) AND length(message) <= 16384),
    -- Who the message went to when it went to one person (an approver's address): a resend goes to the same person, not to the alert list.
    recipient TEXT  CHECK (recipient IS NULL OR length(recipient) BETWEEN 1 AND 254)
);
CREATE INDEX notify_send_at_ix ON notify_send (at DESC);
CREATE INDEX notify_send_ref_ix ON notify_send (kind, ref_id);

-- A grouped message covers several notices: which ones went out in which send.
CREATE TABLE notify_send_notice (
    send_id   TEXT NOT NULL REFERENCES notify_send (id) ON DELETE CASCADE,
    notice_id TEXT NOT NULL REFERENCES notify_notice (id) ON DELETE CASCADE,
    PRIMARY KEY (send_id, notice_id)
);
CREATE INDEX notify_send_notice_ix ON notify_send_notice (notice_id);

-- Exploited vulnerabilities (CISA KEV) the box has heard of, and whether a finding matched a device of the
-- customer: the ones with matched = 0 are what HistoryView.suppressed counts (INV-2). One row per CVE, so the
-- same CVE reported twice is one. Filled from feeds.vuln.new_kev and from notices; notify reads no other module's tables.
CREATE TABLE notify_kev (
    cve     TEXT    NOT NULL PRIMARY KEY CHECK (length(cve) BETWEEN 1 AND 128),
    seen_at TEXT    NOT NULL CHECK (seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    matched INTEGER NOT NULL DEFAULT 0 CHECK (matched IN (0, 1))
);
CREATE INDEX notify_kev_seen_ix ON notify_kev (seen_at);

-- The delivery queue: what is waiting to go out on which channel. pending -> claimed (taken by a run, in one
-- transaction, so two runs never take the same row) -> sending (marked just before the network call) -> row
-- deleted together with the notify_send row. A run that is interrupted puts claimed rows back to pending (never
-- attempted: sent later) and records sending rows as "may or may not have been sent" (not sent again).
CREATE TABLE notify_pending (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    channel    TEXT NOT NULL CHECK (channel IN ('telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook')),
    notice_id  TEXT NOT NULL CHECK (length(notice_id) BETWEEN 1 AND 128),
    notice     TEXT NOT NULL CHECK (json_valid(notice) AND length(notice) <= 65536),
    reason     TEXT NOT NULL CHECK (reason IN ('now', 'group', 'quiet')),
    due_at     TEXT NOT NULL CHECK (due_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    state      TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'claimed', 'sending')),
    claimed_at TEXT CHECK (claimed_at IS NULL OR claimed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
CREATE UNIQUE INDEX notify_pending_uq ON notify_pending (channel, notice_id);
CREATE INDEX notify_pending_state_ix ON notify_pending (state, channel);
