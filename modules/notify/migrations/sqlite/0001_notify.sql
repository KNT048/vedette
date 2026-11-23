-- +goose Up
-- The whole schema of the notify module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

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
, url_secret_id TEXT REFERENCES core_secret (id), url_last4 TEXT CHECK (url_last4 IS NULL OR length(url_last4) = 4));

CREATE TABLE notify_approver (
    channel_type TEXT NOT NULL REFERENCES notify_channel (type) ON DELETE CASCADE,
    user_id      TEXT NOT NULL CHECK (length(user_id) BETWEEN 1 AND 96),
    address      TEXT NOT NULL CHECK (length(address) BETWEEN 1 AND 254), name TEXT NOT NULL DEFAULT '',
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
    kind       TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 40 AND kind NOT GLOB '*[^a-z0-9_]*'),
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
, attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt IN (0, 1)), unsent TEXT CHECK (unsent IS NULL OR length(unsent) BETWEEN 1 AND 40), unsent_floor TEXT CHECK (unsent_floor IS NULL OR unsent_floor IN ('critical', 'high', 'medium', 'low')), unsent_channel TEXT CHECK (unsent_channel IS NULL OR unsent_channel IN ('telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook')), resolved_reason TEXT CHECK (resolved_reason IS NULL OR length(resolved_reason) <= 500), active_at TEXT CHECK (active_at IS NULL OR active_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), first_run INTEGER NOT NULL DEFAULT 0 CHECK (first_run IN (0, 1)), summary_id TEXT CHECK (summary_id IS NULL OR length(summary_id) <= 64));

CREATE TABLE notify_incident_device (
    incident_id TEXT NOT NULL REFERENCES notify_incident (id) ON DELETE CASCADE,
    asset_id    TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
    PRIMARY KEY (incident_id, asset_id)
);

-- A vulnerability notice: created when it is sendable; the finding ids it covers are in notify_notice_finding. event is the finding event
-- it tells (created, urgency_changed, reopened, acceptance_expired, first_run: an open vocabulary); '' for a notice that tells none.
CREATE TABLE notify_notice (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    event      TEXT NOT NULL DEFAULT '' CHECK (length(event) <= 40 AND event NOT GLOB '*[^a-z0-9_]*'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    product    TEXT NOT NULL CHECK (length(product) <= 300),
    cves       TEXT NOT NULL CHECK (json_valid(cves))
);

CREATE TABLE notify_notice_finding (
    notice_id  TEXT NOT NULL REFERENCES notify_notice (id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL CHECK (length(finding_id) BETWEEN 1 AND 96),
    -- the urgency layer the finding was told at (1 most urgent .. 4); 0 when the notice did not tell an urgency. A finding is told again
    -- only at a more urgent layer than every one it was told at.
    layer      INTEGER NOT NULL DEFAULT 0 CHECK (layer BETWEEN 0 AND 5),
    PRIMARY KEY (notice_id, finding_id)
);

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
, delayed INTEGER NOT NULL DEFAULT 0 CHECK (delayed IN (0, 1)));

-- A grouped message covers several notices: which ones went out in which send.
CREATE TABLE notify_send_notice (
    send_id   TEXT NOT NULL REFERENCES notify_send (id) ON DELETE CASCADE,
    notice_id TEXT NOT NULL REFERENCES notify_notice (id) ON DELETE CASCADE,
    PRIMARY KEY (send_id, notice_id)
);

CREATE TABLE notify_pending (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    channel    TEXT NOT NULL CHECK (channel IN ('telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook')),
    notice_id  TEXT NOT NULL CHECK (length(notice_id) BETWEEN 1 AND 128),
    notice     TEXT NOT NULL CHECK (json_valid(notice) AND length(notice) <= 65536),
    reason     TEXT NOT NULL CHECK (reason IN ('now', 'group', 'quiet', 'settle')),
    due_at     TEXT NOT NULL CHECK (due_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    state      TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'claimed', 'sending')),
    claimed_at TEXT CHECK (claimed_at IS NULL OR claimed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
, attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100));

CREATE TABLE notify_tg_button (
    request_id TEXT NOT NULL PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 50),
    nonce_hash TEXT NOT NULL CHECK (length(nonce_hash) = 64),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
, message_id INTEGER CHECK (message_id IS NULL OR message_id BETWEEN 1 AND 9007199254740992), chat_id TEXT CHECK (chat_id IS NULL OR length(chat_id) BETWEEN 1 AND 21), state TEXT NOT NULL DEFAULT 'none' CHECK (state IN ('none', 'shown', 'remove', 'removed')), tries INTEGER NOT NULL DEFAULT 0 CHECK (tries BETWEEN 0 AND 5));

CREATE TABLE notify_slack_button (
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
    channel_id TEXT NOT NULL CHECK (length(channel_id) BETWEEN 9 AND 13),
    ts         TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]'),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), state TEXT NOT NULL DEFAULT 'shown' CHECK (state IN ('shown', 'remove', 'removed')), outcome TEXT CHECK (outcome IS NULL OR outcome IN ('approved', 'rejected', 'expired', 'cancelled', 'ended')), tries INTEGER NOT NULL DEFAULT 0 CHECK (tries BETWEEN 0 AND 5),
    PRIMARY KEY (request_id, channel_id, ts)
);

-- notify_slack_team: the workspace id learned with auth.test for the bot token of the Slack channel at revision rev. A press from another
-- workspace is ignored. One row; learned again whenever the channel changes (rev).
CREATE TABLE notify_slack_team (
    id      INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    rev     INTEGER NOT NULL,
    team_id TEXT    NOT NULL CHECK (length(team_id) BETWEEN 7 AND 21)
);

-- notify_slack_final: requests whose final decision arrived (response.decision.made, final=true). The Slack message of a request is
-- recorded after every message of the request went out, so the decision can arrive first (an approver on another channel pressed
-- while the rest were being sent); the message recorded then is marked for removal at once. Pruned a week after at.
CREATE TABLE notify_slack_final (
    request_id TEXT NOT NULL PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 128),
    outcome    TEXT NOT NULL CHECK (outcome IN ('approved', 'rejected', 'expired', 'cancelled', 'ended')),
    at         TEXT NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- When notify first ran on this box (the first discovery of devices is summarised for 36 hours from then) and when the
-- summary incident last told people. A box upgraded to this version takes the earliest notify record it has, so an old box never
-- opens a first-discovery window; a new box starts now.
CREATE TABLE notify_box (
    id                   INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    first_run_at         TEXT    NOT NULL CHECK (first_run_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    discovery_told_at    TEXT    CHECK (discovery_told_at IS NULL OR discovery_told_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    discovery_told_count INTEGER NOT NULL DEFAULT 0 CHECK (discovery_told_count >= 0)
);

CREATE INDEX notify_incident_status_ix ON notify_incident (status, last_seen DESC);

-- One open incident per key (INV-10): a repeat bumps count; once resolved, the next one is a new incident.
CREATE UNIQUE INDEX notify_incident_open_uq ON notify_incident (dedupe_key) WHERE status <> 'resolved';

CREATE INDEX notify_notice_created_ix ON notify_notice (created_at);

CREATE INDEX notify_notice_finding_ix ON notify_notice_finding (finding_id);

CREATE INDEX notify_send_at_ix ON notify_send (at DESC);

CREATE INDEX notify_send_ref_ix ON notify_send (kind, ref_id);

CREATE INDEX notify_send_notice_ix ON notify_send_notice (notice_id);

CREATE UNIQUE INDEX notify_pending_uq ON notify_pending (channel, notice_id);

CREATE INDEX notify_pending_state_ix ON notify_pending (state, channel);

CREATE INDEX notify_tg_button_expires_ix ON notify_tg_button (expires_at);

CREATE INDEX notify_tg_button_state_ix ON notify_tg_button (state, expires_at);

CREATE INDEX notify_slack_button_expires_ix ON notify_slack_button (expires_at);

CREATE INDEX notify_slack_button_state_ix ON notify_slack_button (state, expires_at);

CREATE INDEX notify_slack_final_at_ix ON notify_slack_final (at);

CREATE UNIQUE INDEX notify_approver_address_ux ON notify_approver (channel_type, address);

INSERT INTO notify_box (id, first_run_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
