-- +goose Up
-- agent-intake, the Wazuh pull (S-INV-4, WP-26 slice 4, D-169 (12), (13), D-305..D-309). Only package modules/agent-intake writes it.
-- Forward-only (DATA_MODEL 6): no Down section.

-- The one Wazuh connection (id = 1). The password of the read-only API user is in core_secret (purpose intake_wazuh.password, opened
-- only by this module); password_last4 is what the API shows ("" for a password shorter than 8 characters, core/secrets keeps none).
-- tls_pin is the trust decision of the last Save: 'system' (a public authority vouched for the certificate, and must keep doing so) or
-- the hex SHA-256 of the leaf's public key (trust on first use). generation grows at every Save, so a pull that started before a Save
-- does not write its result over the new connection. next_pull is when the pull job may run next (Save sets it to now).
-- agents and packages are the counts of the last pull that finished; error is its plain-words reason when status = 'error'. A pass that
-- does not fit in one pull's 10 minutes goes on at the next tick after the agent resume_after, adding to pass_packages (D-306).
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
