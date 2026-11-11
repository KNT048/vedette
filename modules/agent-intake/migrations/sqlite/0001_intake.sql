-- +goose Up
-- agent-intake (S-INV-4, WP-26 slice 2, D-169). Only package modules/agent-intake writes these tables. Devices and software go to the
-- inventory through core/observe, never into inv_*. Forward-only (DATA_MODEL 6): no Down section.

-- An enrolment token (D-169 (2)): the secret is shown once; only its SHA-256 and the last four characters are kept. expires_at NULL =
-- never; an expired token cannot enrol new nodes, the nodes it already has keep reporting. Revoke = DELETE the row (the nodes go with
-- it by cascade, so their next call gets node_invalid). last_received is when a node of this token last delivered a result log.
CREATE TABLE intake_agent_tokens (
    id            TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    kind          TEXT NOT NULL DEFAULT 'osquery' CHECK (kind IN ('osquery')),
    token_hash    TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    last4         TEXT NOT NULL CHECK (length(last4) = 4),
    created_at    TEXT NOT NULL,
    expires_at    TEXT,
    last_received TEXT
);

-- An enrolled osquery node: node_key_hash is the SHA-256 of the 256-bit key osquery got at enrol (never the key). (token, host_identifier)
-- is unique: enrolling again replaces the older row. bound_ip/bound_mac are the binding of D-169 (5): the TCP peer address that was among
-- the IPv4 the node declared in its interfaces result, and the MAC of that same card; both NULL = unmatched (nothing is written to the
-- inventory for this node). A node silent for 90 days is deleted by the node-prune job.
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
    bound_mac       TEXT,
    UNIQUE (token_id, host_identifier)
);

CREATE INDEX intake_osquery_nodes_seen_idx ON intake_osquery_nodes (last_seen);
