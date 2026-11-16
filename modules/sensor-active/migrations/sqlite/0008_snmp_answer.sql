-- +goose Up
-- #829 C4 (J2): which device answered which SNMP credential, at which address, last. A device that answered a credential and has
-- since moved to an address outside that credential's scope is never sent the secret there (D-512); this row lets the credential
-- list, Read now and the Scanning card say so ("moved to …, outside the scope of this credential"). One row per credential and
-- device, replaced at each answer; the rows of a credential go with it. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE sa_snmp_answer (
    credential_id TEXT NOT NULL REFERENCES sa_snmp (id) ON DELETE CASCADE,
    asset_id      TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    ip            TEXT NOT NULL CHECK (length(ip) BETWEEN 7 AND 15),
    answered_at   TEXT NOT NULL CHECK (answered_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (credential_id, asset_id)
);
CREATE INDEX sa_snmp_answer_asset_ix ON sa_snmp_answer (asset_id);
