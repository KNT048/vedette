-- +goose Up
-- What product a software line nothing else identifies is, per cleaned publisher and name (IdentityKey), so one row serves every
-- device that has the same software. kind 'ai': the customer's AI's choice among the candidates the box generated from its own
-- catalogue (candidates: a short hash of each of the top 5 products offered, in rank order, so a new one in the top can ask again): a
-- product (vendor, product, record, kev, title; fit: exact, the program itself, or family, only a part of the product's family such as
-- its agent or client, which opens nothing), none or unsure, with the AI's reason; one per name. kind 'rejected': a person said the line is not that product; it wins
-- over the AI (the product is never offered for that name again) and stays. Only an AI's product opens findings, never closes one.
-- No device data. Forward-only: there is no Down section.
CREATE TABLE fnd_identity (
    publisher   TEXT    NOT NULL CHECK (length(publisher) <= 200),
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    kind        TEXT    NOT NULL CHECK (kind IN ('ai', 'rejected')),
    choice      TEXT    NOT NULL CHECK (choice IN ('product', 'none', 'unsure')),
    fit         TEXT    NOT NULL DEFAULT '' CHECK (fit IN ('', 'exact', 'family')),
    vendor      TEXT    NOT NULL DEFAULT '' CHECK (length(vendor) <= 200),
    product     TEXT    NOT NULL DEFAULT '' CHECK (length(product) <= 200),
    record      INTEGER NOT NULL DEFAULT 0 CHECK (record IN (0, 1)),
    kev         TEXT    NOT NULL DEFAULT '' CHECK (length(kev) <= 400),
    title       TEXT    NOT NULL DEFAULT '' CHECK (length(title) <= 200),
    reason      TEXT    NOT NULL DEFAULT '' CHECK (length(reason) <= 200),
    candidates  TEXT    NOT NULL DEFAULT '' CHECK (length(candidates) <= 64),
    model       TEXT    NOT NULL DEFAULT '' CHECK (length(model) <= 80),
    activity_id TEXT    CHECK (activity_id IS NULL OR length(activity_id) <= 96),
    by          TEXT    NOT NULL CHECK (length(by) BETWEEN 1 AND 320),
    at          TEXT    NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((choice = 'product') = (vendor <> '' AND product <> '')),
    CHECK (kind = 'ai' OR choice = 'product'),
    CHECK ((kind = 'ai' AND choice = 'product') = (fit <> ''))
);

CREATE UNIQUE INDEX fnd_identity_ai_uq ON fnd_identity (publisher, name) WHERE kind = 'ai';

CREATE UNIQUE INDEX fnd_identity_rejected_uq ON fnd_identity (publisher, name, vendor, product) WHERE kind = 'rejected';
