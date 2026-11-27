-- +goose Up
-- The identity of the evidence a question about one CVE rests on, as the match pass computed it: sha256 hex of the CVE, the product,
-- the release line, the exact version the line runs and the CVE record's stamps (NVD's and the CVE record's change times, which move
-- when the record or its references change). '' when no check of the CVE's advisories can decide the question (no version, a platform,
-- edition or package release only the device can state, NVD not answered yet). Rewritten with the question at every match, so a new
-- version or a changed record gives a new key and an earlier check no longer applies. Validated in Go (64 hex or ''); no CHECK on an
-- added column, which would make the release unsafe to roll back. Forward-only: there is no Down section.
ALTER TABLE fnd_question ADD COLUMN check_key TEXT NOT NULL DEFAULT '';

CREATE INDEX fnd_question_check_key_ix ON fnd_question (check_key) WHERE check_key <> '';

-- One check of a possible CVE per evidence identity (fnd_question.check_key): whether <product> at <version> is affected by <cve>, read
-- from the CVE's reference pages the box fetched. decided_by says who decided: structured (the box's own data), advisory (the box read
-- the vendor's advisory and its ranges decide), ai (the AI read the pages: a proposal a person confirms or rejects; confidence says how
-- well the box could check the AI's quote). verdict unsure decides nothing (the CVE stays possible with the reason). detail holds the
-- machine-readable reason a CVE stays undecided and the evidence that blocked it, for an audit of the undecided cases. Shared by every
-- device with the same key; no device data. A key is checked once; a check that failed (no answer, budget, provider) stores nothing.
CREATE TABLE fnd_possible_check (
    check_key     TEXT    NOT NULL PRIMARY KEY CHECK (length(check_key) = 64 AND check_key NOT GLOB '*[^0-9a-f]*'),
    cve           TEXT    NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    product_key   TEXT    NOT NULL CHECK (length(product_key) BETWEEN 1 AND 300),
    line          TEXT    NOT NULL CHECK (length(line) BETWEEN 1 AND 200),
    version       TEXT    NOT NULL CHECK (length(version) BETWEEN 1 AND 200),
    evidence_hash TEXT    NOT NULL CHECK (length(evidence_hash) = 64),
    decided_by    TEXT    NOT NULL CHECK (decided_by IN ('structured', 'advisory', 'ai')),
    verdict       TEXT    NOT NULL CHECK (verdict IN ('affected', 'not_affected', 'unsure')),
    confidence    TEXT    CHECK (confidence IS NULL OR confidence IN ('confident', 'likely')),
    reason        TEXT    NOT NULL CHECK (length(reason) BETWEEN 1 AND 600),
    quote         TEXT    NOT NULL DEFAULT '' CHECK (length(quote) <= 400),
    sources       TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(sources) AND json_type(sources) = 'array'),
    detail        TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail) AND json_type(detail) = 'object'),
    model         TEXT    CHECK (model IS NULL OR length(model) BETWEEN 1 AND 80),
    profile       TEXT    CHECK (profile IS NULL OR length(profile) BETWEEN 1 AND 160),
    activity_id   TEXT    CHECK (activity_id IS NULL OR length(activity_id) <= 96),
    checked_by    TEXT    NOT NULL CHECK (length(checked_by) BETWEEN 1 AND 320),
    checked_at    TEXT    NOT NULL CHECK (checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    rejected_by   TEXT    CHECK (rejected_by IS NULL OR length(rejected_by) BETWEEN 1 AND 320),
    rejected_at   TEXT    CHECK (rejected_at IS NULL OR rejected_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((decided_by = 'ai') = (model IS NOT NULL)),
    CHECK (decided_by = 'ai' OR confidence IS NULL),
    CHECK (verdict <> 'unsure' OR confidence IS NULL),
    CHECK ((rejected_by IS NULL) = (rejected_at IS NULL)),
    CHECK (rejected_by IS NULL OR decided_by = 'ai')
);

CREATE UNIQUE INDEX fnd_possible_check_identity_uq ON fnd_possible_check (cve, product_key, line, evidence_hash);

CREATE INDEX fnd_possible_check_cve_ix ON fnd_possible_check (cve);
