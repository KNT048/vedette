-- +goose Up
-- D-416, core INV-37: the audit log keeps 365 days, at most 200,000 lines. core_audit stays append-only for every writer but the
-- retention prune: a line can be deleted only when it is at or before the line core_chain_anchor names for core_audit. The prune moves
-- the anchor first (chainhead.Prune) and then deletes the oldest run up to that line, in one transaction; any other delete, and a
-- delete past the anchor, still aborts. (The anchor line itself is deleted by its own statement, last, so the lookup still finds it.)
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

DROP TRIGGER core_audit_no_delete;

-- +goose StatementBegin
CREATE TRIGGER core_audit_no_delete BEFORE DELETE ON core_audit
WHEN OLD.seq > COALESCE((SELECT a.seq FROM core_audit a JOIN core_chain_anchor c ON c.last_pruned_id = a.id WHERE c.chain = 'core_audit'), 0)
BEGIN
    SELECT RAISE(ABORT, 'core_audit is append-only');
END;
-- +goose StatementEnd
