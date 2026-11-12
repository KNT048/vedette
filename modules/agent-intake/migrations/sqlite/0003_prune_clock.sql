-- +goose Up
-- agent-intake, the clock of node-prune (S-INV-4, WP-26 slice 3, D-169 (4), D-265 (8)). Only package modules/agent-intake writes it.
-- Forward-only (DATA_MODEL 6): no Down section.

-- One row (id = 1): when the node-prune job last ran. A node is pruned after 90 days of silence while the job runs; time the module was
-- off, or the box was down, is not silence. At the first run after a gap of more than 3 hours the job adds the gap to every node's
-- last_seen, so a restart or an upgrade (D-260) no longer starts the count again and nodes of a box that is updated are still pruned.
CREATE TABLE intake_prune_clock (
    id       INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    last_run TEXT    NOT NULL
);
