-- +goose Up
-- The identity of an MCP tool as the first Test saw it (D-127, M1): a hash of its cleaned description and its input schema. An
-- administrator who sets a tool to "read" vouches for that tool; the reader refuses it, and the next Test resets it to "write, off",
-- when the server now describes it differently. '' for a tool of another kind and for a tool saved before this column existed (a
-- read tool of an MCP server with no identity is not callable until the next Test records one).
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

ALTER TABLE core_connection_tool ADD COLUMN ident TEXT NOT NULL DEFAULT '' CHECK (length(ident) <= 64);
