-- +goose Up
-- How the AI read a release line's statement: 'stated' (the text states it for this product and every version of the quote follows the
-- product's own name), 'unpaired' (a version of the quote does not: it opens, gives no fix, and a "not affected" is a proposal for a
-- person) or 'inferred' (from another product's release line of the same CVE record: it only opens). Decided from this column, not from
-- the quote (findings P-6). Readings stored before were read without that check: 'unpaired' until read again.
-- Add-only: a plain column with a default (its values, stated, unpaired or inferred, are checked in Go where findings writes it: storeStatement),
-- so the release stays safe to roll back. Forward-only: there is no Down section.
ALTER TABLE fnd_line_statement ADD COLUMN basis TEXT NOT NULL DEFAULT 'unpaired';
