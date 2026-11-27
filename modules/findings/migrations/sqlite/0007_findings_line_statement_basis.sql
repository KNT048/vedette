-- +goose Up
-- How the AI read a release line's statement: 'stated' (the text states it for this product) or 'inferred' (from another product's
-- release line of the same CVE record, findings P-6). An inferred reading only ever opens a finding: it never gives a fix and never
-- settles a version as not affected, decided from this column, not from its quote. Readings stored before are 'stated'.
-- Add-only: a plain column with a default (its values, stated or inferred, are checked in Go where findings writes it: storeStatement),
-- so the release stays safe to roll back. Forward-only: there is no Down section.
ALTER TABLE fnd_line_statement ADD COLUMN basis TEXT NOT NULL DEFAULT 'stated';
