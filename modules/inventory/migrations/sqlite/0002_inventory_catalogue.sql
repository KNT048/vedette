-- +goose Up
-- What a source sent of each reading, so that an update of the product catalogue can identify the reading again (its product and
-- release train) without the source reading the device again; and the catalogue the stored lines were last identified under.
-- Forward-only: there is no Down section.

-- The item as the source sent it, as the line's identification read it (identify): its vendor and product names, its version before
-- the catalogue read a release from its name, its first exploited-list key, and its instance before two installs of one train were
-- told apart. NULL item_vendor: not kept (a reading written by an earlier build, a person's edit of a line, a stated OS); such a
-- reading follows its line.
ALTER TABLE inv_software_reading ADD COLUMN item_vendor TEXT CHECK (item_vendor IS NULL OR length(item_vendor) <= 200);
ALTER TABLE inv_software_reading ADD COLUMN item_product TEXT CHECK (item_product IS NULL OR length(item_product) <= 200);
ALTER TABLE inv_software_reading ADD COLUMN item_version TEXT CHECK (item_version IS NULL OR length(item_version) <= 400);
ALTER TABLE inv_software_reading ADD COLUMN item_kev TEXT CHECK (item_kev IS NULL OR length(item_kev) <= 400);
ALTER TABLE inv_software_reading ADD COLUMN item_instance TEXT CHECK (item_instance IS NULL OR length(item_instance) <= 120);

-- One row: the revision of the product catalogue every stored software line was last identified under ('' before the first pass),
-- and the pass under way after an update: the revision it brings the lines to ('' when none) and the last device it finished, so a
-- pass stopped by a restart goes on where it was.
CREATE TABLE inv_catalogue_pass (
    id         INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    revision   TEXT NOT NULL CHECK (length(revision) <= 64),
    target     TEXT NOT NULL DEFAULT '' CHECK (length(target) <= 64),
    after      TEXT NOT NULL DEFAULT '' CHECK (length(after) <= 96),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
