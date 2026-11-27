-- +goose Up
-- feeds_cve.assigner: the short name of the CNA that assigned the CVE record ("acme", "vulncheck"), '' until the record is read. A
-- list of exact affected releases is the vendor's enumeration only when the vendor's own CNA wrote it (or NVD's rows of such a record);
-- a third party lists the build it tested. Written by the record reader (at most 64 bytes, checked in Go: clipAssigner), read with the
-- ranges (Range.VendorCNA). Rows stored before stay '' until the record reader's next revision reads every record again. Add-only.
ALTER TABLE feeds_cve ADD COLUMN assigner TEXT NOT NULL DEFAULT '';
