-- +goose Up
-- D-378: the CA certificates (PEM, normalised) the box trusts for calls to the identity provider only, in addition to the system
-- roots. Public certificates, not a secret. '' = system roots only. At most 5 certificates of at most 64 KiB in all (checked in Go).
ALTER TABLE oidc_config ADD COLUMN ca_pem TEXT NOT NULL DEFAULT '' CHECK (length(ca_pem) <= 65536);
