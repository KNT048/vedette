-- +goose Up
-- The pin of a TLS source (D-435): the SHA-256 of the client certificate the device must present, 64 lowercase hex characters, or '' for a
-- sender known by its IP address alone (every existing row).
ALTER TABLE logs_sources ADD COLUMN client_cert_sha256 TEXT NOT NULL DEFAULT '' CHECK (client_cert_sha256 = '' OR (length(client_cert_sha256) = 64 AND client_cert_sha256 NOT GLOB '*[^0-9a-f]*'));
