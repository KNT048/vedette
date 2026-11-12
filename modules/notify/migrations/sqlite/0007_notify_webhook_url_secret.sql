-- +goose Up
-- The webhook URL is a bearer secret (path or query tokens, SYS-4): it is sealed in core/secrets like the other channel secrets.
-- url_secret_id names the sealed URL; url_last4 is its last 4 characters for the settings page. While a URL is sealed,
-- notify_channel.fields.url holds only "scheme://host/…" (what the API shows). A row saved before this migration still has the
-- plain URL in fields.url and no url_secret_id: Go seals it on the next run of the deliver job or the next read of the channels
-- (SQL cannot open the key), and until then every read masks it.
ALTER TABLE notify_channel ADD COLUMN url_secret_id TEXT REFERENCES core_secret (id);
ALTER TABLE notify_channel ADD COLUMN url_last4 TEXT CHECK (url_last4 IS NULL OR length(url_last4) = 4);
