-- +goose Up
-- A repeat of an event is held back only while its incident is open; whether a person resolved it since is read per key
-- (ResolvedSince). Resolved incidents are kept for a year, so the read needs its own index instead of a scan. Add-only and
-- forward-only: there is no Down section.
CREATE INDEX notify_incident_resolved_idx ON notify_incident (dedupe_key, handled_at) WHERE status = 'resolved';
