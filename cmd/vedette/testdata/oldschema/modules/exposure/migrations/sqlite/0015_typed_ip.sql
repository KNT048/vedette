-- +goose Up
-- A public IP a person types in, proved by a token file served on it or by forward-confirmed reverse DNS (CONTRACT INV-35).
-- exp_target's CHECKs (an IP has no token, its only method is box_egress) stay as they are for the IPs the box finds by itself, so a
-- typed IP keeps its own columns instead of a rebuilt table: typed marks it, ip_token is the token the proof file carries and
-- proof_method is how it was last proved. verified_at is the last passing proof and the 30 days run from it, as for a detected IP.
-- Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_target ADD COLUMN typed INTEGER NOT NULL DEFAULT 0 CHECK (typed IN (0, 1) AND (typed = 0 OR kind = 'ip'));
ALTER TABLE exp_target ADD COLUMN ip_token TEXT CHECK (ip_token IS NULL OR (typed = 1 AND length(ip_token) = 16));
ALTER TABLE exp_target ADD COLUMN proof_method TEXT CHECK (proof_method IS NULL OR (typed = 1 AND proof_method IN ('ip_file', 'ip_ptr')));
