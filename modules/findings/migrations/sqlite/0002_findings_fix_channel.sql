-- +goose Up
-- Where the stored fix is published: 'public' (the vendor's or the distribution's ordinary updates), 'ubuntu_pro' (only Ubuntu Pro's
-- ESM archive carries the fixed package), 'esu' (only Windows Extended Security Updates carry the fixed build). It is part of the fix
-- and of its "By fix" group (fix_key ends in '|<channel>' unless the channel is public), so a fix a subscription is needed for is
-- never said or grouped as an ordinary update. Every row stored before reads 'public'; the next match pass sets the others. The
-- values are validated in Go (Finding.Validate) and by the selfcheck findings.vocabulary: a CHECK on an added column would make the
-- release unsafe to roll back. Forward-only: there is no Down section.
ALTER TABLE fnd_finding ADD COLUMN fix_channel TEXT NOT NULL DEFAULT 'public';
