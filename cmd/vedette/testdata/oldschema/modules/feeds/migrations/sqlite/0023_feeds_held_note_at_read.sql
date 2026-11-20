-- +goose Up
-- What a feed of heldNotes holds (first-epss, nvd-kev, cve-org, the four distribution feeds, windows-releases) is counted when its row
-- is read, in front of the note of its last pull. The previous version stored that sentence at the start of the note of every good
-- pull; it is taken off here, so the row does not say it twice (the old count, then the one of now) until the feed's next pull. The
-- sentence is the note's first one: it ends at its first ". " (it has none inside), and the pull's own sentence follows. A note that
-- does not start with it (one stored before held notes) is kept. Forward-only.
UPDATE feeds_source SET error = CASE WHEN instr(error, '. ') > 0 THEN substr(error, instr(error, '. ') + 2) END
WHERE status = 'ok' AND error IS NOT NULL AND (
    (id = 'first-epss' AND (error GLOB 'Scores of * exploited CVE* on the CISA list, today''s and a week ago''s.*'
        OR error GLOB 'No score yet: the exploited CVEs are scored once the CISA list is on the box.*'))
    OR (id = 'nvd-kev' AND error GLOB 'NVD records of * exploited CVE*; * of them name affected versions.*')
    OR (id = 'cve-org' AND (error GLOB 'Nothing to read yet: CVE.org is read for the exploited CVEs NVD gives no affected versions for*'
        OR error GLOB 'Read only for exploited CVEs NVD gives no affected versions for, and NVD gives them for every one now.*'
        OR error GLOB '[0-9]* exploited CVE* no affected versions from NVD*'))
    OR (id IN ('ubuntu-osv', 'ubuntu-vex', 'debian-tracker', 'alpine-osv') AND error GLOB 'Counts one record per package, release and CVE: *')
    OR (id = 'windows-releases' AND error GLOB '[0-9]* Windows release* on Microsoft''s release information pages*')
);
