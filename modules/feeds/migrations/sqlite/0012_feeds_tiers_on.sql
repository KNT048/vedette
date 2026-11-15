-- +goose Up
-- D-617 (CVE tiers slice 3a): findings now compares the tier data with the devices ("Updates to plan"), so the two tier feeds
-- (D-614) are on by default. A box seeded with them off gets them on, unless an admin edited the feed (rev counts every edit of a
-- feed: the switch, the schedule, the address), which keeps whatever that admin chose: a feed turned off on purpose stays off.
UPDATE feeds_source SET enabled = 1, failures = 0
WHERE builtin = 1 AND id IN ('epss-all', 'nvd-recent') AND enabled = 0 AND rev = 0;
-- D-615 (2), D-617: the published day of an exploited CVE NVD does not answer for (a VulnCheck-only entry) comes from its CVE.org record
-- (cveMetadata.datePublished). source says who gave the day: NVD's replaces CVE.org's, never the reverse, and only NVD's rows count when
-- nvd-kev decides whether a full pull is needed to fill the table. Forward-only.
ALTER TABLE feeds_published ADD COLUMN source TEXT NOT NULL DEFAULT 'nvd' CHECK (source IN ('nvd', 'cve.org'));
