-- +goose Up
-- A new job, research-cves: the AI researches what Vedette's own data cannot decide about one CVE for one release line (the quick
-- profile first, the strong profile when the quick answer is not good enough). The job CHECK of ai_assignment lists every job, so the
-- table is rebuilt with the standard SQLite rebuild (same columns, foreign keys and CHECKs; no index, trigger, view or foreign key
-- refers to it). The new job starts with the routing of explain-finding, which did this reading before, as it is: the administrator
-- picks the quick and the strong profile in Job routing. Forward-only: there is no Down section.
CREATE TABLE ai_assignment_new (
    job                 TEXT NOT NULL PRIMARY KEY CHECK (job IN ('explain-finding', 'mitigation-config', 'cve-news', 'log-digest', 'log-investigate', 'ask-my-data', 'weekly-report', 'pdpl-assessment', 'translate-advisory', 'response-plan', 'research-cves')),
    primary_profile_id  TEXT REFERENCES ai_profile (id) ON DELETE SET NULL,
    fallback_profile_id TEXT REFERENCES ai_profile (id) ON DELETE SET NULL,
    CHECK (fallback_profile_id IS NULL OR primary_profile_id IS NOT NULL),
    CHECK (fallback_profile_id IS NULL OR fallback_profile_id <> primary_profile_id)
);
INSERT INTO ai_assignment_new (job, primary_profile_id, fallback_profile_id) SELECT job, primary_profile_id, fallback_profile_id FROM ai_assignment;
INSERT INTO ai_assignment_new (job, primary_profile_id, fallback_profile_id)
    SELECT 'research-cves', primary_profile_id, fallback_profile_id FROM ai_assignment WHERE job = 'explain-finding';
INSERT OR IGNORE INTO ai_assignment_new (job) VALUES ('research-cves');
DROP TABLE ai_assignment;
ALTER TABLE ai_assignment_new RENAME TO ai_assignment;
