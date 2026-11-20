-- +goose Up
-- The AI token caps become monthly budgets (D-531, beta item 23): no daily cap stops a job any more; the box spends up to the budget
-- of the calendar month, warns at 80 % and stops at 100 %. A saved daily cap becomes 30 times itself, so a box keeps the allowance
-- it had over a month. ai_profile.daily_cap is replaced by monthly_budget (the column CHECK of daily_cap is its own, so the column
-- can be dropped); the shared budget lives in the JSON of ai_setting key config. Forward-only.
ALTER TABLE ai_profile ADD COLUMN monthly_budget INTEGER NOT NULL DEFAULT 6000000 CHECK (monthly_budget BETWEEN 1000 AND 150000000);
UPDATE ai_profile SET monthly_budget = daily_cap * 30;
ALTER TABLE ai_profile DROP COLUMN daily_cap;

UPDATE ai_setting
SET value = json_remove(json_set(value, '$.monthly_budget', json_extract(value, '$.daily_cap') * 30), '$.daily_cap')
WHERE key = 'config' AND json_type(value, '$.daily_cap') = 'integer';
