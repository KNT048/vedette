-- +goose Up
-- INV-32: the version of the code that read each feed's stored data (feeds.contentVersions, by decoder). When an update changes what a
-- feed stores or how it parses its source, the code's version moves and the feed is read again in full at the next check (a whole-file
-- feed without its ETag/Last-Modified, an incremental one by its own full reload), instead of after its interval or never (a source that
-- answers 304). 0 = no data read since this column. Every existing feed starts at 1, the version of the code of migrations 0001..0020,
-- except that the Windows releases feed's code is version 2 (its monthly updates of 0019/0020): every box reads it again once (three
-- pages), so one whose last pull of it ran before those tables gets their rows now, not up to a day later. Forward-only.
ALTER TABLE feeds_source ADD COLUMN content_version INTEGER NOT NULL DEFAULT 0 CHECK (content_version >= 0);
UPDATE feeds_source SET content_version = 1;
