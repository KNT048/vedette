-- +goose Up
-- ai_knowledge_doc, ai_knowledge_chunk and its full-text index of slice 4c (docs/DATA_MODEL.md 4.9, S-AI-7, INV-10). Forward-only.
-- Only ai.Service writes them. The original file is never stored: only the text chunks Go found in it. The index is built on the
-- box with SQLite FTS5 (BM25); nothing is sent anywhere to build it. Go checks every limit first and says why; the trigger is the
-- second lock for the count of documents.

-- One uploaded document. status: uploading (received, waiting for the indexer), indexing (being read), ready. chunks is null until
-- the document is ready; a document that could not be read, or has no text in it, is ready with 0 chunks (the audit row says why).
-- jobs is a JSON array of job ids; [] means every job (only the jobs that carry internal data ever read it, INV-3).
CREATE TABLE ai_knowledge_doc (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    size        INTEGER NOT NULL CHECK (size BETWEEN 1 AND 10485760),
    status      TEXT    NOT NULL CHECK (status IN ('uploading', 'indexing', 'ready')),
    chunks      INTEGER CHECK (chunks IS NULL OR chunks >= 0),
    jobs        TEXT    NOT NULL CHECK (json_valid(jobs) AND json_type(jobs) = 'array'),
    uploaded_at TEXT    NOT NULL CHECK (uploaded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((status = 'ready') = (chunks IS NOT NULL))
);

-- +goose StatementBegin
CREATE TRIGGER ai_knowledge_doc_max BEFORE INSERT ON ai_knowledge_doc
WHEN (SELECT COUNT(*) FROM ai_knowledge_doc) >= 50
BEGIN
    SELECT RAISE(ABORT, 'ai_knowledge_doc: at most 50 documents');
END;
-- +goose StatementEnd

-- The text of a document in pieces of about 3200 bytes (customer data: exported like memory, deleted with the document).
CREATE TABLE ai_knowledge_chunk (
    id     INTEGER NOT NULL PRIMARY KEY,
    doc_id TEXT    NOT NULL REFERENCES ai_knowledge_doc (id) ON DELETE CASCADE,
    seq    INTEGER NOT NULL CHECK (seq >= 1),
    text   TEXT    NOT NULL CHECK (length(text) BETWEEN 1 AND 4000),
    UNIQUE (doc_id, seq)
);

-- The index of the chunks: external content, so the text is stored once. unicode61 with remove_diacritics 2 makes "tuong" find
-- "Tường". The triggers keep it in step with the chunk table, in the same transaction as every insert and delete.
CREATE VIRTUAL TABLE ai_knowledge_chunk_fts USING fts5 (text, content = 'ai_knowledge_chunk', content_rowid = 'id', tokenize = 'unicode61 remove_diacritics 2');

-- +goose StatementBegin
CREATE TRIGGER ai_knowledge_chunk_ai AFTER INSERT ON ai_knowledge_chunk
BEGIN
    INSERT INTO ai_knowledge_chunk_fts (rowid, text) VALUES (new.id, new.text);
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER ai_knowledge_chunk_ad AFTER DELETE ON ai_knowledge_chunk
BEGIN
    INSERT INTO ai_knowledge_chunk_fts (ai_knowledge_chunk_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
-- +goose StatementEnd
