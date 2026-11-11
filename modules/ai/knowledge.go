package ai

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/store"
)

// Slice 4c of WP-25 (S-AI-7, INV-10): the documents an administrator gave the box (ai_knowledge_doc), their text in pieces
// (ai_knowledge_chunk + the FTS5 index) and the profile chosen to "build the index" (ai_setting key `knowledge`). The index is built on
// the box and sends nothing anywhere; the profile is kept for the day an embedding index needs one (D-209). The original file is
// never stored. What a prompt may take from the pieces is in knowledge_rag.go.

// Limits of the knowledge base (the mock is the contract).
const (
	MaxDocs   = 50 // documents a box holds
	maxQueued = 4  // uploads waiting for the indexer, each holding its bytes in memory
)

// BodyLimits is the per-operation request cap this module needs above the server default (operationId → bytes). A 10 MB file as
// base64 is 13.4 MB, and a little more for the JSON around it. cmd/vedette hands it to server.Config through moduleWiring.BodyLimits.
var BodyLimits = map[string]int64{"ai_post_ai_knowledge": 15 << 20}

// KnowledgeDoc is a document as the API shows it. Chunks is null until the document is ready.
type KnowledgeDoc struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Size       int      `json:"size"`
	Status     string   `json:"status"`
	Chunks     *int     `json:"chunks"`
	Jobs       []string `json:"jobs"`
	UploadedAt string   `json:"uploaded_at"`
}

// KnowledgeView is `GET /ai/knowledge`. IndexProfile is null when none is chosen, or the chosen one cannot be used now.
type KnowledgeView struct {
	IndexProfile *string        `json:"index_profile"`
	Items        []KnowledgeDoc `json:"items"`
}

// KnowledgeUpload is the body of `POST /ai/knowledge`: the file as base64 with the size it must decode to. A nil Jobs is the default
// (explaining findings and asking your data); an empty one means every job.
type KnowledgeUpload struct {
	Name    string
	Size    int
	Content string
	Jobs    []string
}

func docJobsJSON(jobs []string) string {
	raw, err := json.Marshal(jobs)
	if err != nil {
		panic("ai: encode jobs: " + err.Error()) // a slice of strings always encodes
	}
	return string(raw)
}

// checkDocJobs validates the jobs of a document and removes repeats, keeping the order.
func checkDocJobs(jobs []string) ([]string, error) {
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		if !Job(j).Valid() {
			return nil, badInput("invalid_jobs", "One of the chosen jobs is not an AI job. Pick from the list.")
		}
		if !slices.Contains(out, j) {
			out = append(out, j)
		}
	}
	return out, nil
}

// checkDocName tidies a file name and checks it: 1 to 120 characters, no slash, no control or invisible character, one of the four
// types (PDF, MD, TXT, DOCX).
func checkDocName(name string) (string, string, error) {
	name = tidy(name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 120 || strings.ContainsAny(name, `/\`) || auth.HasInvisible(name) {
		return "", "", badInput("invalid_name", "The file name is missing or contains a slash.")
	}
	kind := docKind(name)
	if kind == "" {
		return "", "", badInput("invalid_type", "Only PDF, MD, TXT and DOCX files can be added.")
	}
	return name, kind, nil
}

// indexProfileID is the chosen index profile when it can be used now (INV-3): it exists, has a key or runs inside the network, and
// the privacy rule does not forbid it. "" otherwise. The saved choice stays; only what is shown and what is allowed changes.
func (s *Service) indexProfileID(ctx context.Context) (string, error) {
	var raw string
	err := s.cfg.DB.Reader().QueryRowContext(ctx, `SELECT value FROM ai_setting WHERE key = 'knowledge'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("ai: read knowledge setting: %w", err)
	}
	var v struct {
		IndexProfile *string `json:"index_profile"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return "", fmt.Errorf("ai: knowledge setting: %w", err)
	}
	if v.IndexProfile == nil {
		return "", nil
	}
	sn := s.snap.Load()
	p, ok := sn.find(*v.IndexProfile)
	if !ok || !p.Usable() || sn.assign.InternalOnly && p.Location != LocationInternal {
		return "", nil
	}
	return p.ID, nil
}

func scanDoc(sc interface{ Scan(...any) error }) (KnowledgeDoc, error) {
	var d KnowledgeDoc
	var chunks sql.NullInt64
	var jobs string
	if err := sc.Scan(&d.ID, &d.Name, &d.Size, &d.Status, &chunks, &jobs, &d.UploadedAt); err != nil {
		return KnowledgeDoc{}, err //nolint:wrapcheck // the callers wrap with what they were reading
	}
	if chunks.Valid {
		n := int(chunks.Int64)
		d.Chunks = &n
	}
	d.Jobs = []string{}
	if err := json.Unmarshal([]byte(jobs), &d.Jobs); err != nil {
		return KnowledgeDoc{}, fmt.Errorf("jobs: %w", err)
	}
	return d, nil
}

const docCols = `id, name, size, status, chunks, jobs, uploaded_at`

func (s *Service) docByID(ctx context.Context, q queryer, id string) (KnowledgeDoc, error) {
	d, err := scanDoc(q.QueryRowContext(ctx, `SELECT `+docCols+` FROM ai_knowledge_doc WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return KnowledgeDoc{}, harnessNotFound("document")
	}
	if err != nil {
		return KnowledgeDoc{}, fmt.Errorf("ai: document: %w", err)
	}
	return d, nil
}

// KnowledgeView returns the documents (newest first) and the index profile (`GET /ai/knowledge`, admin).
func (s *Service) KnowledgeView(ctx context.Context) (KnowledgeView, error) {
	if err := s.harnessGuard(); err != nil {
		return KnowledgeView{}, err
	}
	v := KnowledgeView{Items: []KnowledgeDoc{}}
	id, err := s.indexProfileID(ctx)
	if err != nil {
		return v, err
	}
	if id != "" {
		v.IndexProfile = &id
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT `+docCols+` FROM ai_knowledge_doc ORDER BY rowid DESC`)
	if err != nil {
		return v, fmt.Errorf("ai: documents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		d, err := scanDoc(rows)
		if err != nil {
			return v, fmt.Errorf("ai: documents: %w", err)
		}
		v.Items = append(v.Items, d)
	}
	if err := rows.Err(); err != nil {
		return v, fmt.Errorf("ai: documents: %w", err)
	}
	return v, nil
}

// SetIndexProfile chooses the profile that builds the index, or none (`PUT /ai/knowledge/settings`, admin). The index is built
// on the box, so the choice changes nothing yet; it is checked as if it did (INV-3), so no state that would later send documents to a
// profile the privacy rule forbids can be saved.
func (s *Service) SetIndexProfile(ctx context.Context, who string, id *string) (KnowledgeView, error) {
	s.mu.Lock()
	if err := s.harnessGuard(); err != nil {
		s.mu.Unlock()
		return KnowledgeView{}, err
	}
	target := "none"
	if id != nil {
		sn := s.snap.Load()
		p, ok := sn.find(*id)
		switch {
		case !ok:
			s.mu.Unlock()
			return KnowledgeView{}, badInput("unknown_profile", "This AI profile no longer exists. Pick another.")
		case !p.Usable():
			s.mu.Unlock()
			return KnowledgeView{}, badInput("profile_unusable", "%q has no API key yet, so it cannot build the index. Edit the profile and add the key.", p.Name)
		case sn.assign.InternalOnly && p.Location != LocationInternal:
			s.mu.Unlock()
			return KnowledgeView{}, badInput("privacy_rule", "%q runs in the cloud, and your documents are internal data: the privacy rule only allows an internal profile. Pick an internal profile or switch the rule off.", p.Name)
		}
		target = *id
	}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if err := upsertSetting(ctx, tx, "knowledge", struct {
			IndexProfile *string `json:"index_profile"`
		}{id}, s.cfg.Clock(), who); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, who, "ai.knowledge.index", target, "")
	})
	s.mu.Unlock()
	if err != nil {
		return KnowledgeView{}, err
	}
	return s.KnowledgeView(ctx)
}

// AddDoc takes an uploaded document (`POST /ai/knowledge`, admin): it checks the request in the order the mock does, keeps a row with
// the status `uploading`, and hands the bytes to the indexer, which reads and indexes them in the background (the request does not
// wait). Only the text pieces are kept, never the file.
func (s *Service) AddDoc(ctx context.Context, who string, in KnowledgeUpload) (KnowledgeDoc, error) {
	if err := s.harnessGuard(); err != nil {
		return KnowledgeDoc{}, err
	}
	name, kind, err := checkDocName(in.Name)
	if err != nil {
		return KnowledgeDoc{}, err
	}
	switch {
	case in.Size < 1:
		return KnowledgeDoc{}, badInput("invalid_size", "The file is empty.")
	case in.Size > MaxDocBytes:
		return KnowledgeDoc{}, badInput("too_large", "The file is larger than 10 MB. Split it or remove pictures, then upload again.")
	}
	if len(in.Content) > base64.StdEncoding.EncodedLen(in.Size) {
		return KnowledgeDoc{}, badInput("invalid_size", "The file arrived damaged or cut short. Pick it again.")
	}
	data, err := base64.StdEncoding.DecodeString(in.Content)
	if err != nil {
		if data, err = base64.RawStdEncoding.DecodeString(in.Content); err != nil {
			return KnowledgeDoc{}, badInput("invalid_size", "The file arrived damaged or cut short. Pick it again.")
		}
	}
	if len(data) != in.Size {
		return KnowledgeDoc{}, badInput("invalid_size", "The file arrived damaged or cut short. Pick it again.")
	}
	if err := sniffDoc(kind, data); err != nil {
		return KnowledgeDoc{}, badInput("invalid_content", "%s. Only PDF, MD, TXT and DOCX files can be added.", strings.TrimSuffix(err.Error(), "."))
	}
	jobs := []string{"explain-finding", "ask-my-data"}
	if in.Jobs != nil {
		if jobs, err = checkDocJobs(in.Jobs); err != nil {
			return KnowledgeDoc{}, err
		}
	}
	if id, err := s.indexProfileID(ctx); err != nil {
		return KnowledgeDoc{}, err
	} else if id == "" {
		return KnowledgeDoc{}, badInput("no_index_profile", "Choose which AI profile builds the index before adding documents.")
	}
	if s.queued.Add(1) > maxQueued {
		s.queued.Add(-1)
		return KnowledgeDoc{}, apierr.New(http.StatusConflict, "busy", "Documents are still being read. Wait a moment, then add this one.")
	}
	id, now := store.NewID("kd"), store.FormatTS(s.cfg.Clock())
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ai_knowledge_doc`).Scan(&n); err != nil {
			return fmt.Errorf("ai: count documents: %w", err)
		}
		if n >= MaxDocs {
			return badInput("too_many", "A box holds up to %d documents. Delete the ones you no longer use.", MaxDocs)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ai_knowledge_doc (id, name, size, status, chunks, jobs, uploaded_at) VALUES (?, ?, ?, 'uploading', NULL, ?, ?)`,
			id, name, in.Size, docJobsJSON(jobs), now); err != nil {
			return fmt.Errorf("ai: save document: %w", err)
		}
		return s.auditTx(ctx, tx, who, "ai.knowledge.add", name, fmt.Sprintf("%d bytes", in.Size))
	})
	if err != nil {
		s.queued.Add(-1)
		return KnowledgeDoc{}, err
	}
	// The indexer outlives the request: the file is in memory only, and a restart before it ends marks the document unread (New).
	s.indexing.Add(1)
	go s.index(context.WithoutCancel(ctx), id, name, kind, data)
	return KnowledgeDoc{ID: id, Name: name, Size: in.Size, Status: "uploading", Jobs: jobs, UploadedAt: now}, nil
}

// index reads one document and stores its text pieces. It takes the single place of the indexer, so documents are read one at a
// time. A document that cannot be read ends `ready` with 0 chunks and the reason in the audit row; a document deleted meanwhile is
// dropped without a trace.
func (s *Service) index(ctx context.Context, id, name, kind string, data []byte) {
	defer s.indexing.Done()
	defer s.queued.Add(-1)
	s.indexSlot <- struct{}{}
	defer func() { <-s.indexSlot }()
	if !s.moduleOn() { // module off stops the job (SYS-5); the document stays unfinished and the next start ends it (recoverKnowledge)
		return
	}
	wctx, cancel := context.WithTimeout(ctx, extractTimeout+writeTimeout)
	defer cancel()
	moved := false
	if err := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(wctx, `UPDATE ai_knowledge_doc SET status = 'indexing' WHERE id = ? AND status = 'uploading'`, id)
		if err != nil {
			return fmt.Errorf("ai: document status: %w", err)
		}
		n, _ := res.RowsAffected()
		moved = n == 1
		return nil
	}); err != nil || !moved {
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "ai: could not start reading a document", "doc", id, "error", err)
		}
		return
	}
	text, truncated, perr := extractText(wctx, kind, data)
	var chunks []string
	if perr == nil {
		chunks = chunkText(text)
	}
	detail := fmt.Sprintf("%d chunks", len(chunks))
	action := "ai.knowledge.indexed"
	switch {
	case perr != nil:
		action, detail = "ai.knowledge.failed", errReason(perr)
		if errors.Is(perr, errDocNoReader) { // the binary is miswired (no child registered): an operator problem, not a bad file
			s.cfg.Log.ErrorContext(ctx, "ai: no PDF reader is registered in this binary", "doc", id)
		}
	case len(chunks) == 0:
		action, detail = "ai.knowledge.failed", errDocEmpty.Error()
	case truncated:
		detail += fmt.Sprintf(", only the first %d MB of the text was kept", maxStoredText>>20)
	}
	if !s.moduleOn() {
		return
	}
	err := s.withFTSRepair(wctx, func() error {
		return s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
			res, err := tx.ExecContext(wctx, `UPDATE ai_knowledge_doc SET status = 'ready', chunks = ? WHERE id = ? AND status = 'indexing'`, len(chunks), id)
			if err != nil {
				return fmt.Errorf("ai: document status: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return nil // deleted while it was read: nothing to keep
			}
			for i, c := range chunks {
				if _, err := tx.ExecContext(wctx, `INSERT INTO ai_knowledge_chunk (doc_id, seq, text) VALUES (?, ?, ?)`, id, i+1, c); err != nil {
					return fmt.Errorf("ai: save chunk: %w", err)
				}
			}
			return s.auditTx(wctx, tx, "system", action, name, detail)
		})
	})
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "ai: could not store a document", "doc", id, "error", err)
		s.failStuck(ctx, id, name)
	}
}

// failStuck ends a document whose pieces could not be stored as ready with 0 chunks, so it does not stay "indexing" for good.
func (s *Service) failStuck(ctx context.Context, id, name string) {
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := s.cfg.DB.Write(wctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(wctx, `UPDATE ai_knowledge_doc SET status = 'ready', chunks = 0 WHERE id = ? AND status <> 'ready'`, id)
		if err != nil {
			return fmt.Errorf("ai: document status: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil
		}
		return s.auditTx(wctx, tx, "system", "ai.knowledge.failed", name, "its text could not be stored")
	}); err != nil {
		s.cfg.Log.WarnContext(ctx, "ai: could not end a document", "doc", id, "error", err)
	}
}

// recoverKnowledge runs when the service starts. The bytes of an upload are in memory only, so a document still `uploading` or
// `indexing` was cut off by a restart and cannot be finished: it becomes ready with 0 chunks and an audit row says to add it again.
func (s *Service) recoverKnowledge(ctx context.Context) error {
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, name FROM ai_knowledge_doc WHERE status <> 'ready' ORDER BY rowid`)
		if err != nil {
			return fmt.Errorf("ai: unfinished documents: %w", err)
		}
		type doc struct{ id, name string }
		var stuck []doc
		for rows.Next() {
			var d doc
			if err := rows.Scan(&d.id, &d.name); err != nil {
				_ = rows.Close()
				return fmt.Errorf("ai: unfinished documents: %w", err)
			}
			stuck = append(stuck, d)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("ai: unfinished documents: %w", err)
		}
		_ = rows.Close()
		for _, d := range stuck {
			if _, err := tx.ExecContext(ctx, `UPDATE ai_knowledge_doc SET status = 'ready', chunks = 0 WHERE id = ?`, d.id); err != nil {
				return fmt.Errorf("ai: end document: %w", err)
			}
			if err := s.auditTx(ctx, tx, "system", "ai.knowledge.failed", d.name, "the box restarted while it was being read. Delete it and add it again"); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetDocJobs chooses which jobs may use a document (`PUT /ai/knowledge/{id}`, admin). An empty list means every job.
func (s *Service) SetDocJobs(ctx context.Context, who, id string, jobs []string) (KnowledgeDoc, error) {
	if err := s.harnessGuard(); err != nil {
		return KnowledgeDoc{}, err
	}
	jobs, err := checkDocJobs(jobs)
	if err != nil {
		return KnowledgeDoc{}, err
	}
	var out KnowledgeDoc
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		d, err := s.docByID(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ai_knowledge_doc SET jobs = ? WHERE id = ?`, docJobsJSON(jobs), id); err != nil {
			return fmt.Errorf("ai: save document: %w", err)
		}
		d.Jobs = jobs
		out = d
		return s.auditTx(ctx, tx, who, "ai.knowledge.jobs", d.Name, "")
	})
	return out, err
}

// DeleteDoc removes a document with its pieces and its index entries, in one transaction (`DELETE /ai/knowledge/{id}`, admin).
func (s *Service) DeleteDoc(ctx context.Context, who, id string) error {
	if err := s.harnessGuard(); err != nil {
		return err
	}
	return s.withFTSRepair(ctx, func() error {
		return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			d, err := s.docByID(ctx, tx, id)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM ai_knowledge_chunk WHERE doc_id = ?`, id); err != nil {
				return fmt.Errorf("ai: delete chunks: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM ai_knowledge_doc WHERE id = ?`, id); err != nil {
				return fmt.Errorf("ai: delete document: %w", err)
			}
			return s.auditTx(ctx, tx, who, "ai.knowledge.remove", d.Name, "")
		})
	})
}
