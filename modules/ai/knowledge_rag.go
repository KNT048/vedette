package ai

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// What a call takes from the knowledge base (S-AI-7, INV-10, D-209). The question and the data of the call are turned into search
// words, the FTS5 index (BM25) answers with the best pieces of the documents assigned to the job, each piece goes through the
// before-AI hooks on its own, and what is left goes with the call as a fenced data block, never in the system prompt. Only a job that
// carries internal data reads the base: a job that may run on a cloud profile whatever the privacy rule says (CVE news, translating
// an advisory) never does (INV-3).

// Limits of one retrieval.
const (
	ragTerms      = 24    // search words taken from the question and data
	ragCandidates = 12    // pieces asked of the index, so the hooks can drop some and the rest still fill the block
	ragPieces     = 4     // pieces in a call
	ragChars      = 12000 // characters of pieces in a call
	ragQueryChars = 8000  // characters of question and data read for search words
)

// ftsQuery turns free text into a safe FTS5 query: the words (letters and digits, 2 characters or more, lower case, each once, at
// most ragTerms) each in double quotes, joined with OR. No character of the text is ever passed as FTS5 syntax: a quote cannot occur
// inside a word, and NEAR, AND, OR, NOT, column filters, parentheses and * are either cut off as separators or quoted into plain
// words. "" when the text has no word.
func ftsQuery(text string) string {
	var terms []string
	seen := map[string]bool{}
	var word strings.Builder
	end := func() {
		if w := word.String(); len([]rune(w)) >= 2 && !seen[w] && len(terms) < ragTerms {
			seen[w] = true
			terms = append(terms, `"`+w+`"`)
		}
		word.Reset()
	}
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) {
			word.WriteRune(unicode.ToLower(r))
			continue
		}
		end()
	}
	end()
	return strings.Join(terms, " OR ")
}

// knowCall is what the knowledge base adds to one call: the block to send, the pieces it carries ("<document id>:<piece number>") and
// the names of their documents, the pieces left out because a hook stopped them and the hooks that acted.
type knowCall struct {
	block     DataBlock
	refs      []string
	docs      []string // file names of the documents the pieces come from, each once, in the order sent: the answer's source
	left      []string
	leftNames []string
	names     []string
}

// knowledgeForCall retrieves the pieces for the job and the search text. A piece a hook blocks or holds, or that cannot be checked in
// time, is left out and the next one comes in its place; a mask is applied. The hooks see each piece alone, so a pattern cannot match
// across two pieces and one piece cannot stop the whole call.
func (s *Service) knowledgeForCall(ctx context.Context, hooks *HookRunner, job Job, query string) (knowCall, error) {
	var kc knowCall
	if !job.CarriesInternalData() || s.skillOff(job) != nil {
		return kc, nil
	}
	if len(query) > ragQueryChars {
		query = query[:ragQueryChars]
	}
	match := ftsQuery(query)
	if match == "" {
		return kc, nil
	}
	type piece struct {
		ref, doc, text string
	}
	var found []piece
	read := func() error {
		found = found[:0]
		rows, err := s.cfg.DB.Reader().QueryContext(ctx, `
		SELECT c.doc_id, d.name, c.seq, c.text
		FROM ai_knowledge_chunk_fts f
		JOIN ai_knowledge_chunk c ON c.id = f.rowid
		JOIN ai_knowledge_doc d ON d.id = c.doc_id
		WHERE ai_knowledge_chunk_fts MATCH ? AND d.status = 'ready'
		  AND (d.jobs = '[]' OR EXISTS (SELECT 1 FROM json_each(d.jobs) WHERE value = ?))
		ORDER BY bm25(ai_knowledge_chunk_fts), c.id
		LIMIT ?`, match, string(job), ragCandidates)
		if err != nil {
			return err //nolint:wrapcheck // wrapped below
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var doc, name, text string
			var seq int
			if err := rows.Scan(&doc, &name, &seq, &text); err != nil {
				return err //nolint:wrapcheck // wrapped below
			}
			found = append(found, piece{fmt.Sprintf("%s:%d", doc, seq), name, text})
		}
		return rows.Err() //nolint:wrapcheck // wrapped below
	}
	if err := s.withFTSRepair(ctx, read); err != nil {
		return kc, fmt.Errorf("ai: knowledge: %w", err)
	}
	hctx, cancel := context.WithTimeout(ctx, s.hookTimeout())
	defer cancel()
	var out strings.Builder
	for _, p := range found {
		if len(kc.refs) == ragPieces {
			break
		}
		r, err := hooks.Run(hctx, BeforeAI, p.text)
		if err != nil || r.Outcome == OutcomeBlocked || r.Outcome == OutcomeHeld {
			kc.left = append(kc.left, p.ref)
			kc.leftNames = append(kc.leftNames, r.Names()...)
			continue
		}
		if out.Len()+len(r.Text) > ragChars {
			continue // too long for what is left; a shorter piece further down may still fit
		}
		kc.names = append(kc.names, r.Names()...)
		kc.refs = append(kc.refs, p.ref)
		if !slices.Contains(kc.docs, p.doc) {
			kc.docs = append(kc.docs, p.doc)
		}
		if out.Len() > 0 {
			out.WriteString("\n\n")
		}
		fmt.Fprintf(&out, "[%s]\n%s", p.ref, r.Text)
	}
	if len(kc.refs) > 0 {
		kc.block = DataBlock{Kind: DataDocument, Source: "documents kept by an administrator", Text: out.String()}
	}
	return kc, nil
}

// knowledgeNote names the pieces a call used and the ones a hook kept out (ids, never text), for the activity row.
func knowledgeNote(kc knowCall) string {
	var b strings.Builder
	if len(kc.refs) > 0 {
		b.WriteString(" (knowledge used: " + strings.Join(kc.refs, ", ") + ")")
	}
	if len(kc.left) > 0 {
		b.WriteString(" (knowledge left out because a hook stopped it: " + strings.Join(kc.left, ", ") + ")")
	}
	if n := b.String(); len(n) <= 240 {
		return n
	}
	return b.String()[:237] + "...)" // the row holds 600 characters in all
}

// documentsCite is the source line of the knowledge documents a call carried ("Documents: runbook.md, vpn.pdf"), none when it carried
// none (S-AI-7, D-445). The names are the box's own (checkDocName), never the model's.
func documentsCite(docs []string) []Citation {
	if len(docs) == 0 {
		return nil
	}
	return []Citation{{Title: "Documents: " + strings.Join(docs, ", ")}}
}

// knowledgeQuery is the text a call is searched with: the explicit one of the spec, else the question and the data.
func knowledgeQuery(spec JobSpec) string {
	if spec.KnowledgeQuery != "" {
		return spec.KnowledgeQuery
	}
	var b strings.Builder
	b.WriteString(spec.Question)
	for _, d := range spec.Data {
		b.WriteByte(' ')
		b.WriteString(d.Text)
	}
	return b.String()
}

// knowledgeKey is what the pieces add to the key of a cached result: nothing when the call would carry none, so boxes without documents
// keep their cached explanations.
func knowledgeKey(kc knowCall) string {
	if len(kc.refs) == 0 {
		return ""
	}
	return "\nknowledge:" + kc.block.Text
}
