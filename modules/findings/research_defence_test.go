package findings

import (
	"database/sql"
	"testing"
)

// A reading the AI made before research (no research behind it) from the vendor's own page, of a CVE no exploited list has, saying "not
// affected": it closes nothing either. The CVE is a proposal in the review queue, its question unanswered, and a finding an earlier
// "affected" reading opened stays open.
func TestAIRead_NotAffectedFromTheVendorsPageNeverCloses(t *testing.T) {
	t.Parallel()
	e, fc := quillWorld(t, "115.11.0")
	aff := quillResearch(StatementAffected, QuoteTool, "Quillfeather Mail 115.11.0 is affected", quillSAText+" Quillfeather Mail 115.11.0 is affected.")
	aff.Verdict.FixedIn, aff.Verdict.Introduced = "", ""
	fc.answers = map[string]ResearchAnswer{cveQuill + "|115.11.0": aff}
	runCheck(t, e)
	if n := quillFindings(t, e); n != 1 {
		t.Fatalf("the affected reading opened %d findings, want 1", n)
	}
	sts, err := statementsOf(t.Context(), e.db.Reader(), []string{cveQuill})
	if err != nil || len(sts) == 0 {
		t.Fatalf("readings %v %v", sts, err)
	}
	legacy := sts[0]
	legacy.Research, legacy.Status, legacy.Basis = nil, StatementNotAffected, BasisStated
	legacy.VendorPage, legacy.QuoteFound = true, true
	legacy.Quote = "Quillfeather Mail 115.11 is not affected"
	legacy.AskedAt, legacy.SeenAt = legacy.AskedAt.Add(60_000_000_000), legacy.SeenAt.Add(60_000_000_000)
	legacy.Key = statementKey(legacy.CVE, legacy.Product, legacy.Line, legacy.RecordHash, "legacy-page")
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { return storeStatement(t.Context(), tx, legacy) }); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := quillFindings(t, e); n != 1 {
		t.Errorf("a not-affected reading closed the finding: %d open, want 1", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE cve = '` + cveQuill + `' AND answer IS NOT NULL`); n != 0 {
		t.Error("the AI's not affected answered the question")
	}
	it := quillItem(t, e)
	if it.State == PossibleSettled {
		t.Fatalf("item %+v: an AI reading settled the CVE", it)
	}
	sts, _ = statementsOf(t.Context(), e.db.Reader(), []string{cveQuill})
	seen := false
	for _, st := range sts {
		seen = seen || st.Key == legacy.Key && st.Status == StatementNotAffected && st.VendorPage && st.Research == nil
	}
	if !seen {
		t.Fatal("the legacy reading is not stored: the test proves nothing")
	}
}

// The basis of a research answer is the box's, never the model's: "stated" only when the quote the box found names the installed
// product itself with a release or line that covers the installed version. A quote about another edition of the vendor's products
// (here a server edition) is an inference, whatever the model wrote.
func TestResearch_TheBoxDecidesTheBasis(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct{ quote, want string }{
		"another edition":        {"Quillfeather Mail Server 115.12 and later are not affected", BasisInferred},
		"no version":             {"Quillfeather Mail is not affected by this issue at all", BasisInferred},
		"a release not paired":   {"the 115 line is fixed in Quillfeather Mail 115.12", BasisInferred},
		"the product's own line": {"Quillfeather Mail 115 is not affected by this issue", BasisStated},
		"the installed release":  {"Quillfeather Mail 115.12.0 is not affected by this issue", BasisStated},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, fc := quillWorld(t, "115.12.0")
			a := quillResearch(StatementNotAffected, QuoteTool, c.quote, quillSAText+" "+c.quote+".")
			a.Basis = BasisStated // the model's claim
			fc.answers = map[string]ResearchAnswer{cveQuill + "|115.12.0": a}
			runCheck(t, e)
			it := quillItem(t, e)
			if it.Check == nil || it.Check.Reading == nil || it.Check.Reading.Research == nil {
				t.Fatalf("item %+v", it)
			}
			if got := it.Check.Reading.Basis; (got == BasisStated) != (c.want == BasisStated) {
				t.Errorf("reading basis %q, want %q", got, c.want) // not stated: unpaired (or inferred from another product's line)
			}
			if got := it.Check.Reading.Research.Detail.Basis; got != c.want {
				t.Errorf("research basis shown %q, want %q", got, c.want)
			}
			if it.State == PossibleSettled {
				t.Errorf("an AI answer settled the CVE")
			}
		})
	}
}
