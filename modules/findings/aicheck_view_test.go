package findings

import (
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
)

// A finding a person confirmed from an AI proposal says so on its view, with the check it rests on (the pages read and the model), and
// keeps saying it after the next match; a question answered "not affected" from a confirmed AI proposal carries that check in the
// Answered list, and a person's own answer carries none.
func TestAIChecked_ViewAndAnsweredCarryTheCheck(t *testing.T) {
	t.Parallel()
	e, fc := possibleWorld(t)
	fc.verdicts["CVE-2026-82002|7.2.1-69057-5"] = ProposeVerdict{Verdict: VerdictAffected, Reason: "DSM 7.2 is affected.", Quote: "DSM 7.2 is not affected by this issue", Source: 1}
	runCheck(t, e)
	it := possibleByCVE(t, e)["CVE-2026-82002"]
	if it.State != PossibleProposal {
		t.Fatalf("82002: %s, want a proposal", it.State)
	}
	id, err := e.svc.ConfirmProposal(t.Context(), it.Question.ID, "ana@example.com", true)
	if err != nil || id == "" {
		t.Fatalf("confirm: %q, %v", id, err)
	}
	check := func(when string) {
		t.Helper()
		v, err := e.svc.View(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		c := v.JSON().AICheck
		if c == nil {
			t.Fatalf("%s: the view of a finding confirmed from an AI proposal has no AI check", when)
		}
		if c.DecidedBy != DecidedAI || c.Verdict != VerdictAffected || c.Model == nil || *c.Model == "" || len(c.Sources) == 0 {
			t.Errorf("%s: AI check %+v: want decided by ai, affected, with its model and pages", when, c)
		}
		// the handler's answer carries it as the contract names it
		out, err := Into[oas.FindingsGetFindingsIDViewOK](v.JSON())
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := out.AiCheck.Get(); !ok || len(got.Sources) == 0 {
			t.Errorf("%s: GET /findings/{id}/view has no ai_check with its pages", when)
		}
	}
	check("after the confirmation")
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	check("after the next match")

	// a finding of another origin has none
	var other string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE id <> ? AND range_origin <> 'ai_confirmed' LIMIT 1`, id).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if v, err := e.svc.View(t.Context(), other); err != nil || v.JSON().AICheck != nil {
		t.Errorf("finding %s: AI check %+v, %v; want none", other, v.JSON().AICheck, err)
	}

	// Answered: a confirmed "not affected" proposal carries its check; a person's own answer none
	e2, _ := possibleWorld(t)
	runCheck(t, e2)
	q := possibleByCVE(t, e2)["CVE-2026-82002"].Question
	if _, err := e2.svc.ConfirmProposal(t.Context(), q.ID, "ana@example.com", false); err != nil {
		t.Fatal(err)
	}
	own := possibleByCVE(t, e2)["CVE-2026-82003"].Question
	if _, err := e2.svc.AnswerQuestion(t.Context(), own.ID, AnswerNotAffected, "not on this build", "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	list, err := e2.svc.Answered(t.Context(), "", Page{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, x := range list.Items {
		switch x.ID {
		case q.ID:
			seen++
			if x.Check == nil || x.Check.DecidedBy != DecidedAI || x.Check.Verdict != VerdictNotAffected || x.Check.Model == nil {
				t.Errorf("answered from an AI proposal: check %+v, want the AI's not-affected check with its model", x.Check)
			}
		case own.ID:
			seen++
			if x.Check != nil {
				t.Errorf("a person's own answer carries a check %+v", x.Check)
			}
		}
	}
	if seen != 2 {
		t.Errorf("found %d of the 2 answered questions in the list", seen)
	}
}

// A person's "not affected" answer given before any check of its evidence was stored does not carry a check made later (here for another
// device that shares the evidence): the answer was not a confirmation of it, so the Answered list must not present it as one.
func TestAIChecked_AnswerBeforeTheCheckCarriesNone(t *testing.T) {
	t.Parallel()
	e, _ := possibleWorld(t)
	twin := e.inv.match["nas-01"]
	twin.ID, twin.Name = "nas-02", "nas-02"
	e.inv.match[twin.ID] = twin
	e.inv.assets[twin.ID] = AssetView{ID: twin.ID, Name: twin.ID, Hostname: ptr(twin.ID), IP: "192.0.2.90", Kind: "server", Approved: true}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	items, err := e.svc.possibleItems(t.Context(), "nas-02")
	if err != nil {
		t.Fatal(err)
	}
	var early Question
	for _, it := range items {
		if it.CVE == "CVE-2026-82002" {
			early = it.Question
		}
	}
	if early.ID == "" || early.CheckKey == "" || early.CheckKey != possibleByCVE(t, e)["CVE-2026-82002"].Question.CheckKey {
		t.Fatalf("nas-02 has no question about CVE-2026-82002 sharing nas-01's evidence: %+v", early)
	}
	if _, err := e.svc.AnswerQuestion(t.Context(), early.ID, AnswerNotAffected, "not on this build", "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	*e.clock = e.clock.Add(time.Hour)
	runCheck(t, e) // checks nas-01's open question: the AI proposes "not affected" for the shared evidence
	if it := possibleByCVE(t, e)["CVE-2026-82002"]; it.State != PossibleProposal {
		t.Fatalf("nas-01 82002: %s, want a proposal", it.State)
	}
	list, err := e.svc.Answered(t.Context(), "nas-02", Page{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range list.Items {
		if x.ID == early.ID && x.Check != nil {
			t.Errorf("an answer given before any check carries the later check %+v", x.Check)
		}
	}
}
