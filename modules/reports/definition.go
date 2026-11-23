package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/apierr"
)

// DefinitionID is the id of the one report definition (a single template with section switches; SPEC: no template choice).
const DefinitionID = "security"

// ScheduleOwnerKey is the owner key prefix of the report's schedule in core/schedule: reports.def:<definition id>.
const ScheduleOwnerKey = "reports.def"

// ScheduleKey is the core/schedule owner key of a definition's schedule.
func ScheduleKey(id string) string { return ScheduleOwnerKey + ":" + id }

func defaultDefinition() Definition {
	return Definition{ID: DefinitionID, Name: "Security report", Options: DefaultOptions, Recipients: []string{}, ScheduleKey: ScheduleKey(DefinitionID),
		UpdatedAt: "1970-01-01T00:00:00.000Z", UpdatedBy: "system"}
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// loadDefinition reads the definition; one nobody saved is the default (off, no recipients: a clean install sends nothing).
func loadDefinition(ctx context.Context, q rowQuerier, id string) (Definition, error) {
	d := defaultDefinition()
	var opts, rec string
	err := q.QueryRowContext(ctx, `SELECT name, options, recipients, updated_at, updated_by FROM rep_definition WHERE id = ?`, id).Scan(&d.Name, &opts, &rec, &d.UpdatedAt, &d.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return d, nil
	}
	if err != nil {
		return d, fmt.Errorf("reports: reading the report definition: %w", err)
	}
	// Options stored by an older release keep what they say; a field they lack takes its default.
	o := DefaultOptions
	if err := json.Unmarshal([]byte(opts), &o); err != nil {
		return d, fmt.Errorf("reports: reading the report options: %w", err)
	}
	if err := json.Unmarshal([]byte(rec), &d.Recipients); err != nil {
		return d, fmt.Errorf("reports: reading the report recipients: %w", err)
	}
	d.Options = o
	if d.Recipients == nil {
		d.Recipients = []string{}
	}
	return d, nil
}

var (
	periods   = []string{PeriodLast7, PeriodLast30, PeriodMonth}
	groupings = []string{groupDevice, groupCVE}
)

// checkDefinition validates the body of PUT /reports/definition at the boundary (INV-3) and returns it normalised: the name trimmed,
// addresses trimmed, lower-cased, without duplicates. Each refusal names the field.
func checkDefinition(in DefinitionInput) (DefinitionInput, *apierr.Error) {
	var ok bool
	if in.Name, ok = field(in.Name); !ok || runes(in.Name) < 1 || runes(in.Name) > 80 {
		return in, bad("invalid_name", "The report name must be 1 to 80 characters.").With("field", "name")
	}
	if !slices.Contains(periods, in.Options.Period) {
		return in, bad("invalid_period", "Pick the period: the last 7 days, the last 30 days or the last calendar month.").With("field", "options.period")
	}
	if !slices.Contains(groupings, in.Options.Grouping) {
		return in, bad("invalid_grouping", "Group the open findings by device or by CVE.").With("field", "options.grouping")
	}
	if !in.Options.Sections.any() {
		return in, bad("no_sections", "Turn on at least one section; a report with no section would be empty.").With("field", "options.sections")
	}
	if len(in.Recipients) > MaxRecipients {
		return in, bad("invalid_recipients", "The recipient list holds %d emails at most.", MaxRecipients).With("field", "recipients")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in.Recipients))
	for i, e := range in.Recipients {
		e = strings.TrimSpace(e)
		if !validEmail(e) {
			return in, bad("invalid_email", "The email %q is not valid. Use the form name@company.com.", clipRunes(e, 60)).With("field", fmt.Sprintf("recipients[%d]", i))
		}
		if e = strings.ToLower(e); !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	in.Recipients = out
	return in, nil
}

// Definition is GET /reports/definition.
func (s *Service) Definition(ctx context.Context) (Definition, error) {
	return loadDefinition(ctx, s.cfg.DB.Reader(), DefinitionID)
}

// SaveDefinition is PUT /reports/definition (admin): name, options and recipients, with the core_audit row in the same write.
func (s *Service) SaveDefinition(ctx context.Context, actor string, in DefinitionInput) (Definition, error) {
	in, aerr := checkDefinition(in)
	if aerr != nil {
		return Definition{}, aerr
	}
	opts, _ := json.Marshal(in.Options)
	rec, _ := json.Marshal(in.Recipients)
	now := ts(s.clock())
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO rep_definition (id, name, kind, options, recipients, updated_at, updated_by) VALUES (?, ?, 'security', ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET name = excluded.name, options = excluded.options, recipients = excluded.recipients,
			updated_at = excluded.updated_at, updated_by = excluded.updated_by`, DefinitionID, in.Name, string(opts), string(rec), now, actor); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "report.definition", DefinitionID, fmt.Sprintf("%s, by %s, %d recipients", in.Options.Period, in.Options.Grouping, len(in.Recipients)))
	})
	if err != nil {
		return Definition{}, fmt.Errorf("reports: saving the report definition: %w", err)
	}
	d := defaultDefinition()
	d.Name, d.Options, d.Recipients, d.UpdatedAt, d.UpdatedBy = in.Name, in.Options, in.Recipients, now, actor
	return d, nil
}
