package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store/coredb"
)

// The one-time setup code (D-75). While first-run setup is open (no administrator has been created) the box
// keeps a random code in core_secret and prints it in its log at every start; POST /core/setup needs it, so
// whoever can merely reach the port cannot claim the box before its owner does. The code is deleted in the
// transaction that creates the first administrator. It is 100 bits typed in four groups of five (letters
// and digits that cannot be mistaken for each other); input is compared without case, spaces and hyphens.
const (
	setupCodePurpose = "core_setup_code"
	// CodeInvalidSetupCode is the 403 of a missing or wrong setup code.
	CodeInvalidSetupCode = "invalid_setup_code"
	setupCodeAlphabet    = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 32 symbols: 256 % 32 == 0, so a random byte maps without bias
	setupCodeGroups      = 4
	setupCodeGroupLen    = 5
)

func invalidSetupCode() *apierr.Error {
	return apierr.New(403, CodeInvalidSetupCode, "The setup code is missing or wrong. Find it in the box's log: it is printed there each time Vedette starts while setup is open.")
}

func newSetupCode() (string, error) {
	n := setupCodeGroups * setupCodeGroupLen
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("core: setup code: %w", err)
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%setupCodeGroupLen == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(setupCodeAlphabet[int(c)%len(setupCodeAlphabet)])
	}
	return sb.String(), nil
}

// normalizeSetupCode makes typed input comparable: upper case, without spaces or hyphens.
func normalizeSetupCode(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, strings.ToUpper(s))
}

// setupCodesEqual compares the typed code with the stored one in constant time: both are reduced to a
// SHA-256 digest first, so the comparison always takes the same time whatever the lengths or the first
// differing character are.
func setupCodesEqual(given, want string) bool {
	a := sha256.Sum256([]byte(normalizeSetupCode(given)))
	b := sha256.Sum256([]byte(normalizeSetupCode(want)))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// storedSetupCode reads the code, ok=false when none is stored (setup is done, or EnsureSetupCode has not run).
func (h *Handlers) storedSetupCode(ctx context.Context) (code string, ok bool, err error) {
	id, err := coredb.New(h.db.Reader()).GetSecretIDByPurpose(ctx, setupCodePurpose)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("core: find setup code: %w", err)
	}
	b, err := h.secrets.Open(ctx, h.db.Reader(), id, setupCodePurpose)
	if err != nil {
		return "", false, fmt.Errorf("core: open setup code: %w", err)
	}
	return string(b), true, nil
}

// EnsureSetupCode is called once at start-up. While setup is open it returns the code (making and storing
// it the first time); once setup is done it removes any code that is left and returns "". The caller prints
// a non-empty code in the log: that is the one place the code is meant to be read, the same way the first
// admin password of other self-hosted tools is.
func (h *Handlers) EnsureSetupCode(ctx context.Context) (string, error) {
	var code string
	err := h.db.Write(ctx, func(tx *sql.Tx) error {
		q := coredb.New(tx)
		id, err := q.GetSecretIDByPurpose(ctx, setupCodePurpose)
		have := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("core: find setup code: %w", err)
		}
		if org, err := q.GetOrg(ctx); err == nil && org.SetupComplete != 0 {
			if have {
				if err := h.secrets.Delete(ctx, tx, id); err != nil && !errors.Is(err, secrets.ErrNotFound) {
					return err
				}
			}
			return nil
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("core: read org: %w", err)
		}
		if have {
			b, err := h.secrets.Open(ctx, tx, id, setupCodePurpose)
			if err != nil {
				return fmt.Errorf("core: open setup code: %w", err)
			}
			code = string(b)
			return nil
		}
		code, err = newSetupCode()
		if err != nil {
			return err
		}
		_, _, err = h.secrets.Seal(ctx, tx, setupCodePurpose, []byte(code), false)
		return err
	})
	return code, err
}

// dropSetupCode removes the stored code inside the transaction that completes setup.
func (h *Handlers) dropSetupCode(ctx context.Context, tx *sql.Tx) error {
	id, err := coredb.New(tx).GetSecretIDByPurpose(ctx, setupCodePurpose)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("core: find setup code: %w", err)
	}
	if err := h.secrets.Delete(ctx, tx, id); err != nil && !errors.Is(err, secrets.ErrNotFound) {
		return err
	}
	return nil
}
