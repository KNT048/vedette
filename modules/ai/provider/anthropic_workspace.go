package provider

import (
	"errors"
	"strings"
)

// noWorkspace recognises the 400 Anthropic answers to a key that is not scoped to a workspace: every request fails until the key is
// created inside a workspace. The text is checked, not just the status, so other 400 answers stay ordinary refused requests.
func noWorkspace(err error) error {
	var pe *Error
	if !errors.As(err, &pe) || !errors.Is(err, ErrRequest) || pe.Status != 400 {
		return err
	}
	m := strings.ToLower(pe.Message)
	if strings.Contains(m, "not scoped to a workspace") || strings.Contains(m, "anthropic-workspace-id") {
		return &Error{Kind: ErrNoWorkspace, Status: 400}
	}
	return err
}
