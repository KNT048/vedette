package ai

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/modules/ai/provider"
)

// Location says where a model runs (D-29): internal = inside the company network, cloud = a provider's servers.
type Location string

// The two places a model can run.
const (
	LocationInternal Location = "internal"
	LocationCloud    Location = "cloud"
)

// Profile is one customer-configured AI connection (S-AI-1). APIKey comes from core/secrets.
type Profile struct {
	ID       string
	Name     string
	Kind     string // anthropic, openai, gemini, openai-compatible, custom
	APIStyle provider.APIStyle
	BaseURL  string
	Model    string
	APIKey   provider.Secret
	Location Location
	DailyCap int
	// AnthropicVersion overrides the anthropic-version header (YYYY-MM-DD); empty = the provider package default.
	AnthropicVersion string
}

var modelNameRE = regexp.MustCompile(`^[\w.:/-]{1,80}$`)
var versionRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// ProfileError is a validation failure with a stable code (the API layer maps it to 400).
type ProfileError struct{ Code, Msg string }

func (e *ProfileError) Error() string { return "ai: " + e.Msg }

func perr(code, format string, a ...any) error { return &ProfileError{code, fmt.Sprintf(format, a...)} }

// Validate applies the profile rules of `POST /ai/profiles` (PRE-3) and the mock's checks. It does not
// check name uniqueness; that needs the other profiles.
func (p Profile) Validate() error {
	if n := utf8.RuneCountInString(strings.TrimSpace(p.Name)); n < 1 || n > 40 {
		return perr("invalid_name", `Give the profile a name of 1 to 40 characters, for example "Claude Sonnet".`)
	}
	switch p.Kind {
	case "anthropic", "openai", "gemini", "openai-compatible", "custom":
	default:
		return perr("invalid_kind", "Pick a provider type: Anthropic, OpenAI, Gemini, OpenAI-compatible or Custom.")
	}
	_, err := provider.StyleForKind(p.Kind, p.APIStyle)
	if err != nil {
		return perr("invalid_style", "Pick a provider type (Anthropic, OpenAI, Gemini, OpenAI-compatible or Custom); a Custom profile also needs the API style the server speaks.")
	}
	if p.Location != LocationInternal && p.Location != LocationCloud {
		return perr("invalid_location", "Say where the model runs: inside the company network or in the cloud.")
	}
	switch p.Kind {
	case "anthropic", "openai", "gemini":
		if p.Location == LocationInternal {
			return perr("invalid_location", "Anthropic, OpenAI and Gemini run in the cloud. Use OpenAI-compatible or Custom for a server on your own network.")
		}
	}
	u, err := url.Parse(strings.TrimSpace(p.BaseURL))
	if err != nil || u.Host == "" {
		return perr("invalid_base_url", "The server address is not valid. Enter it in full, for example https://api.anthropic.com or http://localhost:11434/v1.")
	}
	if _, err := provider.ParseBaseURL(p.BaseURL); err != nil {
		return perr("invalid_base_url", "The address must be http(s)://host[/path] with no user name, password, query or fragment. Enter the API key in its own field.")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || p.Location != LocationInternal) {
		return perr("invalid_base_url", "The address must start with https://. Only a server inside your own network may use http://.")
	}
	// "internal" is only true if it is enforced: a literal IP address must be private. A name is allowed (an Ollama box
	// on the LAN DNS is normal); where it resolves is checked on every connection by the provider's dialer.
	// No profile may point at an address that reaches a metadata service or a neighbour on the link, and a cloud profile may not
	// point at this machine or the private networks (the dialer checks resolved names again at connect time).
	host := strings.ToLower(u.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil {
		switch {
		case provider.Forbidden(ip):
			return perr("invalid_base_url", "That address cannot be used: it is a link-local, metadata, multicast or unspecified address.")
		case p.Location == LocationInternal && !provider.IsInternalAddr(ip):
			return perr("invalid_base_url", "A profile marked as running inside your network must use a private address (10.x, 172.16-31.x, 192.168.x, 100.64-127.x or loopback) or a host name. Mark it as cloud, or fix the address.")
		case p.Location == LocationCloud && provider.IsInternalAddr(ip):
			return perr("invalid_base_url", "A profile marked as running in the cloud must use a public address. A server on this machine or in your network is marked as running inside your network.")
		}
	}
	if p.Location == LocationCloud && (host == "localhost" || strings.HasSuffix(host, ".localhost")) {
		return perr("invalid_base_url", "A profile marked as running in the cloud must use a public address. A server on this machine or in your network is marked as running inside your network.")
	}
	if !modelNameRE.MatchString(p.Model) {
		return perr("invalid_model", "The model name may only contain letters, digits, dots, dashes, colons and slashes (80 characters at most).")
	}
	if p.AnthropicVersion != "" && !versionRE.MatchString(p.AnthropicVersion) {
		return perr("invalid_version", "The API version must look like 2026-10-21.")
	}
	if k := p.APIKey.Reveal(); k != "" && (len(k) < 8 || strings.IndexFunc(k, unicode.IsSpace) >= 0) {
		return perr("invalid_key", "The API key is too short or contains spaces. Copy the whole key again from the provider's console.")
	}
	if p.Location == LocationCloud && !p.APIKey.IsSet() {
		return perr("key_required", "Enter the API key. It stays on this box and is encrypted.")
	}
	if !ValidDailyCap(p.DailyCap) {
		return perr("invalid_cap", "The profile's daily token cap must be a whole number from %d to %d.", MinDailyCap, MaxDailyCap)
	}
	return nil
}

// Usable reports whether the profile can be assigned and called: it has a key, or runs inside the network
// where a key may be optional (INV-1).
func (p Profile) Usable() bool { return p.APIKey.IsSet() || p.Location == LocationInternal }

// Provider builds the client for this profile. http base URLs are only reachable here for internal profiles
// because Validate refuses them otherwise.
func (p Profile) Provider() (provider.Provider, error) {
	style, err := provider.StyleForKind(p.Kind, p.APIStyle)
	if err != nil {
		return nil, fmt.Errorf("ai: profile %q: %w", p.Name, err)
	}
	pr, err := provider.New(provider.Config{
		Style: style, BaseURL: p.BaseURL, Model: p.Model, APIKey: p.APIKey,
		CompatMode: style == provider.StyleOpenAI && p.Kind != "openai", InternalOnly: p.Location == LocationInternal, AnthropicVersion: p.AnthropicVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("ai: profile %q: %w", p.Name, err)
	}
	return pr, nil
}

// Slot is the primary and fallback profile IDs of one job ("" = none).
type Slot struct{ Primary, Fallback string }

// Assignments maps jobs to profiles and carries the privacy rule (INV-2, INV-3).
type Assignments struct {
	InternalOnly bool
	Jobs         map[Job]Slot
}

// Allowed reports whether profile p may be used for job under the privacy rule. Together with AllowedFor this
// is the single place that decides INV-3; assignment validation and the call path both use it.
func (a Assignments) Allowed(job Job, p Profile) bool {
	return a.AllowedFor(job.CarriesInternalData(), p)
}

// AllowedFor is Allowed for a request whose data class is already known: carriesInternal is true when the
// request holds the customer's data (an internal job, or any request with tools or tool results).
func (a Assignments) AllowedFor(carriesInternal bool, p Profile) bool {
	if !p.Usable() {
		return false
	}
	return !a.InternalOnly || !carriesInternal || p.Location == LocationInternal
}

// ErrInvalidAssignment is wrapped by every AssignmentError.
var ErrInvalidAssignment = errors.New("invalid job assignment")

// AssignmentError names the job and a stable code: unknown_profile, profile_unusable, privacy_rule,
// fallback_without_primary, same_profile, unknown_job.
type AssignmentError struct {
	Job       Job
	Code, Msg string
}

func (e *AssignmentError) Error() string { return "ai: " + e.Msg }
func (e *AssignmentError) Unwrap() error { return ErrInvalidAssignment }

// Validate checks the assignments against the known profiles (`PUT /ai/assignments`). A cloud profile for
// a job that carries internal data is refused when InternalOnly is on, so the bad state cannot be saved.
func (a Assignments) Validate(profiles map[string]Profile) error {
	for job := range a.Jobs {
		if !job.Valid() {
			return &AssignmentError{job, "unknown_job", fmt.Sprintf("%q is not an AI job.", job)}
		}
	}
	for _, job := range Jobs() {
		s := a.Jobs[job]
		for _, id := range []struct{ slot, id string }{{"primary", s.Primary}, {"fallback", s.Fallback}} {
			if id.id == "" {
				continue
			}
			p, ok := profiles[id.id]
			switch {
			case !ok:
				return &AssignmentError{job, "unknown_profile", fmt.Sprintf("The %s profile for %s no longer exists. Pick another.", id.slot, job.Name())}
			case !p.Usable():
				return &AssignmentError{job, "profile_unusable", fmt.Sprintf("%q has no API key yet, so it cannot be assigned to %s. Edit the profile and add the key.", p.Name, job.Name())}
			case !a.Allowed(job, p):
				return &AssignmentError{job, "privacy_rule", fmt.Sprintf("%q runs in the cloud, but %s sends internal data and the privacy rule only allows internal profiles. Pick an internal profile or switch the rule off.", p.Name, job.Name())}
			}
		}
		if s.Fallback != "" && s.Primary == "" {
			return &AssignmentError{job, "fallback_without_primary", fmt.Sprintf("Set a primary profile for %s before adding a fallback.", job.Name())}
		}
		if s.Primary != "" && s.Primary == s.Fallback {
			return &AssignmentError{job, "same_profile", fmt.Sprintf("The fallback for %s must be a different profile from the primary.", job.Name())}
		}
	}
	return nil
}
