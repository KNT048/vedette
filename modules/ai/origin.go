package ai

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/ai/provider"
)

// originOf returns scheme://host:port of a base URL, lower case, with the default port filled in, or "" when it cannot be read.
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

// sameOrigin reports whether two base URLs name the same scheme, host and port. An address that cannot be read is never the same.
func sameOrigin(a, b string) bool {
	oa, ob := originOf(a), originOf(b)
	return oa != "" && oa == ob
}

// hostOf is the host (and the port when one is written) a profile points at, for the audit log: no path, no user info.
func hostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return strings.ToLower(u.Host)
}

// keyFor decides which key a profile gets when it is edited or tested. A new key (in.APIKey) is used as given. A blank key keeps the
// stored one only while the provider type and the origin of the address stay the same, so a stored key cannot be sent to another
// host by changing the address (review of slice 1, M1). Otherwise a cloud profile must have its key entered again; an internal
// profile, whose key is optional, simply has none. A profile that had no key gets none.
func keyFor(old stored, in ProfileInput, baseURL string) (key provider.Secret, keptOld bool, err error) {
	if in.APIKey != "" {
		return provider.NewSecret(in.APIKey), false, nil
	}
	if !old.APIKey.IsSet() {
		return provider.Secret{}, false, nil
	}
	moved := !sameOrigin(old.BaseURL, baseURL)
	if old.Kind == in.Kind && !moved {
		return old.APIKey, true, nil
	}
	if in.Location == LocationCloud {
		msg := "Changing the provider type needs the API key entered again."
		if moved {
			msg = "Changing the address needs the API key entered again."
		}
		return provider.Secret{}, false, apierr.New(http.StatusBadRequest, "key_required", msg)
	}
	return provider.Secret{}, false, nil
}

// number formats n with thousands separators, like the mock does.
func number(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
