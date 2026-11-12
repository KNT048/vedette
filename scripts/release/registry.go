package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// registryHTTP reads manifests from a registry over the distribution API, anonymously: the way a customer box pulls (D-457). It is
// used to prove a published image is pullable without credentials (publish) and to read a remote list that already exists (push).
// The host is fixed by the caller (https://ghcr.io, or http://127.0.0.1:<port> for a rehearsal); no URL comes from a response.
type registryHTTP struct {
	base   string // scheme://host, no trailing slash
	client *http.Client
}

const (
	acceptList  = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json"
	acceptImage = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
	maxManifest = 4 << 20
)

// errDenied is a registry that does not give the manifest to an anonymous client (private package, or no such name).
var errDenied = errors.New("not pullable anonymously")

func newRegistryHTTP(base string) registryHTTP {
	return registryHTTP{base: base, client: &http.Client{Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// registryBase is the API base of a registry name (host[:port][/namespace]) and the namespace in front of each repository.
func registryBase(reg string) (base, ns string) {
	host, ns, _ := strings.Cut(reg, "/")
	if loopbackRegistry(reg) {
		return "http://" + host, ns
	}
	return "https://" + host, ns
}

// token asks the registry's /token endpoint for an anonymous pull token (ghcr.io, Docker Hub style). A registry without that
// endpoint (404, the rehearsal's registry:2) needs none.
func (r registryHTTP) token(ctx context.Context, repo string) (string, error) {
	q := url.Values{"scope": {"repository:" + repo + ":pull"}, "service": {strings.TrimPrefix(strings.TrimPrefix(r.base, "https://"), "http://")}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+"/token?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", fmt.Errorf("%s: token: %w (HTTP %d)", repo, errDenied, resp.StatusCode)
	default:
		return "", fmt.Errorf("%s: token: HTTP %d", repo, resp.StatusCode)
	}
	var t struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&t); err != nil || t.Token == "" {
		return "", fmt.Errorf("%s: token: no token in the answer", repo)
	}
	return t.Token, nil
}

// manifest fetches /v2/<repo>/manifests/<ref> anonymously. HEAD returns no body. A GET by digest checks that the bytes hash to it.
func (r registryHTTP) manifest(ctx context.Context, method, repo, ref, accept string) ([]byte, error) {
	tok, err := r.token(ctx, repo)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+"/v2/"+repo+"/manifests/"+ref, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return nil, fmt.Errorf("%s@%s: %w (HTTP %d)", repo, ref, errDenied, resp.StatusCode)
	default:
		return nil, fmt.Errorf("%s@%s: HTTP %d", repo, ref, resp.StatusCode)
	}
	if method == http.MethodHead {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxManifest+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxManifest {
		return nil, fmt.Errorf("%s@%s: manifest larger than %d bytes", repo, ref, maxManifest)
	}
	if strings.HasPrefix(ref, "sha256:") && digestBytes(b) != ref {
		return nil, fmt.Errorf("%s@%s: the registry answered other bytes (%s)", repo, ref, digestBytes(b))
	}
	return b, nil
}

func digestBytes(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// configDigest is the config digest of an image manifest.
func configDigest(raw []byte) (string, error) {
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || !serviceDigestRE.MatchString(m.Config.Digest) {
		return "", errors.New("not an image manifest with a config digest")
	}
	return m.Config.Digest, nil
}
