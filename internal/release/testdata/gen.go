//go:build ignore

// gen.go makes the cosign-format test vectors and the unsigned release documents. cosign itself is
// not installed on the dev machine, so the legacy simple-signing format is built here exactly as
// sigstore's pkg/signature/payload emits it (see README.md): ECDSA P-256 over SHA-256 of the
// payload, ASN.1 DER, base64. A fresh cosign test key is made on every run; its private half is
// never written to disk.
//
//	go run internal/release/testdata/gen.go internal/release/testdata
//
// Afterwards sign release/index.json and release/release-manifest.json with minisign (README.md).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func write(dir, name string, b []byte) { must(os.WriteFile(filepath.Join(dir, name), b, 0o644)) }

// The payload types are copied in shape from sigstore/sigstore pkg/signature/payload/payload.go.
type simpleContainerImage struct {
	Critical critical       `json:"critical"`
	Optional map[string]any `json:"optional"`
}
type critical struct {
	Identity identity `json:"identity"`
	Image    image    `json:"image"`
	Type     string   `json:"type"`
}
type identity struct {
	DockerReference string `json:"docker-reference"`
}
type image struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

func main() {
	dir := os.Args[1]
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(err)
	write(dir, "cosign/cosign.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	sign := func(payload []byte) string {
		h := sha256.Sum256(payload)
		sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
		must(err)
		return base64.StdEncoding.EncodeToString(sig)
	}
	// Sign the two payloads taken from sigstore's own payload_test.go.
	for _, n := range []string{"null-optional", "nested-optional"} {
		p, err := os.ReadFile(filepath.Join(dir, "cosign/sigstore-"+n+".json"))
		must(err)
		write(dir, "cosign/sigstore-"+n+".sig", []byte(sign(p)))
	}

	// A realistic manifest: one payload per image, signed with the same key.
	type cos struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	mk := func(service, version, digest string) cos {
		p, err := json.Marshal(simpleContainerImage{Critical: critical{
			Identity: identity{"ghcr.io/knt048/vedette-" + service},
			Image:    image{digest},
			Type:     "cosign container image signature",
		}})
		must(err)
		return cos{base64.StdEncoding.EncodeToString(p), sign(p)}
	}
	dg := func(s string) string { h := sha256.Sum256([]byte(s)); return "sha256:" + hex.EncodeToString(h[:]) }
	type img struct {
		Service   string   `json:"service"`
		Ref       string   `json:"ref"`
		Digest    string   `json:"digest"`
		Size      int64    `json:"size"`
		Platforms []string `json:"platforms"`
		Cosign    cos      `json:"cosign"`
	}
	const ver = "1.4.0"
	imgs := []img{}
	for _, s := range []struct {
		name string
		size int64
		pl   []string
	}{{"core", 61203456, []string{"linux/amd64", "linux/arm64"}}, {"sensor", 48000000, []string{"linux/amd64"}}} {
		d := dg("vedette-" + s.name + "-" + ver)
		imgs = append(imgs, img{s.name, "ghcr.io/knt048/vedette-" + s.name + ":" + ver, d, s.size, s.pl, mk(s.name, ver, d)})
	}
	manifest := map[string]any{
		"schema": 1, "version": ver, "channel": "stable", "released_at": "2026-12-02T08:00:00Z",
		"min_upgrade_from": "1.2.0", "db_schema": 14,
		"rollback":      map[string]any{"safe": true, "min_version": "1.3.0"},
		"install_modes": []string{"appliance", "container"},
		"images":        imgs,
		"host":          map[string]any{"version": ver, "files": []map[string]any{{"name": "vedette-host_1.4.0_amd64.deb", "sha256": hex.EncodeToString(make([]byte, 32)), "size": 1234}}},
		"content":       []map[string]any{{"name": "mitigation-packs", "version": "2026-12-02.1", "in_image": "core", "path": "/opt/vedette/content/mitigation-packs", "sha256": hex.EncodeToString(make([]byte, 32))}},
		"bundled":       []map[string]any{{"service": "scan", "name": "nmap", "version": "7.95"}},
		"sbom":          map[string]any{"format": "CycloneDX", "url": "https://github.com/knt048/vedette/releases/download/v1.4.0/sbom.json", "sha256": hex.EncodeToString(make([]byte, 32))},
		"notes":         "Test vector release.",
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	mb = append(mb, '\n')
	write(dir, "release/release-manifest.json", mb)
	ms := sha256.Sum256(mb)

	gen := time.Date(2026, 12, 2, 8, 0, 0, 0, time.UTC)
	index := map[string]any{
		"schema": 1, "sequence": 7,
		"generated_at": gen.Format(time.RFC3339), "expires_at": gen.Add(14 * 24 * time.Hour).Format(time.RFC3339),
		"channels": map[string]any{
			"stable": map[string]any{"latest": ver, "manifest": "https://github.com/knt048/vedette/releases/download/v1.4.0/release-manifest.json", "manifest_sha256": hex.EncodeToString(ms[:]), "rollout": map[string]any{"percent": 100}},
		},
		"revoked":    []map[string]any{{"kind": "release", "id": "1.3.2", "reason": "Test vector: broken migration", "since": "2026-11-20T00:00:00Z", "action": "block_install"}},
		"advisories": []map[string]any{},
		"keys":       []map[string]any{},
	}
	ib, err := json.MarshalIndent(index, "", "  ")
	must(err)
	write(dir, "release/index.json", append(ib, '\n'))
}
