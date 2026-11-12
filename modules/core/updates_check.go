package core

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store/coredb"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/release"
)

// The check side of the software update (S-CORE-2, D-340, D-341, update-manifest.md §5.3, §6): fetch the signed
// index and the offered manifest from the project's GitHub releases, verify them with internal/release, keep the
// newest verified index (sequence floor, revocations) and the offered manifest in core_setting, and build
// UpdatesState. Nothing here installs anything: the run side (updates_run.go) takes offered() to the host, which
// verifies everything again (host-api 6.7); the periodic check and the automatic mode are in updates_auto.go.

// DefaultReleaseBase is where the release documents are downloaded from (PRIVACY.md flow 6): the index at
// <base>/index/index.json and a release's manifest at <base>/v<version>/release-manifest.json, each with .minisig.
const DefaultReleaseBase = "https://github.com/KNT048/vedette/releases/download"

// Error codes of the update check (API_CONVENTIONS 3.3, D-341).
const (
	CodeUpdateSourceUnreachable = "update_source_unreachable"
	CodeUpdateCheckFailed       = "update_check_failed"
)

const (
	fetchTimeout = 30 * time.Second // one document
	maxNoteRunes = 500
)

var (
	// releaseHosts are the hosts a release download may be redirected to (PRIVACY.md flow 6, SYS-7).
	releaseHosts = map[string]bool{"github.com": true, "objects.githubusercontent.com": true, "release-assets.githubusercontent.com": true}
	// versionTokenRE is what may go into the User-Agent (modules/feeds does the same).
	versionTokenRE = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,32}$`)
	// errStoredInvalid: the index stored earlier no longer verifies.
	errStoredInvalid = errors.New("core: the stored release index does not verify")
)

// updCheck is the check side's part of OSHandlers.
type updCheck struct {
	version string // the running release (main.version)
	base    string // DefaultReleaseBase, or a test server
	dataDir string // core_data: where a test-channel build looks for testBaseFile
	src     string // where this check downloads from: releaseBase(), read once at its start (checkMu)
	client  *http.Client
	trust   func() (release.Trust, error)
	started time.Time // process start: the installed_at of the running release (no better record exists in core)

	checkMu sync.Mutex  // one check at a time: two checks could otherwise store an older index over a newer one
	next    time.Time   // when the periodic check is due (updates_auto.go); zero until the job first looks; guarded by checkMu
	failed  atomic.Bool // the latest check of this process failed: the automatic mode installs nothing (D-388)

	contMu sync.Mutex // the cached state/containers and /v1/info (the page polls every second during a run; the host allows 60 a minute)
	contAt time.Time
	cont   api.ContainersState
	contEr error
	info   api.Info // the system helper's version and commands (the host component, D-316)
	infoEr error

	warned sync.Map // log lines already written once (key -> struct{})
}

func (u *updCheck) init(c OSConfig, now time.Time) error {
	u.version, u.base, u.client, u.trust, u.started = c.Version, c.ReleaseBase, c.HTTPClient, c.Trust, now
	u.dataDir = c.DataDir
	if u.base == "" {
		u.base = DefaultReleaseBase
	}
	if b, err := url.Parse(u.base); err != nil || b.Host == "" || b.RawQuery != "" || b.Fragment != "" || strings.HasSuffix(u.base, "/") {
		return fmt.Errorf("core: release base %q is not a plain URL", u.base)
	}
	if u.client == nil {
		u.client = newReleaseClient()
	}
	if u.trust == nil {
		u.trust = release.Embedded
	}
	return nil
}

// testBaseFile is the one-line file in core_data that points a TEST-CHANNEL box at a local release source (#469, D-382),
// so that an install of 0.0.1-test.1 can be updated to test.2 from the GUI. It is read only by a build whose own version has
// a -test. prerelease (the version of `make install-artifacts`; release-manifest and the release preflight refuse that version,
// so no published release ever has it) and only when it names an http(s) address of this machine or its LAN. Nothing else
// changes: the documents are still verified with the keys compiled into this build, and the host verifies them again.
const testBaseFile = "test-release-base"

// isTestVersion: a -test. prerelease, the same rule as scripts/release (refuseTestVersion) and install.sh.
func isTestVersion(v string) bool {
	l := strings.ToLower(v)
	return strings.Contains(l, "-test.") || strings.HasSuffix(l, "-test")
}

// releaseBase is where the release documents come from: the configured base (tests), on a test-channel build the address
// in testBaseFile, else DefaultReleaseBase. The file is read on every use, so it can be written after the install.
func (h *OSHandlers) releaseBase() string {
	u := &h.upd
	if u.base != DefaultReleaseBase || u.dataDir == "" || !isTestVersion(u.version) {
		return u.base
	}
	path := filepath.Join(u.dataDir, testBaseFile)
	if st, err := os.Lstat(path); err != nil || !st.Mode().IsRegular() { // a FIFO would block the check
		return u.base
	}
	f, err := os.Open(path) //nolint:gosec // the constant name testBaseFile under core_data
	if err != nil {
		return u.base
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		return u.base
	}
	b := strings.TrimSpace(string(raw))
	if v, ok := testBase(b); ok {
		return v
	}
	if u.firstWarn("test-release-base") {
		h.log.Warn("core: " + testBaseFile + " is not an http(s) address of this machine or its LAN (a private IP; no query, fragment, user info or trailing slash); using the release source")
	}
	return u.base
}

// testBase accepts http(s)://<private or loopback IP>[:port][/path] only.
func testBase(b string) (string, bool) {
	p, err := url.Parse(b)
	if err != nil || len(b) > 256 || (p.Scheme != "http" && p.Scheme != "https") || p.User != nil || p.RawQuery != "" || p.Fragment != "" || strings.ContainsAny(b, "?#") || strings.HasSuffix(b, "/") {
		return "", false
	}
	ip, err := netip.ParseAddr(p.Hostname())
	if err != nil || (!ip.IsLoopback() && !ip.IsPrivate()) {
		return "", false
	}
	return b, true
}

// newReleaseClient is the client of the update check: explicit timeouts, no environment proxy, and redirects only over
// https to the GitHub hosts PRIVACY.md flow 6 names (a release download is redirected to a GitHub file host).
func newReleaseClient() *http.Client {
	return &http.Client{
		Timeout: fetchTimeout,
		Transport: &http.Transport{
			TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second,
			MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" || !releaseHosts[strings.ToLower(req.URL.Hostname())] {
				return errors.New("redirect to a host that is not on the list")
			}
			return nil
		},
	}
}

// userAgent is the User-Agent of every release download: PRIVACY.md flow 6 says the request carries the running
// version, nothing else.
func (u *updCheck) userAgent() string {
	if versionTokenRE.MatchString(u.version) {
		return "Vedette/" + u.version
	}
	return "Vedette/dev"
}

// firstWarn reports whether the warning of kind was not logged yet (since the last clear), and marks it logged.
func (u *updCheck) firstWarn(kind string) bool {
	_, seen := u.warned.LoadOrStore(kind, struct{}{})
	return !seen
}

// ---- stored state ----

// updateSettings is core_setting keyUpdates.
type updateSettings struct {
	Channel   string    `json:"channel"` // stable | beta
	Mode      string    `json:"mode"`    // auto | manual
	LastCheck time.Time `json:"last_check"`
	// LastCheckError is the latest check's failure, kept across restarts and cleared by the next good check (D-392).
	LastCheckError *checkErrorView `json:"last_check_error,omitempty"`
}

// checkErrorView is UpdateCheckError (contract.ts): when the latest check failed, its code and the box's own sentence
// for it (checkFailure's message, never text received from the network).
type checkErrorView struct {
	At      time.Time `json:"at"`
	Code    string    `json:"code"` // CodeUpdateSourceUnreachable | CodeUpdateCheckFailed
	Message string    `json:"message"`
}

func defaultUpdateSettings() updateSettings { return updateSettings{Channel: "stable", Mode: "manual"} }

func (h *OSHandlers) updSettings(ctx context.Context) (updateSettings, error) {
	s := defaultUpdateSettings()
	return s, h.loadJSON(ctx, keyUpdates, &s)
}

func updSettingsTx(ctx context.Context, tx *sql.Tx) (updateSettings, error) {
	s := defaultUpdateSettings()
	raw, err := coredb.New(tx).GetSetting(ctx, keyUpdates)
	if isNoRows(err) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("core: read setting %s: %w", keyUpdates, err)
	}
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return s, fmt.Errorf("core: setting %s is not valid: %w", keyUpdates, err)
	}
	return s, nil
}

// setManual turns the automatic mode off (a rollback does, D-340 (4)); the caller's transaction writes it.
func (h *OSHandlers) setManual(ctx context.Context, tx *sql.Tx, by string) error {
	s, err := updSettingsTx(ctx, tx)
	if err != nil {
		return err
	}
	s.Mode = "manual"
	return h.putSetting(ctx, tx, keyUpdates, s, by)
}

// releaseState is core_setting keyUpdateRelease: the newest verified index as it arrived (bytes and signature) with
// the revocations carried with it (they are not in the signed bytes; host/ops pullstate.go keeps the same), the
// manifest offered at the last check and the manifest of the running release. Every read verifies them again.
type releaseState struct {
	Index    []byte               `json:"index"`
	IndexSig []byte               `json:"index_sig"`
	Carried  []release.Revocation `json:"carried"`
	Offer    *storedManifest      `json:"offer,omitempty"`
	Running  *storedManifest      `json:"running,omitempty"`
}

type storedManifest struct {
	Version  string `json:"version"`
	Manifest []byte `json:"manifest"`
	Sig      []byte `json:"sig"`
}

// loadRelease reads the stored release state and verifies its index again; idx is nil when no index was ever stored.
// A stored index that no longer verifies is an error, never "nothing stored": that would reopen replay (host/ops does the same).
func (h *OSHandlers) loadRelease(ctx context.Context, trust release.Trust) (releaseState, *release.Index, error) {
	var st releaseState
	if err := h.loadJSON(ctx, keyUpdateRelease, &st); err != nil {
		return releaseState{}, nil, err
	}
	if len(st.Index) == 0 {
		return st, nil, nil
	}
	idx, err := release.VerifyStoredIndex(st.Index, st.IndexSig, trust, st.Carried)
	if err != nil {
		return releaseState{}, nil, fmt.Errorf("%w: %w", errStoredInvalid, err)
	}
	return st, idx, nil
}

// ---- offer rules (§5.3, §6) ----

// cohort is uint32(SHA-256(install_id || "vedette-cohort")[0:4]) mod 100 (update-manifest.md §6); ok is false
// before setup (no install_id yet).
func (h *OSHandlers) cohort(ctx context.Context) (int, bool, error) {
	org, err := coredb.New(h.db.Reader()).GetOrg(ctx)
	if isNoRows(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("core: read install id: %w", err)
	}
	return cohortOf(org.InstallID), org.InstallID != "", nil
}

func cohortOf(installID string) int {
	s := sha256.Sum256([]byte(installID + "vedette-cohort"))
	return int(binary.BigEndian.Uint32(s[:4]) % 100)
}

// eligible applies the rules that need only the index: the channel's latest is newer than the running release and
// this box is in its rollout cohort. why says in words why not ("" = eligible).
func (h *OSHandlers) eligible(ctx context.Context, idx *release.Index, channel string) (ch release.Channel, why string, err error) {
	ch, ok := idx.Channels[channel]
	if !ok {
		return ch, "the channel has no release", nil
	}
	c, err := release.CompareVersions(ch.Latest, h.upd.version)
	if err != nil {
		return ch, "the running build has no release version", nil //nolint:nilerr // a dev build: nothing to compare, not a failure
	}
	if c <= 0 {
		return ch, "up to date", nil
	}
	n, ok, err := h.cohort(ctx)
	if err != nil {
		return ch, "", err
	}
	if !ok {
		return ch, "setup is not finished (no install id)", nil
	}
	if n >= ch.Rollout.Percent {
		return ch, fmt.Sprintf("not in the rollout yet (cohort %d, rollout %d%%)", n, ch.Rollout.Percent), nil
	}
	return ch, "", nil
}

// acceptable applies the rules that need the verified manifest; "" = it can be offered.
func (h *OSHandlers) acceptable(m *release.Manifest, latest string) string {
	if m.Version != latest {
		return "the manifest is not the channel's latest release"
	}
	if err := release.CheckUpgrade(m, h.upd.version); err != nil {
		if errors.Is(err, release.ErrUpgradePath) {
			return "needs an intermediate release first (min_upgrade_from " + m.MinUpgradeFrom + ")"
		}
		return "not an upgrade of the running release"
	}
	if h.host != nil && m.CheckInstallMode("appliance") != nil {
		return "the release is not for appliance installs"
	}
	// Without a host this is a container-only install (D-381): the customer pulls the release's images, so it must say
	// it is built for that (S-CORE-9 G4).
	if h.host == nil && m.CheckInstallMode("container") != nil {
		return "the release is not for container-only installs"
	}
	return ""
}

// releaseNow is what the stored state says right now, everything verified again.
type releaseNow struct {
	st      releaseState
	idx     *release.Index    // nil: no index stored
	offer   *verifiedRelease  // nil: nothing offered
	running *release.Manifest // nil: the running release's manifest is unknown
}

func (h *OSHandlers) releaseNow(ctx context.Context) (releaseNow, error) {
	trust, err := h.upd.trust()
	if err != nil {
		return releaseNow{}, fmt.Errorf("core: release keys: %w", err)
	}
	st, idx, err := h.loadRelease(ctx, trust)
	if err != nil || idx == nil {
		return releaseNow{}, err
	}
	s, err := h.updSettings(ctx)
	if err != nil {
		return releaseNow{}, err
	}
	r := releaseNow{st: st, idx: idx}
	if st.Offer != nil {
		r.offer, err = h.offerFrom(ctx, trust, st, idx, s.Channel)
		if err != nil {
			return releaseNow{}, err
		}
	}
	r.running = runningFrom(trust, st, idx, h.upd.version)
	return r, nil
}

// offerFrom re-verifies the stored offer against idx and the current channel: nil when it no longer applies.
func (h *OSHandlers) offerFrom(ctx context.Context, trust release.Trust, st releaseState, idx *release.Index, channel string) (*verifiedRelease, error) {
	ch, why, err := h.eligible(ctx, idx, channel)
	if err != nil || why != "" || ch.Latest != st.Offer.Version {
		return nil, err
	}
	if release.CheckManifestSHA256(idx, channel, st.Offer.Manifest) != nil {
		return nil, nil //nolint:nilnil // the offer is of the other channel (switched since the check): nothing offered
	}
	m, err := release.VerifyManifest(st.Offer.Manifest, st.Offer.Sig, trust, idx)
	if err != nil || h.acceptable(m, ch.Latest) != "" {
		return nil, nil //nolint:nilnil,nilerr // revoked since, or no longer an upgrade: nothing offered
	}
	return &verifiedRelease{Index: st.Index, IndexSig: st.IndexSig, Manifest: st.Offer.Manifest, ManifestSig: st.Offer.Sig, M: m}, nil
}

// runningFrom is the verified manifest of the running release, nil when unknown. After an Apply the running release
// is the one that was offered (st.Offer) until the next check stores it as st.Running. A running release revoked
// since still says what its rollback does: it is verified again with only the key revocations of idx (a revoked
// signing key still makes it unknown).
func runningFrom(trust release.Trust, st releaseState, idx *release.Index, version string) *release.Manifest {
	sm := st.Running
	if sm == nil || sm.Version != version {
		sm = st.Offer
	}
	if sm == nil || sm.Version != version {
		return nil
	}
	m, err := release.VerifyManifest(sm.Manifest, sm.Sig, trust, idx)
	if errors.Is(err, release.ErrReleaseRevoked) {
		keys := *idx
		keys.Revoked = nil
		for _, r := range idx.Revoked {
			if r.Kind == release.KindKey {
				keys.Revoked = append(keys.Revoked, r)
			}
		}
		m, err = release.VerifyManifest(sm.Manifest, sm.Sig, trust, &keys)
	}
	if err != nil || m.Version != version {
		return nil
	}
	return m
}

// offered is the release Apply installs: the stored offer, verified again; errNoUpdate when none.
func (h *OSHandlers) offered(ctx context.Context) (*verifiedRelease, error) {
	r, err := h.releaseNow(ctx)
	if err != nil {
		h.log.WarnContext(ctx, "core: the stored update offer could not be read", "error", err)
		return nil, errNoUpdate
	}
	if r.offer == nil {
		return nil, errNoUpdate
	}
	return r.offer, nil
}

// runningRestoresData: the running release's manifest says rollback.safe=false, so a rollback also puts back the
// database. When the manifest is unknown (never fetched, a dev build, or it does not verify) an appliance assumes it
// does: the host decides from its own record, and a database put back without the confirmation is the worse mistake
// (D-342 (8)); without a host there is no rollback at all.
func (h *OSHandlers) runningRestoresData(ctx context.Context) (bool, error) {
	r, err := h.releaseNow(ctx)
	if err != nil {
		if h.upd.firstWarn("release-state") {
			h.log.WarnContext(ctx, "core: the stored update information could not be read", "error", err)
		}
		r = releaseNow{}
	}
	return h.restoresData(r), nil
}

// restoresData is rollback_restores_data of the page and the confirmation rule of the rollback: one rule for both.
func (h *OSHandlers) restoresData(r releaseNow) bool {
	if r.running == nil {
		return h.host != nil
	}
	return !r.running.Rollback.Safe
}

// ---- fetching ----

// errSource is a download that did not happen: the network, a timeout, or an answer other than 200.
type errSource struct{ err error }

func (e errSource) Error() string { return "core: update source: " + e.err.Error() }
func (e errSource) Unwrap() error { return e.err }

func (h *OSHandlers) fetchDoc(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", h.upd.userAgent())
	resp, err := h.upd.client.Do(req)
	if err != nil {
		return nil, errSource{err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errSource{fmt.Errorf("HTTP %d", resp.StatusCode)}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errSource{err}
	}
	if int64(len(b)) > limit {
		return nil, release.ErrTooLarge
	}
	return b, nil
}

// fetchPair downloads a document and its .minisig.
// docURL is a URL under the fixed upd.base (the one the signed index may name); the bytes come from the check's source,
// which differs from it only on a test-channel build (releaseBase).
func (h *OSHandlers) fetchPair(ctx context.Context, docURL string) (doc, sig []byte, err error) {
	if rest, ok := strings.CutPrefix(docURL, h.upd.base); ok && h.upd.src != "" {
		docURL = h.upd.src + rest
	}
	if doc, err = h.fetchDoc(ctx, docURL, release.MaxDocBytes); err != nil {
		return nil, nil, err
	}
	if sig, err = h.fetchDoc(ctx, docURL+".minisig", release.MaxSigBytes); err != nil {
		return nil, nil, err
	}
	return doc, sig, nil
}

// manifestURL is (under the fixed base, never the test source) the only place a release's manifest is accepted from (D-341): the index names it, and it must be
// exactly this (case-insensitive, as GitHub owners are), so a signed index cannot send the box to another host.
func (h *OSHandlers) manifestURL(version string) string {
	return h.upd.base + "/v" + version + "/release-manifest.json"
}

// ---- POST /core/updates/check ----

// checkFailure turns a failed check into the API error; the remote text is never echoed (it is logged).
func (h *OSHandlers) checkFailure(ctx context.Context, err error) error {
	var src errSource
	switch {
	case errors.Is(err, context.Canceled):
		return err
	case errors.As(err, &src) || errors.Is(err, context.DeadlineExceeded):
		h.log.WarnContext(ctx, "core: the update source could not be reached", "error", err)
		return apierr.New(503, CodeUpdateSourceUnreachable, "Vedette could not download the update information from GitHub. Check that the box can reach github.com over HTTPS, then try again.")
	case errors.Is(err, release.ErrNoTrustKeys):
		h.log.ErrorContext(ctx, "core: this build has no usable release keys", "error", err)
		return apierr.New(502, CodeUpdateCheckFailed, "This build of Vedette has no release signing keys, so it cannot check for updates. Install an official build.")
	case errors.Is(err, errStoredInvalid):
		h.log.ErrorContext(ctx, "core: the stored update information no longer verifies", "error", err)
		return apierr.New(502, CodeUpdateCheckFailed, "The update information this box stored earlier no longer verifies, so Vedette does not trust new information either. The details are in the box log.")
	case errors.Is(err, release.ErrUnknownSchema):
		h.log.WarnContext(ctx, "core: the update information has a newer schema", "error", err)
		return apierr.New(502, CodeUpdateCheckFailed, "This version of Vedette cannot read the newer update information. Update it with an offline bundle or reinstall it.")
	}
	h.log.ErrorContext(ctx, "core: the update information did not verify", "error", err)
	return apierr.New(502, CodeUpdateCheckFailed, "The update information did not pass Vedette's signature checks, so nothing new is offered and nothing was installed. The details are in the box log.")
}

// CorePostCoreUpdatesCheck implements POST /core/updates/check (operator): download and verify the index, the
// offered manifest and (once per running version) the running release's manifest; store them; answer UpdatesState.
// 409 check_off when update checks are off under Privacy: the box then makes no request at all. In automatic mode the
// release on offer is then installed as user "system" when the maintenance window allows (autoInstall, updates_auto.go):
// the answer shows the run going, and applied stays 0 because the software reports at the end of its run (as the mock).
func (h *OSHandlers) CorePostCoreUpdatesCheck(ctx context.Context) (*oas.CorePostCoreUpdatesCheckOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	if err := h.check(ctx, c); err != nil {
		return nil, err
	}
	if err := h.autoInstall(ctx, c.Email); err != nil { // the check itself succeeded; the next tick of the job tries again
		h.log.WarnContext(ctx, "core: the automatic software update did not start", "error", err)
	}
	v, err := h.updatesState(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePostCoreUpdatesCheckOK](struct {
		updatesStateView
		Applied int `json:"applied"`
	}{v, 0})
}

// check is one software update check, the same code for POST /core/updates/check and the periodic job (c = systemCaller):
// 409 check_off when update checks are off under Privacy (no request at all); otherwise one check under checkMu, one
// update.check audit row after it, and the next periodic check due 6 hours ± 30 minutes from now (§12).
func (h *OSHandlers) check(ctx context.Context, c caller) error {
	on, err := h.updateCheckOn(ctx)
	if err != nil {
		return err
	}
	if !on {
		return apierr.New(409, CodeCheckOff, "Update checks are off under Privacy. Turn them on or import an offline bundle.")
	}
	leave, ok := h.gate.Enter()
	if !ok {
		return errPurging()
	}
	defer leave()
	h.upd.checkMu.Lock()
	defer h.upd.checkMu.Unlock()
	h.upd.src = h.releaseBase()
	detail, cerr := h.runCheck(ctx, c.Email)
	h.upd.next = h.now().Add(checkInterval())
	h.upd.failed.Store(cerr != nil)
	if cerr != nil {
		cerr = h.checkFailure(ctx, cerr)
		code := "error"
		if ae, ok := apierr.As(cerr); ok {
			code = ae.Code
			// Kept for the page and for the automatic mode after a restart (D-392); a cancelled request is not a
			// failure of the source and leaves the record as it was. Not written = the in-memory flag still holds.
			if err := h.putCheckError(context.WithoutCancel(ctx), c.Email, &checkErrorView{At: h.now().UTC(), Code: ae.Code, Message: ae.Message}); err != nil {
				h.log.ErrorContext(ctx, "core: the failed update check could not be recorded", "error", err)
			}
		}
		detail = "failed: " + code
	}
	// One row per check, after it (§5.3: who, when, version, sha256); the row of a cancelled request is still written.
	if err := h.record(context.WithoutCancel(ctx), c, false, "update.check", "updates", detail); err != nil {
		return err
	}
	return cerr
}

// runCheck is one check. The newest verified index is stored even when the manifest fails, since it carries the
// sequence floor and the revocations; last_check moves only when the whole check succeeded.
func (h *OSHandlers) runCheck(ctx context.Context, by string) (string, error) {
	trust, err := h.upd.trust()
	if err != nil {
		return "", fmt.Errorf("%w: %w", release.ErrNoTrustKeys, err)
	}
	s, err := h.updSettings(ctx)
	if err != nil {
		return "", err
	}
	st, stored, err := h.loadRelease(ctx, trust)
	if err != nil {
		return "", err
	}
	raw, sig, err := h.fetchPair(ctx, h.upd.base+"/index/index.json")
	if err != nil {
		return "", err
	}
	idx, err := release.VerifyIndex(raw, sig, trust, stored)
	if err != nil {
		return "", err
	}
	if idx.Expired(h.now()) {
		h.log.WarnContext(ctx, "core: the update information is stale (the index is past expires_at)", "sequence", idx.Sequence, "expires_at", idx.ExpiresAt)
	}
	st.Index, st.IndexSig, st.Carried = raw, sig, nonNil(idx.Revoked)
	offer, why, oerr := h.fetchOffer(ctx, trust, idx, s.Channel)
	if st.Offer != nil && st.Offer.Version == h.upd.version {
		st.Running = st.Offer // the release installed since the last check: its manifest is already here
	}
	st.Offer = offer
	if oerr == nil && runningFrom(trust, st, idx, h.upd.version) == nil {
		st.Running = h.fetchRunning(ctx, trust, idx)
	}
	wctx := context.WithoutCancel(ctx) // what was verified is kept even when the caller left
	err = h.db.Write(wctx, func(tx *sql.Tx) error {
		if err := h.putSetting(wctx, tx, keyUpdateRelease, st, by); err != nil {
			return err
		}
		if oerr != nil {
			return nil
		}
		cur, err := updSettingsTx(wctx, tx) // the channel and mode as they are now, not as they were when the check began
		if err != nil {
			return err
		}
		cur.LastCheck, cur.LastCheckError = h.now().UTC(), nil
		return h.putSetting(wctx, tx, keyUpdates, cur, by)
	})
	if err != nil {
		return "", err
	}
	if oerr != nil {
		return "", oerr
	}
	h.log.InfoContext(ctx, "core: update check", "sequence", idx.Sequence, "channel", s.Channel, "offer", why)
	return fmt.Sprintf("running %s, channel %s, index %d sha256 %s: %s", h.upd.version, s.Channel, idx.Sequence, idx.RawSHA256, why), nil
}

// putCheckError stores the failure of the latest check in core_updates (the channel and mode as they are now).
func (h *OSHandlers) putCheckError(ctx context.Context, by string, e *checkErrorView) error {
	return h.db.Write(ctx, func(tx *sql.Tx) error {
		cur, err := updSettingsTx(ctx, tx)
		if err != nil {
			return err
		}
		cur.LastCheckError = e
		return h.putSetting(ctx, tx, keyUpdates, cur, by)
	})
}

// fetchOffer downloads and verifies the channel's latest manifest when the index makes this box eligible. why is the
// outcome in words ("offered 1.4.0" or the reason nothing is). A revoked release, or one this box cannot move to, is
// not an error: nothing is offered. A manifest that does not verify is.
func (h *OSHandlers) fetchOffer(ctx context.Context, trust release.Trust, idx *release.Index, channel string) (*storedManifest, string, error) {
	ch, why, err := h.eligible(ctx, idx, channel)
	if err != nil || why != "" {
		return nil, "nothing offered: " + why, err
	}
	if !strings.EqualFold(ch.Manifest, h.manifestURL(ch.Latest)) {
		return nil, "", fmt.Errorf("%w: the index names a manifest outside the project's releases", release.ErrMalformed)
	}
	raw, sig, err := h.fetchPair(ctx, h.manifestURL(ch.Latest))
	if err != nil {
		return nil, "", err
	}
	if err := release.CheckManifestSHA256(idx, channel, raw); err != nil {
		return nil, "", err
	}
	m, err := release.VerifyManifest(raw, sig, trust, idx)
	if errors.Is(err, release.ErrRevoked) {
		return nil, "nothing offered: " + ch.Latest + " is revoked", nil
	}
	if err != nil {
		return nil, "", err
	}
	if why := h.acceptable(m, ch.Latest); why != "" {
		return nil, "nothing offered: " + why, nil
	}
	return &storedManifest{Version: m.Version, Manifest: raw, Sig: sig}, "offered " + m.Version, nil
}

// fetchRunning downloads the manifest of the running release (for rollback_restores_data). It is not part of the
// check's verdict: a dev build has none and a failure only leaves it unknown.
func (h *OSHandlers) fetchRunning(ctx context.Context, trust release.Trust, idx *release.Index) *storedManifest {
	if _, err := release.CompareVersions(h.upd.version, h.upd.version); err != nil { // not a release version: nothing to fetch
		return nil
	}
	raw, sig, err := h.fetchPair(ctx, h.manifestURL(h.upd.version))
	if err != nil {
		h.log.InfoContext(ctx, "core: the manifest of the running release could not be downloaded", "version", h.upd.version, "error", err)
		return nil
	}
	st := releaseState{Running: &storedManifest{Version: h.upd.version, Manifest: raw, Sig: sig}}
	if runningFrom(trust, st, idx, h.upd.version) == nil {
		h.log.WarnContext(ctx, "core: the manifest of the running release did not verify", "version", h.upd.version)
		return nil
	}
	return st.Running
}

// ---- PATCH /core/updates ----

// CorePatchCoreUpdates implements PATCH /core/updates (admin): the channel and the mode.
func (h *OSHandlers) CorePatchCoreUpdates(ctx context.Context, req *oas.CorePatchCoreUpdatesReq) (*oas.CorePatchCoreUpdatesOK, error) {
	c, err := callerOf(ctx, h.auth)
	if err != nil {
		return nil, err
	}
	ch, chSet := req.Channel.Get()
	mode, modeSet := req.Mode.Get()
	if chSet && ch != "stable" && ch != "beta" {
		return nil, apierr.New(400, "invalid_channel", "The channel is stable or beta.")
	}
	if modeSet && mode != "auto" && mode != "manual" {
		return nil, apierr.New(400, "invalid_mode", "The mode is automatic or manual.")
	}
	detail := fmt.Sprintf("channel %s, mode %s", req.Channel.Or("-"), req.Mode.Or("-"))
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		s, err := updSettingsTx(ctx, tx)
		if err != nil {
			return err
		}
		if chSet {
			s.Channel = string(ch)
		}
		if modeSet {
			s.Mode = string(mode)
		}
		if err := h.putSetting(ctx, tx, keyUpdates, s, c.Email); err != nil {
			return err
		}
		return h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: "update.settings", Target: "updates", Detail: detail})
	})
	if err != nil {
		return nil, err
	}
	v, err := h.updatesState(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CorePatchCoreUpdatesOK](v)
}

// ---- GET /core/updates ----

type updateComponentView struct {
	ID                   string    `json:"id"`
	Kind                 string    `json:"kind"`
	Version              string    `json:"version"`
	Previous             *string   `json:"previous"`
	InstalledAt          time.Time `json:"installed_at"`
	Signature            string    `json:"signature"` // valid | unsigned (invalid is never shown: core does not run what does not verify)
	RollbackRestoresData bool      `json:"rollback_restores_data"`
}

type updateAvailableView struct {
	Component   string `json:"component"`
	Version     string `json:"version"`
	Channel     string `json:"channel"`
	SizeKB      int64  `json:"size_kb"`
	Note        string `json:"note"`
	HostVersion string `json:"host_version,omitempty"` // the release's system helper when it is above the running one (D-316)
	// Images are the release's images by digest from the verified manifest: a container-only install shows one
	// cosign verify per image it runs (S-CORE-9 G4).
	Images []releaseImageView `json:"images"`
}

type releaseImageView struct {
	Service string `json:"service"`
	Digest  string `json:"digest"`
}

type advisoryView struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"` // critical | high | medium
	Published string `json:"published"`
	FixedIn   string `json:"fixed_in"`
	Summary   string `json:"summary"`
	Status    string `json:"status"` // affected | fixed
}

type managedView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Status  string `json:"status"` // ok | update_pending
}

// updatesStateView is UpdatesState (contract.ts).
type updatesStateView struct {
	Channel      string                `json:"channel"`
	Mode         string                `json:"mode"`
	CheckEnabled bool                  `json:"check_enabled"`
	LastCheck    *time.Time            `json:"last_check"`       // null until the first check
	LastCheckErr *checkErrorView       `json:"last_check_error"` // null unless the latest check failed (D-392)
	Components   []updateComponentView `json:"components"`
	Available    []updateAvailableView `json:"available"`
	History      []updateHistoryView   `json:"history"`
	Advisories   []advisoryView        `json:"advisories"`
	Run          *updateRunView        `json:"run"`
	Managed      []managedView         `json:"managed"`
	// RunningRevoked and StaleSince are D-386: what the stored index says about the running release and itself.
	RunningRevoked *runningRevokedView `json:"running_revoked"`
	StaleSince     *time.Time          `json:"stale_since"` // expires_at of the stored index once it has passed
}

type runningRevokedView struct {
	Version string    `json:"version"`
	Reason  string    `json:"reason"`
	Since   time.Time `json:"since"`
	Action  string    `json:"action"`
}

// CoreGetCoreUpdates implements GET /core/updates (viewer).
func (h *OSHandlers) CoreGetCoreUpdates(ctx context.Context) (*oas.CoreGetCoreUpdatesOK, error) {
	v, err := h.updatesState(ctx)
	if err != nil {
		return nil, err
	}
	return asOAS[oas.CoreGetCoreUpdatesOK](v)
}

// updatesView is the whole UpdatesState for the run side's answers (asOAS into the operation's type).
func (h *OSHandlers) updatesView(ctx context.Context) (any, error) {
	return h.updatesState(ctx)
}

// updatesState builds UpdatesState from core's own records; it makes no request outside the box. A stored state that
// does not verify, or a host that does not answer, shows as "nothing known" (logged once), never as a failed page.
func (h *OSHandlers) updatesState(ctx context.Context) (updatesStateView, error) {
	s, err := h.updSettings(ctx)
	if err != nil {
		return updatesStateView{}, err
	}
	on, err := h.updateCheckOn(ctx)
	if err != nil {
		return updatesStateView{}, err
	}
	r, err := h.releaseNow(ctx)
	if err != nil {
		if h.upd.firstWarn("release-state") {
			h.log.WarnContext(ctx, "core: the stored update information could not be read", "error", err)
		}
		r = releaseNow{}
	} else {
		h.upd.warned.Delete("release-state")
	}
	run, err := h.runView(ctx)
	if err != nil {
		return updatesStateView{}, err
	}
	hist, err := h.historyView(ctx)
	if err != nil {
		return updatesStateView{}, err
	}
	comp := updateComponentView{
		ID: softwareComponent, Kind: "software", Version: h.upd.version, InstalledAt: h.upd.started, Signature: "unsigned",
		RollbackRestoresData: h.restoresData(r),
	}
	if cs, ok := h.coreContainer(ctx); ok {
		if cs.Previous != nil {
			comp.Previous = cs.Previous.Version
		}
		if cs.Version != nil && *cs.Version == h.upd.version {
			comp.Signature = "valid" // the host runs only what it verified (host-api 6.7)
		}
	}
	comps := []updateComponentView{comp}
	var helper *api.Info
	if info, ok := h.hostInfo(ctx); ok {
		helper = &info
		comps = append(comps, hostComponentOf(info, hist, h.upd.started))
	}
	var last *time.Time // null until the first check, not Go's zero time (S-CORE-2)
	if !s.LastCheck.IsZero() {
		last = &s.LastCheck
	}
	return updatesStateView{
		Channel: s.Channel, Mode: s.Mode, CheckEnabled: on, LastCheck: last, LastCheckErr: s.LastCheckError,
		Components: comps, Available: availableOf(r.offer, s.Channel, helper),
		History: nonNil(hist), Advisories: advisoriesOf(r.idx, h.upd.version), Run: run,
		Managed:        managedOf(r.running, r.offer),
		RunningRevoked: runningRevokedOf(r.idx, r.running, h.upd.version),
		StaleSince:     staleSince(r.idx, h.now()),
	}, nil
}

// warnsRunning: the revocation actions that tell a box running the release, on every page (D-386 (2)).
func warnsRunning(action string) bool {
	return action == "block_install_and_warn" || action == "rollback_if_possible"
}

// runningRevokedOf is the revocation in idx that hits the running release (update-manifest §8, D-386 (1)): its version,
// or a digest of its manifest when that is known; one with a warning action wins. A key revocation is not one: the box
// keeps the software and only stops trusting new documents signed by that key.
func runningRevokedOf(idx *release.Index, running *release.Manifest, version string) *runningRevokedView {
	if idx == nil {
		return nil
	}
	digests := map[string]bool{}
	if running != nil {
		for _, im := range running.Images {
			digests[im.Digest] = true
		}
	}
	var hit *release.Revocation
	for i := range idx.Revoked {
		r := &idx.Revoked[i]
		hits := (r.Kind == release.KindRelease && r.ID == version) || (r.Kind == release.KindImageDigest && digests[r.ID])
		if !hits {
			continue
		}
		if hit == nil || (!warnsRunning(hit.Action) && warnsRunning(r.Action)) {
			hit = r
		}
	}
	if hit == nil {
		return nil
	}
	return &runningRevokedView{Version: version, Reason: hit.Reason, Since: hit.Since.UTC(), Action: hit.Action}
}

// staleSince is the stored index's expires_at once now is past it (§4.1, §13 (d), D-386 (3)); nil while it is current
// or none is stored. It only warns: nothing is blocked by it.
func staleSince(idx *release.Index, now time.Time) *time.Time {
	if idx == nil || !idx.Expired(now) {
		return nil
	}
	t := idx.ExpiresAt.UTC()
	return &t
}

// refreshHost reads state/containers and /v1/info again when the copies are stateTTL old; the caller holds contMu.
func (h *OSHandlers) refreshHost(ctx context.Context) {
	u := &h.upd
	if age := h.now().Sub(u.contAt); !u.contAt.IsZero() && age >= 0 && age < stateTTL {
		return
	}
	lctx, cancel := context.WithTimeout(ctx, h.loadTimeout)
	defer cancel()
	u.cont, u.contEr = h.host.StateContainers(lctx)
	u.info, u.infoEr = h.host.Info(lctx)
	u.contAt = h.now()
	if u.contEr != nil {
		if u.firstWarn("containers") {
			h.log.WarnContext(ctx, "core: vedette-host did not give the state of the containers; the page shows no previous version", "error", u.contEr)
		}
	} else {
		u.warned.Delete("containers")
	}
	if u.infoEr != nil {
		if u.firstWarn("info") {
			h.log.WarnContext(ctx, "core: vedette-host did not give its version; the page shows no system helper row", "error", u.infoEr)
		}
	} else {
		u.warned.Delete("info")
	}
}

// dropHostCopy makes the next read ask the host again (the helper's version changed).
func (u *updCheck) dropHostCopy() {
	u.contMu.Lock()
	u.contAt = time.Time{}
	u.contMu.Unlock()
}

// hostInfo is the host's /v1/info from a copy younger than stateTTL; ok is false without a host or when it does not answer.
func (h *OSHandlers) hostInfo(ctx context.Context) (api.Info, bool) {
	if h.host == nil {
		return api.Info{}, false
	}
	u := &h.upd
	u.contMu.Lock()
	defer u.contMu.Unlock()
	h.refreshHost(ctx)
	return u.info, u.infoEr == nil
}

// coreContainer is the host's record of the core service, from a copy younger than stateTTL. ok is false without a
// host or when it does not answer (logged when that starts).
func (h *OSHandlers) coreContainer(ctx context.Context) (api.ContainerState, bool) {
	if h.host == nil {
		return api.ContainerState{}, false
	}
	u := &h.upd
	u.contMu.Lock()
	defer u.contMu.Unlock()
	h.refreshHost(ctx)
	if u.contEr != nil {
		return api.ContainerState{}, false
	}
	for _, s := range u.cont.Services {
		if s.Service == "core" {
			return s, true
		}
	}
	return api.ContainerState{}, false
}

// availableOf is the offered release; with the running helper known (helper), host_version names the release's system
// helper when it is above the running one, and its package counts in the size (the run downloads it, D-316).
func availableOf(v *verifiedRelease, channel string, helper *api.Info) []updateAvailableView {
	if v == nil {
		return []updateAvailableView{}
	}
	var size int64
	images := make([]releaseImageView, 0, len(v.M.Images))
	for _, im := range v.M.Images {
		size += im.Size
		images = append(images, releaseImageView{Service: im.Service, Digest: im.Digest}) // both checked by manifest validate
	}
	note := []rune(v.M.Notes)
	if len(note) > maxNoteRunes {
		note = note[:maxNoteRunes]
	}
	a := updateAvailableView{Component: softwareComponent, Version: v.M.Version, Channel: channel, Note: string(note), Images: images}
	if helper != nil && hostNewer(v.M, helper.HostVersion) {
		a.HostVersion = v.M.Host.Version
		if f := hostFileOf(v.M, helper.Arch); f != nil {
			size += f.Size
		}
	}
	a.SizeKB = size / 1024
	return []updateAvailableView{a}
}

// advisoriesOf maps index advisories (§4.1) to the page: low shows as medium (the page has three levels), published is
// the date of the index, and an advisory without fixed_in is left out (the page can only name a fixed version).
func advisoriesOf(idx *release.Index, running string) []advisoryView {
	out := []advisoryView{}
	if idx == nil {
		return out
	}
	for _, a := range idx.Advisories {
		sev := a.Severity
		switch sev {
		case "critical", "high", "medium":
		case "low":
			sev = "medium"
		default:
			continue
		}
		c, err := release.CompareVersions(running, a.FixedIn)
		if err != nil {
			continue
		}
		status := "fixed"
		if c < 0 {
			status = "affected"
		}
		out = append(out, advisoryView{ID: a.ID, Title: a.Title, Severity: sev, Published: idx.GeneratedAt.UTC().Format(time.DateOnly), FixedIn: a.FixedIn, Summary: a.Title, Status: status})
	}
	return out
}

// managedOf lists the pinned packages of the running release (bundled[]); update_pending when the offered release
// pins another version of the same one. Unknown running release: an empty list.
func managedOf(running *release.Manifest, offer *verifiedRelease) []managedView {
	out := []managedView{}
	if running == nil {
		return out
	}
	next := map[string]string{}
	if offer != nil {
		for _, b := range offer.M.Bundled {
			next[b.Service+"/"+b.Name] = b.Version
		}
	}
	seen := map[string]bool{}
	for _, b := range running.Bundled {
		if seen[b.Name] {
			continue
		}
		seen[b.Name] = true
		st := "ok"
		if v, ok := next[b.Service+"/"+b.Name]; ok && v != b.Version {
			st = "update_pending"
		}
		out = append(out, managedView{ID: b.Name, Name: b.Name, Version: b.Version, Status: st})
	}
	return out
}
