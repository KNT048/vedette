package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
)

// The nuclei job (D-125, D-136, sensor-protocol.md 6.4). The worker is the last fence: a job names template ids and the hash of
// a pack; everything that reaches the command line comes from the pack index baked into the image, which is checked against the
// files, and from nucleiargv, whose Validate runs once more inside core/exec.

const (
	// maxTemplateFile bounds the bytes hashed per template file: a template is a few KiB; a file over this is not one.
	maxTemplateFile = 1 << 20
	// maxPackEntries bounds the walk over the pack directory.
	maxPackEntries = 100_000
)

type nucleiConfig struct {
	on             bool
	index, tmplDir string
	runHome        string // HOME of a run: emptied before every run
}

// newNuclei returns the allowlist entries of nuclei (none when the worker is not set up for it) and its configuration.
func newNuclei(c Config) ([]exec.Binary, nucleiConfig, error) {
	if c.NucleiPath == "" {
		return nil, nucleiConfig{}, nil
	}
	if !filepath.IsAbs(c.NucleiIndex) || !filepath.IsAbs(c.NucleiHome) {
		return nil, nucleiConfig{}, errors.New("nuclei needs an absolute index path and an absolute home directory")
	}
	nc := nucleiConfig{on: true, index: c.NucleiIndex, tmplDir: c.TemplatesDir, runHome: filepath.Join(c.NucleiHome, "run")}
	if nc.tmplDir == "" {
		nc.tmplDir = nucleiargv.TemplatesDir
	}
	probeHome := filepath.Join(c.NucleiHome, "probe")
	for _, d := range []string{c.NucleiHome, nc.runHome, probeHome} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, nucleiConfig{}, fmt.Errorf("nuclei home: %w", err)
		}
	}
	return []exec.Binary{
		{Name: nucleiBin, Path: c.NucleiPath, Validate: nucleiargv.Validate, MaxOutput: nucleiargv.MaxOutput, MaxStderr: nucleiout.MaxErrorLog, Env: []string{"HOME=" + nc.runHome}}, // stderr is never posted: it holds nuclei's error log (-elog), counted per target into host_errors (D-165); at most 1 MiB is kept in memory, and it cannot make a run "truncated"
		{Name: nucleiVer, Path: c.NucleiPath, Validate: validNucleiVersionArgs, MaxOutput: 64 << 10, Env: []string{"HOME=" + probeHome}},
	}, nc, nil
}

func validNucleiVersionArgs(args []string) error {
	if len(args) != 2 || args[0] != "-version" || args[1] != "-duc" {
		return errors.New("only -version -duc")
	}
	return nil
}

// refusal is a result the worker posts for a job it will not run.
func refusal(reason string) *sensorlink.JobResult {
	return &sensorlink.JobResult{Status: "refused", Reason: reason, ExitCode: -1}
}

// placeholderPaths stand in for template files while only the rest of the job is checked.
func placeholderPaths(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "t" + strconv.Itoa(i) + ".yaml"
	}
	return out
}

func targetsOf(nj *sensorlink.NucleiJob) []nucleiargv.Target {
	out := make([]nucleiargv.Target, len(nj.Targets))
	for i, t := range nj.Targets {
		out[i] = nucleiargv.Target{Host: t.Host, Port: t.Port, Scheme: t.Scheme}
	}
	return out
}

// nucleiArgv is the job grammar of sensor-protocol.md 6.4, checked here again and not trusted from core: the scope, the counts,
// the targets (canonical private IPv4 only, D-136 (4); scope own_ip: exactly one public IPv4 at nucleiargv.OwnIPRate, D-520), the
// rate and the host-error limit by nucleiargv, the timeout, the pack by version and hash, every template id by the index (an
// own_ip job: none of a class of nucleiargv.OwnIPForbiddenTags). The file of every template is hashed against the index before anything
// starts. It returns the argv, or the result to post when the job is refused.
func (w *Worker) nucleiArgv(j sensorlink.Job) ([]string, *sensorlink.JobResult, error) {
	nj := j.Nuclei
	if nj == nil || j.TimeoutS < 1 || j.TimeoutS > MaxNucleiTimeout {
		return nil, refusal("invalid_job"), fmt.Errorf("a nuclei job needs its fields and a timeout of 1..%d s", MaxNucleiTimeout)
	}
	targets := targetsOf(nj)
	scope := nj.Scope
	switch { // D-591: a domain_ip job is the full own_ip shape (one public target) with its fence fields; no other job carries any
	case nj.Scope == sensorlink.ScopeDomainIP && nj.Domain != nil && nj.Depth == nucleiargv.DepthFull:
		scope = nucleiargv.ScopeOwnIP
	case nj.Scope != sensorlink.ScopeDomainIP && nj.Domain == nil:
	default:
		return nil, refusal("invalid_job"), fmt.Errorf("scope %.20q with depth %.20q is not a shape of a job", nj.Scope, nj.Depth)
	}
	job := func(paths []string) nucleiargv.Job {
		return nucleiargv.Job{Templates: paths, Targets: targets, Rate: nj.Rate, MaxHostErrors: nj.MaxHostErrors, Scope: scope, Depth: nj.Depth, Disruptive: nj.Disruptive}
	}
	if _, err := nucleiargv.Build(job(placeholderPaths(len(nj.Templates)))); err != nil {
		return nil, refusal("invalid_job"), err
	}
	full := nj.Depth == nucleiargv.DepthFull // Build accepted the depth only with scope own_ip
	ix, err := readIndex(w.nucleiCfg.index)
	if err != nil {
		return nil, refusal("pack_invalid"), err
	}
	if nj.Pack.Version != ix.Version || nj.Pack.SHA256 != ix.SHA256 {
		return nil, refusal("pack_mismatch"), fmt.Errorf("the job was planned with pack %s, the image holds %s", nj.Pack.Version, ix.Version)
	}
	paths := make([]string, len(nj.Templates))
	chosen := make([]pack.Template, len(nj.Templates))
	for i, id := range nj.Templates {
		tp, ok := ix.Get(id)
		if !ok {
			return nil, refusal("invalid_job"), fmt.Errorf("template %.100q is not in the pack", id)
		}
		chosen[i], paths[i] = tp, tp.Path
		if !tp.RunsAt(full, nj.Disruptive) { // the image's own index decides the set, never core (D-527): KEV unless full
			return nil, refusal("invalid_job"), fmt.Errorf("template %.100q is not in a set of the pack a job of depth %q (disruptive %t) may run", id, nj.Depth, nj.Disruptive)
		}
		if !full && nj.Scope == nucleiargv.ScopeOwnIP && !tp.OwnIP { // the image's own index decides, never core (D-520)
			return nil, refusal("invalid_job"), fmt.Errorf("template %.100q is not marked for the own_ip scope in the pack", id)
		}
	}
	if err := checkTree(w.nucleiCfg.tmplDir); err != nil {
		return nil, refusal("pack_invalid"), err
	}
	for _, t := range chosen {
		body, err := checkFile(w.nucleiCfg.tmplDir, t)
		if err != nil {
			return nil, refusal("pack_invalid"), err
		}
		if err := pack.NoChangeText(body); err != nil { // D-528: no write, upload or other host, in every job (the builder kept only files that pass)
			return nil, refusal("invalid_job"), fmt.Errorf("template %.100q may change the target or reach another host: %w", t.ID, err)
		}
		switch {
		case full: // the last fence of D-527: no out-of-band interaction, read from the file itself
			if err := pack.FullText(body, t.Tech()); err != nil {
				return nil, refusal("invalid_job"), fmt.Errorf("template %.100q may not run at full depth: %w", t.ID, err)
			}
		case nj.Scope == nucleiargv.ScopeOwnIP: // the last fence: the worker reads the file itself (D-520)
			if err := pack.OwnIPText(body); err != nil {
				return nil, refusal("invalid_job"), fmt.Errorf("template %.100q may not run on a public IP: %w", t.ID, err)
			}
		}
	}
	argv, err := nucleiargv.Build(job(paths))
	if err == nil {
		err = nucleiargv.Validate(argv)
	}
	if err != nil {
		return nil, refusal("invalid_job"), err
	}
	return argv, nil, nil
}

// readIndex reads and checks the index baked into the image: a regular file (not a link), at most pack.MaxSize.
func readIndex(path string) (*pack.Index, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("the pack index: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > pack.MaxSize {
		return nil, errors.New("the pack index is not a regular file of a sane size")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the index path is the worker's own configuration, and it was Lstat-ed as a regular file above
	if err != nil {
		return nil, fmt.Errorf("the pack index: %w", err)
	}
	return pack.Parse(raw)
}

// checkTree refuses a pack that holds anything but directories and regular files, anywhere: a symlink could lead a template's
// payload reference out of the pack (to a file of the image, or a mounted secret), and a device or a socket is not a template.
// It walks with Lstat semantics (WalkDir never follows a link, and a link as the root is itself refused).
func checkTree(dir string) error {
	n := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if n++; n > maxPackEntries {
			return errors.New("the pack has too many entries")
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file or a directory", p)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("the pack: %w", err)
	}
	return nil
}

// checkFile reads one template file with Lstat first and accepts a regular file only, compares its hash with the index and
// returns its bytes (at most maxTemplateFile).
func checkFile(dir string, t pack.Template) ([]byte, error) {
	root, err := os.OpenRoot(dir) // Open below it cannot leave the directory by a link, whatever the file system holds
	if err != nil {
		return nil, fmt.Errorf("the pack: %w", err)
	}
	defer func() { _ = root.Close() }()
	fi, err := root.Lstat(t.Path)
	if err != nil {
		return nil, fmt.Errorf("template %.100q: %w", t.ID, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxTemplateFile {
		return nil, fmt.Errorf("template %.100q is not a regular file of a sane size", t.ID)
	}
	f, err := root.Open(t.Path)
	if err != nil {
		return nil, fmt.Errorf("template %.100q: %w", t.ID, err)
	}
	defer func() { _ = f.Close() }()
	body, err := io.ReadAll(io.LimitReader(f, maxTemplateFile+1))
	if err != nil {
		return nil, fmt.Errorf("template %.100q: %w", t.ID, err)
	}
	if sum := sha256.Sum256(body); len(body) > maxTemplateFile || hex.EncodeToString(sum[:]) != t.SHA256 {
		return nil, fmt.Errorf("template %.100q does not match its hash in the index", t.ID)
	}
	return body, nil
}

// freshHome empties nuclei's HOME (a directory on a tmpfs): nothing a run, or an image layer, left in it is read.
func (w *Worker) freshHome() error {
	if err := os.RemoveAll(w.nucleiCfg.runHome); err != nil {
		return err
	}
	return os.Mkdir(w.nucleiCfg.runHome, 0o700)
}

// executeNuclei re-checks a nuclei job, runs the pinned nuclei and returns the result to post. The environment of the program
// is core/exec's (PATH, LANG and the HOME above, never the parent's: no proxy, no cloud upload key, D-136 (5)); its stderr is
// never posted.
func (w *Worker) executeNuclei(ctx, jctx context.Context, cur *activeJob) *sensorlink.JobResult {
	if !w.nucleiCfg.on {
		return &sensorlink.JobResult{Status: "failed", Reason: "nuclei_missing", ExitCode: -1}
	}
	argv, res, err := w.nucleiArgv(cur.job)
	if res != nil {
		w.log.ErrorContext(ctx, "sensor_active_job_refused", "id", cur.job.ID, "reason", res.Reason, "error", err) // core and worker disagree, or the image is not what core planned with
		return res
	}
	if context.Cause(jctx) != nil {
		return stopped()
	}
	rctx, cancel := context.WithTimeout(jctx, time.Duration(cur.job.TimeoutS)*time.Second)
	defer cancel()
	if cur.job.Nuclei.Scope == sensorlink.ScopeDomainIP { // nucleiArgv proved it is a full job with one public target: the domain fence (D-591)
		if res := w.domainFence(ctx, rctx, jctx, cur, w.domainJob(cur.job), "nuclei"); res != nil {
			return res
		}
	}
	if cur.job.Nuclei.Scope == nucleiargv.ScopeOwnIP { // nucleiArgv proved it has one public target: the own-IP fence of D-514, D-520
		if ok, reason := w.ownIP(rctx, netip.MustParseAddr(cur.job.Nuclei.Targets[0].Host)); !ok {
			if context.Cause(jctx) != nil {
				return stopped()
			}
			w.log.WarnContext(ctx, "sensor_active_own_ip_nuclei_job_refused", "id", cur.job.ID, "reason", reason)
			return refusal(reason)
		}
	}
	if err := w.freshHome(); err != nil {
		w.log.WarnContext(ctx, "sensor_active_exec_failed", "id", cur.job.ID, "error", err)
		return &sensorlink.JobResult{Status: "failed", Reason: "exec_failed", ExitCode: -1}
	}
	out, err := w.runner.Run(rctx, nucleiBin, argv, nil)
	res = w.finish(ctx, jctx, rctx, cur, out, err, "nuclei_missing", (*sensorlink.JobResult).SetJSONL)
	if res.Status == "done" {
		res.HostErrors = hostErrors(out.Stderr, cur.job.Nuclei)
	}
	return res
}

// hostErrors is what the result says about targets that stopped answering (INV-6, D-165): the timeouts per target that
// nuclei's error log (-elog on stderr) holds, counted by nucleiout.ParseHostErrors. Stderr itself is never posted.
func hostErrors(stderr []byte, nj *sensorlink.NucleiJob) []sensorlink.HostError {
	targets := make([]string, len(nj.Targets))
	for i, t := range nj.Targets {
		targets[i] = t.Host + ":" + strconv.Itoa(t.Port)
	}
	var out []sensorlink.HostError
	for _, h := range nucleiout.ParseHostErrors(stderr, targets, nj.MaxHostErrors) {
		out = append(out, sensorlink.HostError{Target: h.Target, Errors: h.Errors, Unreachable: h.Unreachable})
	}
	return out
}

// ---- heartbeat ----

var nucleiVersionRE = regexp.MustCompile(`(?m)Version: (v?[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z._+-]{0,16})\s*$`)

// nucleiStatus is the nuclei part of the heartbeat: whether `nuclei -version -duc` runs and which version it prints (nuclei
// logs to stderr), and the version and hash of the pack index in the image ("" when there is none or it does not check out).
func (w *Worker) nucleiStatus(ctx context.Context) sensorlink.HeartbeatNuclei {
	if !w.nucleiCfg.on {
		return sensorlink.HeartbeatNuclei{}
	}
	hb := sensorlink.HeartbeatNuclei{OwnIP: w.egress != nil, Full: w.egress != nil} // D-520, D-527: own_ip jobs (full ones too) only behind the own-IP fence; without its checker every one would be refused
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if res, err := w.runner.Run(rctx, nucleiVer, []string{"-version", "-duc"}, nil); err == nil {
		hb.Present = true
		if m := nucleiVersionRE.FindStringSubmatch(strings.ReplaceAll(string(res.Stdout)+"\n"+string(res.Stderr), "\r", "")); m != nil && validVersion(m[1]) {
			hb.Version = m[1]
		}
	}
	if ix, err := readIndex(w.nucleiCfg.index); err == nil {
		hb.Pack = sensorlink.HeartbeatPack{Version: ix.Version, SHA256: ix.SHA256}
	}
	return hb
}
