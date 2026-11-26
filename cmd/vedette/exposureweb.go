package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
)

// exposureWebScan is exposure's WebScanner over vedette-host's zap.baseline (S-EXP-2, exposure INV-24): ZAP's passive
// baseline in a one-shot container whose only way out is the page's address and port. exposureService sets it as cfg.Web. The host
// pins ZAP to page.IP, refuses a non-public address and re-checks ownership itself (for the box's own IP: the sighting its proof rests
// on, sent as proven_at, while it holds, else the box's own egress now; the TXT token for a domain, which is why the token goes
// along); the report comes back by a second read, at most MaxWebReport bytes.
//
// Every reason the step did not run that holds for the other pages too (no host, busy, still cleaning up, the image is being
// downloaded, the target is no longer the customer's, the fence could not be set up) is an *exposure.Unavailable with a sentence for the page; a run that
// failed on this page (ZAP without a report, the host's time limit) is a plain error, which exposure logs and shows as a failure.
type exposureWebScan struct {
	host  zapHost                                                    // nil: no vedette-host on this install
	token func(ctx context.Context, targetID string) (string, error) // the TXT token of a domain target
}

// zapHost is what the scan needs of the host client (*hostclient.Client).
type zapHost interface {
	ZapBaseline(ctx context.Context, args api.ZapBaselineArgs, requestID, actor string) (api.Run, error)
	ZapActive(ctx context.Context, args api.ZapActiveArgs, requestID, actor string) (api.Run, error)
	ZapStop(ctx context.Context, args api.ZapStopArgs, requestID, actor string) (api.Run, error)
	DownloadZapReport(ctx context.Context, reportID string) (io.ReadCloser, int64, error)
}

// zapPreparer is the host client's zap.prepare: the ZAP image fetched ahead of the first scan.
type zapPreparer interface {
	ZapPrepare(ctx context.Context, requestID, actor string) (api.Run, error)
}

var _ exposure.ImagePreparer = exposureWebScan{}

// PrepareImage is exposure's ImagePreparer: zap.prepare, which starts the download of the ZAP image on the host when it is not on the
// box (and answers at once). Without vedette-host there is nothing to fetch.
func (w exposureWebScan) PrepareImage(ctx context.Context) error {
	p, ok := w.host.(zapPreparer)
	if w.host == nil || !ok {
		return nil
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	run, err := p.ZapPrepare(ctx, id, "exposure")
	switch {
	case err != nil:
		return fmt.Errorf("exposure: zap.prepare: %w", err)
	case run.Status != api.StatusSucceeded:
		code := "command_failed"
		if run.Error != nil {
			code = run.Error.Code
		}
		return fmt.Errorf("exposure: zap.prepare %s: %s", run.Status, code)
	}
	return nil
}

// zapStopWait bounds zap.stop after a run exposure gave up on: the host cancels it and removes its container before it answers.
const zapStopWait = 3 * time.Minute

var _ exposure.ActiveWebScanner = exposureWebScan{}

// The reasons exposure shows after "Passive web scan (ZAP) did not run: ".
const (
	webNoHost         = "this install has no host helper (vedette-host), which runs ZAP's container: the passive web scan needs the appliance install."
	webBusy           = "a passive web scan was still running on this box (possibly this scan's previous page). Scan again later."
	webCleaningUp     = "the box is still cleaning up an earlier passive web scan (its container could not be removed yet; the box log has the reason). Scan again later."
	webPulling        = "the ZAP image (about 1.2 GB) is still downloading to this box; it will run in the next scan."
	webPullFailed     = "the download of the ZAP image from ghcr.io failed (the box may not reach ghcr.io, or its disk is full); the box is trying again, and the web scan will run in the next scan once it is there. The box log has the reason."
	webNotOwnIP       = "this box no longer reaches the Internet through %s, so its pages were not scanned."
	webNotOwnDom      = "%s no longer has its vedette-verify TXT record, so its pages were not scanned."
	webNotOwnAt       = "%s no longer has the vedette-verify TXT record of %s, so its pages were not scanned."
	webForeignAt      = "the token of %s is older than the value this box binds to it, so its record on %s cannot prove its web pages and they were not scanned. Select Check on its Ownership tab: it names the value to add next to the current one."
	webNameMoved      = "%s now points at other addresses than %s, the one the surface scan saw (a moved record, or a CDN or load balancer answering with other addresses), so this page was not scanned. Scan again to check it at its current address."
	webUnchecked      = "the box could not confirm that the target is still yours (the public IP services or DNS did not answer, or did not agree), so nothing was sent."
	webFence          = "the box could not set up the network fence that keeps ZAP to this one address and port, so ZAP was not started. The box log has the reason."
	webTypedNoScope   = "the proof of this IP could not be handed to the host, so its pages were not scanned."
	webTypedNotProved = "the proof of %s (its token file or reverse DNS name) is not found now by the host, so its pages were not scanned."
	webOldHost        = "the box's host helper (vedette-host) is older than this version of Vedette. Update the box, then scan again."
	// The domain fence of the host takes only the token bound to this box.
	webForeign  = "the Vedette host did not recognise this box's token for the domain, so nothing was sent. Update the box."
	webNoFenceK = "the Vedette host has no usable domain fence key, so nothing was sent. Its log says why."
)

var hostActorRE = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,54}$`)

func (w exposureWebScan) Baseline(ctx context.Context, t exposure.ScanTarget, page exposure.WebPage) (exposure.WebScan, error) {
	return w.run(ctx, t, page, false)
}

// Active is exposure's ActiveWebScanner over zap.active: the same page, args and checks as Baseline, and the disruptive rules when the
// step's mode allows them (exposure sets t.Mode.Disruptive only for the box's own proven IP in a person's scan). A run exposure gives
// up on (its time, or the scan was stopped) is stopped on the host (zap.stop) before this returns, so no ZAP outlives its scan.
func (w exposureWebScan) Active(ctx context.Context, t exposure.ScanTarget, page exposure.WebPage) (exposure.WebScan, error) {
	return w.run(ctx, t, page, true)
}

// zapArgsOf is the host args of one page of target t.
func (w exposureWebScan) zapArgsOf(ctx context.Context, t exposure.ScanTarget, page exposure.WebPage) (api.ZapBaselineArgs, error) {
	args := api.ZapBaselineArgs{URL: page.URL, Host: page.Host, IP: page.IP.String(), Port: page.Port}
	switch t.Kind {
	case exposure.KindIP:
		args.Kind = api.ZapKindIP
		switch {
		case t.Typed && (t.Domain == nil || t.Domain.Typed == nil): // a typed IP goes only with its proof, never as the box's own address
			return args, &exposure.Unavailable{Reason: orText(t.TypedWhy, webTypedNoScope)}
		case t.Typed:
			s := t.Domain.Typed
			args.TXTToken = t.Domain.Token
			args.Typed = &api.ExposureTyped{Method: s.Method, PTRName: s.PTRName, CoverDomain: s.CoverDomain, CoverToken: s.CoverToken, CoverProofAt: s.CoverProofAt}
		case !t.ProvenAt.IsZero() && provenPage(t, page): // the box's own IP: the sighting its proof rests on, which the host takes while it holds (90 days)
			args.ProvenAt = t.ProvenAt.UTC().Format(time.RFC3339)
		}
	case exposure.KindDomain:
		if p := t.Proof; p != nil { // The domain whose record proved the target at the gate (itself, or a parent covering it)
			args.Kind, args.Domain, args.TXTToken, args.ProofAt = api.ZapKindDomain, p.Domain, p.Token, p.ProofAt
			break
		}
		tok, err := w.token(ctx, t.ID)
		if err != nil {
			return args, fmt.Errorf("exposure web scan: reading the token of %s: %w", t.Value, err)
		}
		args.Kind, args.Domain, args.TXTToken = api.ZapKindDomain, t.Value, tok
	default:
		return args, fmt.Errorf("exposure web scan: target kind %q", t.Kind)
	}
	return args, nil
}

// run is one ZAP run of one page on the host, the passive baseline or the active scan.
func (w exposureWebScan) run(ctx context.Context, t exposure.ScanTarget, page exposure.WebPage, active bool) (exposure.WebScan, error) {
	if w.host == nil {
		return exposure.WebScan{}, &exposure.Unavailable{Reason: webNoHost}
	}
	args, err := w.zapArgsOf(ctx, t, page)
	if err != nil {
		return exposure.WebScan{}, err
	}
	id, err := newUUID()
	if err != nil {
		return exposure.WebScan{}, err
	}
	actor := "exposure"
	if hostActorRE.MatchString(t.User) {
		actor += ":" + t.User
	}
	var run api.Run
	if active {
		// The disruptive rules only for the box's own IP: the host refuses them on any other page as well.
		run, err = w.host.ZapActive(ctx, api.ZapActiveArgs{ZapBaselineArgs: args, Disruptive: t.Mode.Disruptive && args.Kind == api.ZapKindIP && args.Typed == nil}, id, actor)
	} else {
		run, err = w.host.ZapBaseline(ctx, args, id, actor)
	}
	if err != nil {
		var he *hostclient.Error
		switch {
		case ctx.Err() != nil: // exposure's limit of the page, or the run was stopped: ZAP is stopped on the host, and exposure tells the two apart
			w.stop(ctx, id, actor)
			return exposure.WebScan{}, ctx.Err()
		case errors.As(err, &he) && (he.Code == api.CodeUnknownCommand ||
			he.Code == api.CodeInvalidArgs && (t.Proof != nil && t.Proof.ProofAt != "" || t.Typed || args.ProvenAt != "")): // an older host refuses a proof it does not know

			return exposure.WebScan{}, &exposure.Unavailable{Reason: webOldHost}
		}
		return exposure.WebScan{}, err
	}
	if run.Status != api.StatusSucceeded {
		code, msg := "command_failed", ""
		if run.Error != nil {
			code, msg = run.Error.Code, run.Error.Message // the host's own fixed text (exit code and what it means), for the box log
		}
		if code == api.CodeZapNameMoved { // this page only: exposure goes on with the next page
			return exposure.WebScan{}, &exposure.PageSkipped{Reason: fmt.Sprintf(webNameMoved, page.Host, page.IP)}
		}
		if why := webReason(code, t, page); why != "" { // the image still downloading: on, not ready yet (the run says so)
			return exposure.WebScan{}, &exposure.Unavailable{Reason: why, Pending: code == api.CodeZapPulling || code == api.CodeZapPullFailed}
		}
		if msg != "" {
			code += ": " + msg
		}
		return exposure.WebScan{}, fmt.Errorf("exposure web scan: %s %s: %s", run.Command, run.Status, code)
	}
	var reportID string
	cut := false
	var disruptiveRules []string
	if active {
		res, err := hostclient.ResultOf[api.ZapActiveResult](run)
		if err != nil {
			return exposure.WebScan{}, err
		}
		reportID, cut = res.ReportID, res.CutShort
		for _, r := range res.DisruptiveRules {
			disruptiveRules = append(disruptiveRules, strconv.Itoa(r))
		}
	} else {
		res, err := hostclient.ResultOf[api.ZapBaselineResult](run)
		if err != nil {
			return exposure.WebScan{}, err
		}
		reportID = res.ReportID
	}
	body, _, err := w.host.DownloadZapReport(ctx, reportID)
	if err != nil {
		return exposure.WebScan{}, fmt.Errorf("exposure web scan: reading the report: %w", err)
	}
	defer func() { _ = body.Close() }()
	// One byte over the limit is kept, so that ParseZAPReport refuses a report that is too big instead of reading a cut one.
	b, err := io.ReadAll(io.LimitReader(body, exposure.MaxWebReport+1))
	if err != nil {
		return exposure.WebScan{}, fmt.Errorf("exposure web scan: reading the report: %w", err)
	}
	return exposure.WebScan{Report: b, CutShort: cut, DisruptiveRules: disruptiveRules}, nil
}

// stop stops the ZAP run of request runID on the host when exposure gave up on it (the scan was stopped, or the page's time ran
// out): the host cancels that run and removes its container and fence before it answers, or, when the run has not started yet,
// keeps the stop so it never starts. A run of another scan is left alone. A failure is logged by the host and cleaned up by its next
// run; it never holds the scan.
func (w exposureWebScan) stop(ctx context.Context, runID, actor string) {
	id, err := newUUID()
	if err != nil {
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), zapStopWait)
	defer cancel()
	_, _ = w.host.ZapStop(sctx, api.ZapStopArgs{RequestID: runID}, id, actor)
}

// provenPage says whether the target's proof is about the page's address: the proof is a sighting of the target's own IP, so it goes
// to the host only with a page on exactly that address, never with a page on another one.
func provenPage(t exposure.ScanTarget, page exposure.WebPage) bool {
	ip, err := netip.ParseAddr(t.Value)
	return err == nil && ip.Unmap() == page.IP.Unmap()
}

// webReason is the sentence of a run that ended without a report for a reason that holds for the other pages too; "" for a failure
// of this page.
func webReason(code string, t exposure.ScanTarget, page exposure.WebPage) string {
	switch code {
	case api.CodeBusy:
		return webBusy
	case api.CodeZapCleaningUp:
		return webCleaningUp
	case api.CodeZapPulling:
		return webPulling
	case api.CodeZapPullFailed:
		return webPullFailed
	case api.CodeTargetNotOwned:
		if t.Kind == exposure.KindDomain {
			if p := t.Proof; p != nil && p.ProofAt != "" { // Its record on the parent name is the one that went
				return fmt.Sprintf(webNotOwnAt, p.ProofAt, p.Domain)
			}
			return fmt.Sprintf(webNotOwnDom, t.Value)
		}
		if t.Typed {
			return fmt.Sprintf(webTypedNotProved, page.IP)
		}
		return fmt.Sprintf(webNotOwnIP, page.IP)
	case api.CodeOwnershipUnchecked:
		return webUnchecked
	case api.CodeTokenForeign:
		if p := t.Proof; p != nil && p.ProofAt != "" { // An older target's own token cannot prove pages through a parent name
			return fmt.Sprintf(webForeignAt, p.Domain, p.ProofAt)
		}
		return webForeign
	case api.CodeFenceUnavailable:
		return webNoFenceK
	case api.CodeZapFenceFailed:
		return webFence
	}
	return ""
}

// exposureWebFor builds the scanner for exposureService: the host client when this install has vedette-host, and the target's token
// read from exposure itself at scan time.
func exposureWebFor(d deps) exposureWebScan {
	w := exposureWebScan{token: func(ctx context.Context, id string) (string, error) {
		v, err := exposureService(d).Target(ctx, id) // called at scan time, after exposureService returned
		return v.Token, err
	}}
	if d.HostSocket != "" {
		c := hostclient.New(d.HostSocket)
		w.host = c
	}
	return w
}

func orText(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
