package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
)

// exposureWebScan is exposure's WebScanner over vedette-host's zap.baseline (S-EXP-2, exposure INV-24, D-562, D-521): ZAP's passive
// baseline in a one-shot container whose only way out is the page's address and port. exposureService sets it as cfg.Web. The host
// pins ZAP to page.IP, refuses a non-public address and re-checks ownership itself (the box's own egress for an IP target, the TXT
// token for a domain, which is why the token goes along); the report comes back by a second read, at most MaxWebReport bytes.
//
// Every reason the step did not run that holds for the other pages too (no host, busy, still cleaning up, the image is being
// downloaded, the target is no longer the customer's, the fence could not be set up) is an *exposure.Unavailable with a sentence for the page; a run that
// failed on this page (ZAP without a report, the host's time limit) is a plain error, which exposure logs and shows as a failure.
type exposureWebScan struct {
	host  zapHost                                                    // nil: no vedette-host on this install
	token func(ctx context.Context, targetID string) (string, error) // the TXT token of a domain target
	// fence is the domain's box-bound token (exposure.token, D-591): the host's own fence takes no other token for kind domain.
	fence func(ctx context.Context, domain string) (string, error)
}

// zapHost is what the scan needs of the host client (*hostclient.Client).
type zapHost interface {
	ZapBaseline(ctx context.Context, args api.ZapBaselineArgs, requestID, actor string) (api.Run, error)
	DownloadZapReport(ctx context.Context, reportID string) (io.ReadCloser, int64, error)
}

// The reasons exposure shows after "Passive web scan (ZAP) did not run: ".
const (
	webNoHost     = "this install has no host helper (vedette-host), which runs ZAP's container: the passive web scan needs the appliance install."
	webBusy       = "a passive web scan was still running on this box (possibly this scan's previous page). Scan again later."
	webCleaningUp = "the box is still cleaning up an earlier passive web scan (its container could not be removed yet; the box log has the reason). Scan again later."
	webPulling    = "the ZAP image (about 1.2 GB) is being downloaded to this box. Scan again in a few minutes."
	webPullFailed = "the download of the ZAP image from ghcr.io failed (the box may not reach ghcr.io, or its disk is full). Scan again to try once more; the box log has the reason."
	webNotOwnIP   = "this box no longer reaches the Internet through %s, so its pages were not scanned."
	webNotOwnDom  = "%s no longer has its vedette-verify TXT record, so its pages were not scanned."
	webNameMoved  = "%s now points at other addresses than %s, the one the surface scan saw (a moved record, or a CDN or load balancer answering with other addresses), so this page was not scanned. Scan again to check it at its current address."
	webUnchecked  = "the box could not confirm that the target is still yours (the public IP services or DNS did not answer, or did not agree), so nothing was sent."
	webFence      = "the box could not set up the network fence that keeps ZAP to this one address and port, so ZAP was not started. The box log has the reason."
	webOldHost    = "the box's host helper (vedette-host) is older than this version of Vedette. Update the box, then scan again."
	// D-591: the domain fence of the host takes only the token bound to this box.
	webNoToken  = "the Vedette host did not give this domain's fence token (it may be older than this version of Vedette, or its fence key is not usable), so nothing was sent. Update the box; its log says why." //nolint:gosec // a sentence for the page, not a credential
	webNewTXT   = "%s was verified before this box's domain fence: its pages are scanned once the domain also has the TXT record vedette-verify=%s (add it and keep the current one), so nothing was sent."
	webForeign  = "the Vedette host did not recognise this box's token for the domain, so nothing was sent. Update the box."
	webNoFenceK = "the Vedette host has no usable domain fence key, so nothing was sent. Its log says why."
)

var hostActorRE = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,54}$`)

func (w exposureWebScan) Baseline(ctx context.Context, t exposure.ScanTarget, page exposure.WebPage) (exposure.WebScan, error) {
	if w.host == nil {
		return exposure.WebScan{}, &exposure.Unavailable{Reason: webNoHost}
	}
	args := api.ZapBaselineArgs{URL: page.URL, Host: page.Host, IP: page.IP.String(), Port: page.Port}
	oldToken := false // the domain's stored TXT value is not the box-bound one (verified before D-591)
	switch t.Kind {
	case exposure.KindIP:
		args.Kind = api.ZapKindIP
	case exposure.KindDomain:
		tok, err := w.token(ctx, t.ID)
		if err != nil {
			return exposure.WebScan{}, fmt.Errorf("exposure web scan: reading the token of %s: %w", t.Value, err)
		}
		if w.fence != nil { // D-591: the box-bound token, which the host derives from its own key
			box, err := w.fence(ctx, t.Value)
			if err != nil {
				if ctx.Err() != nil {
					return exposure.WebScan{}, ctx.Err()
				}
				return exposure.WebScan{}, &exposure.Unavailable{Reason: webNoToken}
			}
			if box != tok {
				oldToken = true
			}
			tok = box
		}
		args.Kind, args.Domain, args.TXTToken = api.ZapKindDomain, t.Value, tok
	default:
		return exposure.WebScan{}, fmt.Errorf("exposure web scan: target kind %q", t.Kind)
	}
	id, err := newUUID()
	if err != nil {
		return exposure.WebScan{}, err
	}
	actor := "exposure"
	if hostActorRE.MatchString(t.User) {
		actor += ":" + t.User
	}
	run, err := w.host.ZapBaseline(ctx, args, id, actor)
	if err != nil {
		var he *hostclient.Error
		switch {
		case ctx.Err() != nil: // exposure's 8 minutes, or the run was stopped: exposure tells them apart
			return exposure.WebScan{}, ctx.Err()
		case errors.As(err, &he) && he.Code == api.CodeUnknownCommand:
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
		if code == api.CodeTargetNotOwned && oldToken { // D-591: verified before the fence: say which TXT value the box needs now
			return exposure.WebScan{}, &exposure.Unavailable{Reason: fmt.Sprintf(webNewTXT, t.Value, args.TXTToken)}
		}
		if why := webReason(code, t, page); why != "" {
			return exposure.WebScan{}, &exposure.Unavailable{Reason: why}
		}
		if msg != "" {
			code += ": " + msg
		}
		return exposure.WebScan{}, fmt.Errorf("exposure web scan: zap.baseline %s: %s", run.Status, code)
	}
	res, err := hostclient.ResultOf[api.ZapBaselineResult](run)
	if err != nil {
		return exposure.WebScan{}, err
	}
	body, _, err := w.host.DownloadZapReport(ctx, res.ReportID)
	if err != nil {
		return exposure.WebScan{}, fmt.Errorf("exposure web scan: reading the report: %w", err)
	}
	defer func() { _ = body.Close() }()
	// One byte over the limit is kept, so that ParseZAPReport refuses a report that is too big instead of reading a cut one.
	b, err := io.ReadAll(io.LimitReader(body, exposure.MaxWebReport+1))
	if err != nil {
		return exposure.WebScan{}, fmt.Errorf("exposure web scan: reading the report: %w", err)
	}
	return exposure.WebScan{Report: b}, nil
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
			return fmt.Sprintf(webNotOwnDom, t.Value)
		}
		return fmt.Sprintf(webNotOwnIP, page.IP)
	case api.CodeOwnershipUnchecked:
		return webUnchecked
	case api.CodeTokenForeign:
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
		w.fence = hostDomainFence{host: c}.Token
	}
	return w
}
