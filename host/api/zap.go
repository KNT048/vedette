package api

// zap.baseline (docs/specs/host-api.md §6.15, D-521): ZAP's passive baseline scan of one page of a verified exposure target, in a
// one-shot container on the network vedette-zap whose only way out is the one address and port of the page.

// CmdZapBaseline is the name of the command.
const CmdZapBaseline = "zap.baseline"

// Kinds of the target a page belongs to (exposure's target kinds).
const (
	ZapKindIP     = "ip"
	ZapKindDomain = "domain"
)

// Refusal and failure codes of zap.baseline (spec §6.15).
const (
	// CodeZapPulling: the ZAP image is not on the box; the host started its download (or one is running). Ask again later.
	CodeZapPulling = "zap_image_pulling"
	// CodeZapPullFailed: the last download of the ZAP image failed; the next call tries again.
	CodeZapPullFailed = "zap_image_pull_failed"
	// CodeTargetNotOwned: the host's own re-check says the page is not the box's own address (IP target), or the domain no longer
	// has its TXT token (domain target).
	CodeTargetNotOwned = "target_not_owned"
	// CodeZapCleaningUp: an earlier run's container could not be proven gone yet, so its fence is kept and no new run starts.
	CodeZapCleaningUp = "zap_cleaning_up"
	// CodeZapNameMoved: the page's name no longer resolves to the IP ZAP would be pinned to (a moved record, or a CDN or load balancer
	// that answers with another subset of its addresses). This page only: the domain's TXT record was there.
	CodeZapNameMoved = "zap_name_moved"
	// CodeOwnershipUnchecked: the host could not re-check (the public-IP services or DNS did not answer), so nothing was sent.
	CodeOwnershipUnchecked = "ownership_unchecked"
	// CodeZapFenceFailed: the network vedette-zap or its egress rule could not be set up and proven, so ZAP was not started.
	CodeZapFenceFailed = "zap_fence_failed"
	// CodeZapFailed: ZAP ran but did not end with a report (exit 3 or another code, or no report file), or the host could not
	// prepare the run's work folder.
	CodeZapFailed = "zap_failed"
	// CodeZapTimedOut: ZAP did not finish within the host's bound; the container was removed.
	CodeZapTimedOut = "zap_timed_out"
	// CodeZapReportTooLarge: the report is bigger than MaxZapReport.
	CodeZapReportTooLarge = "zap_report_too_large"
	// CodeZapReportUnknown: GET /v1/zap/{id}/content of a report the host no longer keeps.
	CodeZapReportUnknown = "zap_report_unknown"
)

// MaxZapReport is the largest report the host keeps and serves (exposure.MaxWebReport).
const MaxZapReport = 4 << 20

// ZapBaselineArgs are the args of zap.baseline. URL is http(s)://Host[:Port]/; IP is the public IPv4 address ZAP is pinned to and
// Port its TCP port. Kind ip: Host is the IP itself, and the host checks that the box leaves the Internet through it. Kind domain:
// Host is Domain or a name under it, and the host checks that Domain still has the TXT record vedette-verify=<TXTToken> and that Host
// resolves to IP.
type ZapBaselineArgs struct {
	URL      string `json:"url"`
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Kind     string `json:"kind"`
	Domain   string `json:"domain,omitempty"`
	TXTToken string `json:"txt_token,omitempty"`
}

// ZapBaselineResult is the result of a zap.baseline that produced a report: zap-baseline.py's exit code (0 no rule matched, 1 a FAIL
// rule, 2 a WARN rule) and the id of the report, served by GET /v1/zap/{report_id}/content until the next run or the next start of the host.
type ZapBaselineResult struct {
	ReportID string `json:"report_id"`
	Size     int64  `json:"size"`
	ExitCode int    `json:"exit_code"`
}
