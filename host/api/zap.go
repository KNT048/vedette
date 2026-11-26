package api

// zap.baseline (docs/specs/host-api.md §6.15): ZAP's passive baseline scan of one page of a verified exposure target, in a
// one-shot container on the network vedette-zap whose only way out is the one address and port of the page.

// CmdZapBaseline is the name of the command.
const CmdZapBaseline = "zap.baseline"

// CmdZapActive is ZAP's active scan of one page (§6.15a): the same page, checks, fence and container as zap.baseline, with ZAP's
// Automation Framework plan the host writes itself (one context anchored to the page's scheme, host and port, a bounded spider, the
// active scan rules of the host's rule split). Disruptive turns on the rules that may crash a service or change data heavily, and
// form posting; the host takes it only for the box's own IP (kind ip, not a typed IP).
const CmdZapActive = "zap.active"

// CmdZapStop stops one ZAP run (zap.baseline or zap.active), named by the request id it was sent with (ZapStopArgs): when it runs,
// its context is cancelled, the container removed and proven gone, and the fence deleted, before the command answers; when it has
// not started yet, the host remembers the stop and that run refuses to start. A run of another request id is left alone.
const CmdZapStop = "zap.stop"

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
	// CodeZapStopped: zap.stop stopped this run; the container was removed.
	CodeZapStopped = "zap_stopped"
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
	// ProofAt: the name above Domain (the zone apex or a parent name) where the token of Domain sits; "" = on Domain. Host may then
	// be any name under ProofAt, not only under Domain. Only with the token bound to this box for Domain (the domain fence), and
	// between Domain and its registered domain.
	ProofAt string `json:"proof_at,omitempty"`
	// Typed, with Kind ip, says the IP is one a person typed in: TXTToken is the box-bound token of the IP and the host checks the IP's
	// own proof (the token file, or reverse DNS) itself before ZAP starts.
	Typed *ExposureTyped `json:"typed,omitempty"`
	// ProvenAt, with Kind ip and no Typed (the box's own public IP), is the latest sighting of IP as the box's egress, RFC 3339, that
	// core's gate took the address on: the address stays the box's own for 90 days from it (egressip.ProofHolds), also while the box
	// goes out through another line, and the host then takes the page on it instead of its own sighting. Empty: the host's sighting
	// right before the run decides, as before.
	ProvenAt string `json:"proven_at,omitempty"`
}

// ZapBaselineResult is the result of a zap.baseline that produced a report: zap-baseline.py's exit code (0 no rule matched, 1 a FAIL
// rule, 2 a WARN rule) and the id of the report, served by GET /v1/zap/{report_id}/content until the next run or the next start of the host.
type ZapBaselineResult struct {
	ReportID string `json:"report_id"`
	Size     int64  `json:"size"`
	ExitCode int    `json:"exit_code"`
}

// ZapActiveArgs are the args of zap.active: the page as in zap.baseline, and whether the disruptive rules run.
type ZapActiveArgs struct {
	ZapBaselineArgs
	// Disruptive runs the disruptive rules of the rule split (denial of service, and checks that may change data heavily) and lets the
	// spider post forms. Only for kind ip without Typed: the box's own public IP, proven by the host's own check right before the run.
	Disruptive bool `json:"disruptive,omitempty"`
}

// ZapActiveResult is the result of a zap.active that produced a report: the Automation Framework's exit code (0 no error or
// warning, 1 a job reported an error, 2 a warning) and the report as for zap.baseline. CutShort says the active scan reached its time
// limit (or was ended by ZAP) before it finished: the report holds what it found until then.
type ZapActiveResult struct {
	ReportID string `json:"report_id"`
	Size     int64  `json:"size"`
	ExitCode int    `json:"exit_code"`
	CutShort bool   `json:"cut_short"`
	// DisruptiveRules are the ZAP plugin ids of the host's rule split that a run without Disruptive does not run as a run with it
	// does (the disruptive rules, and SQL Injection, whose stronger payloads need Disruptive): an alert of one of them found with
	// Disruptive is closed by core only after another run with Disruptive. The same list for every run of a host version.
	DisruptiveRules []int `json:"disruptive_rules"`
}

// ZapStopArgs are the args of zap.stop: the X-Request-Id (a UUID v4) of the zap.baseline or zap.active run to stop.
type ZapStopArgs struct {
	RequestID string `json:"request_id"`
}

// ZapStopResult says whether zap.stop found the run running and stopped it (false: the run had not started, and will refuse to, or
// had already ended).
type ZapStopResult struct {
	Stopped bool `json:"stopped"`
}
