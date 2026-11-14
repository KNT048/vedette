package worker

import (
	"context"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// The domain fence of domain_ip jobs (D-591, FULL-5 slice 2, plan 2026-11-14 §5): an nmap job of a full shape or a nuclei job of depth
// full whose one public target is not the box's own egress, sent because a name under a verified domain resolves to it. Right before
// the tool starts the worker checks on its own (core/domainfence): the grammar, that the token is the one this box's fence key gives
// for the domain (core's word is not taken: a TXT value is public), that the domain's TXT record carries it now, that the name resolves
// to the address now, and for a disruptive job that the name's canonical name stays inside the domain. A yes stands 5 minutes per
// (domain, name, ip); a deep nmap checks again every domainfence.Recheck while it runs (review r1 L2) and the first answer that is not
// a yes kills it and drops its output. Every refusal and stop is a log line of the worker with the CNAME chain (the executor's fence
// log), and nothing is sent.

// domainJob is the fence's view of a domain_ip job (its fields were checked by argvOf or nucleiArgv: one target, Domain set).
func (w *Worker) domainJob(j sensorlink.Job) domainfence.Job {
	var d sensorlink.DomainScope
	target, disruptive := "", false
	switch {
	case j.Nuclei != nil:
		if j.Nuclei.Domain != nil {
			d = *j.Nuclei.Domain
		}
		if len(j.Nuclei.Targets) == 1 {
			target = j.Nuclei.Targets[0].Host
		}
		disruptive = j.Nuclei.Disruptive
	default:
		if j.Domain != nil {
			d = *j.Domain
		}
		if len(j.Targets) == 1 {
			target = j.Targets[0]
		}
		kind, _ := nmapargv.KindOf(j.Shape)
		disruptive = kind == nmapargv.ExternalDisruptive
	}
	ip, _ := netip.ParseAddr(target) // a bad one stays the zero address, which the grammar refuses
	return domainfence.Job{Domain: d.Domain, Name: d.Name, IP: ip, Token: d.Token, Disruptive: disruptive}
}

// domainFence is the check right before the tool: nil to go on, or the result to post (refused with the fence's reason; stopped when
// core cancelled meanwhile).
func (w *Worker) domainFence(ctx, rctx, jctx context.Context, cur *activeJob, dj domainfence.Job, tool string) *sensorlink.JobResult {
	if w.fence == nil { // never advertised domain_ip: core should not have sent it
		w.log.ErrorContext(ctx, "sensor_active_domain_job_refused", "id", cur.job.ID, "tool", tool, "reason", domainfence.InvalidJob, "error", "this worker has no fence key")
		return refusal(domainfence.InvalidJob)
	}
	o := w.fence.Check(rctx, dj, true)
	if context.Cause(jctx) != nil {
		return stopped()
	}
	attrs := []any{"id", cur.job.ID, "tool", tool, "domain", dj.Domain, "name", dj.Name, "ip", dj.IP.String(), "cname_chain", o.ChainText(), "cached", o.Cached}
	if o.Reason != "" {
		w.log.WarnContext(ctx, "sensor_active_domain_job_refused", append(attrs, "reason", o.Reason, "detail", o.Detail)...)
		return refusal(o.Reason)
	}
	w.log.InfoContext(ctx, "sensor_active_domain_job_allowed", attrs...)
	return nil
}

// watchDomain is watchEgress for a domain_ip job: the fence again, without the cache, on every tick; the first answer that is not a
// yes kills the tool and is returned ("" when ctx ended first).
func (w *Worker) watchDomain(ctx context.Context, dj domainfence.Job, ticks <-chan time.Time, kill context.CancelFunc) string {
	if w.fence == nil {
		return ""
	}
	o := w.fence.Watch(ctx, dj, ticks, kill)
	if o.Reason != "" {
		w.log.WarnContext(ctx, "sensor_active_domain_job_stopped", "domain", dj.Domain, "name", dj.Name, "ip", dj.IP.String(), "cname_chain", o.ChainText(), "reason", o.Reason, "detail", o.Detail)
	}
	return o.Reason
}
