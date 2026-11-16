// One shape of "how far is it" for the long jobs a customer waits on (#830): a device of a scan, a scan of a public IP, its OpenVAS
// step. The server keeps only the latest state, in memory, while the job runs (core/progress). Shared by the scan and exposure
// contracts; the component that shows it comes with the web part of #830.
import { z } from 'zod'

export const PROGRESS_PHASES = ['discovery', 'ports', 'services', 'scripts', 'vulns', 'web', 'openvas', 'saving'] as const
export const JobProgress = z.object({
  phase: z.enum(PROGRESS_PHASES).describe('discovery: is the host up (ping or ARP); ports: port scan; services: service and version detection; scripts: nmap reads titles, certificates and NTLM answers; vulns: vulnerability checks (nuclei templates); web: passive web checks (ZAP); openvas: the optional OpenVAS deep scan; saving: the result is being stored'),
  percent: z.number().min(0).max(100).nullable().describe('How far into the phase, 0 to 100, one decimal; null when the tool gives no measure yet (show the phase without a bar)'),
  done: z.number().int().nullable().describe('With total: the count behind percent (unit says what is counted); null when the phase has no count'),
  total: z.number().int().nullable(),
  unit: z.enum(['checks', 'hosts']).nullable().describe('checks: template x port pairs of the vulnerability checks; hosts: addresses of a discovery batch'),
  started_at: z.iso.datetime().describe('When the job (the device, or the public IP scan) started: elapsed time is now minus this'),
  phase_started_at: z.iso.datetime().describe('When the current phase (or the current pass of it: a device gets a second nmap pass over admin ports) started'),
  updated_at: z.iso.datetime().describe('The latest report; nmap and nuclei report every 5 seconds at most, so an older one means the tool is quiet, not that the box hangs'),
  eta: z.iso.datetime().nullable().describe('Estimated end of the current phase: nmap\'s own estimate for its phases, the pace so far for the vulnerability checks (after 10 s and 1 %); null until it can be estimated'),
  message: z.string().max(120).nullable().describe('A short English note on the pass, e.g. "Second pass: administration and alternative ports"; null when none'),
})
export type JobProgress = z.infer<typeof JobProgress>

/** For the mocks (make dev): the progress of a device fraction 0..1 through its scan, as the box reports it: discovery, a port scan
 *  and service detection with nmap's percent and estimate, scripts, then vulnerability checks counted out of 12. */
export function mockDeviceProgress(startedMs: number, fraction: number, nowMs: number): JobProgress {
  const f = Math.min(1, Math.max(0, fraction))
  const steps: { phase: JobProgress['phase']; from: number; to: number }[] = [
    { phase: 'discovery', from: 0, to: 0.1 }, { phase: 'ports', from: 0.1, to: 0.45 }, { phase: 'services', from: 0.45, to: 0.7 },
    { phase: 'scripts', from: 0.7, to: 0.8 }, { phase: 'vulns', from: 0.8, to: 1.0001 },
  ]
  const step = steps.find((s) => f < s.to) ?? { phase: 'vulns' as const, from: 0.8, to: 1.0001 }
  const inPhase = (f - step.from) / (step.to - step.from)
  const span = Math.max(1, nowMs - startedMs) / Math.max(f, 0.01)
  const iso = (ms: number) => new Date(ms).toISOString()
  const phaseStart = startedMs + span * step.from
  const counted = step.phase === 'vulns'
  const done = Math.min(12, Math.floor(inPhase * 12))
  return {
    phase: step.phase, percent: step.phase === 'discovery' ? null : Math.round((counted ? (done * 100) / 12 : inPhase * 100) * 10) / 10,
    done: counted ? done : null, total: counted ? 12 : null, unit: counted ? 'checks' : null,
    started_at: iso(startedMs), phase_started_at: iso(phaseStart), updated_at: iso(nowMs),
    eta: inPhase > 0.05 ? iso(startedMs + span * step.to) : null, message: null,
  }
}
