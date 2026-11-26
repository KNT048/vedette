import type { z } from 'zod'
import type { RunDetail } from './contract'

// The runs of the dev data's public scans with their steps, as exposure writes them (modules/exposure/runsteps.go): every step of the
// plan from the start, each done, running, failed or skipped with why, one log line per start and end. The ids are the scans of the
// exposure mocks (treeSeed.ts), so "Open the run" of a target's Scans tab opens them: the box's IP (xt-14) has a deep scan running
// now (OpenVAS at 41 %) and its last finished one (a step failed, one did not run), example.com (xt-11) a deep scan of its names.

type RunRow = z.infer<typeof RunDetail>
type Step = RunRow['steps'][number]
type Line = RunRow['log'][number]

const at = (min: number) => new Date(Date.now() - min * 60_000).toISOString()
const BOX = '198.51.100.2'

/** A step from its start and end, in minutes ago; null start: it never started. */
function step(seq: number, name: string, status: Step['status'], start: number | null, end: number | null, note: string | null, counted = true): Step {
  return { seq, name, status, total: 1, done: counted && !['queued', 'running', 'waiting', 'stopping', 'stopped'].includes(status) ? 1 : 0, note,
    started_at: start === null ? null : at(start), ended_at: end === null ? null : at(end) }
}

/** The log a run's steps write: a line when each starts, one when it ends (with how long it took and what it found). */
function logOf(steps: Step[]): Line[] {
  const words: Partial<Record<Step['status'], string>> = { done: 'Done', partial: 'Partly done', failed: 'Failed', stopped: 'Stopped' }
  const level = (s: Step): Line['level'] => (s.status === 'failed' ? 'error' : s.status === 'partial' || s.status === 'stopped' ? 'warn' : 'info')
  const lines: Line[] = []
  for (const s of steps) {
    if (s.status === 'skipped') { lines.push({ ts: s.ended_at!, level: 'info', text: `Skipped: ${s.name}. ${s.note}` }); continue }
    if (s.started_at) lines.push({ ts: s.started_at, level: 'info', text: `Started: ${s.name}` })
    if (s.ended_at && words[s.status]) {
      const m = Math.round((Date.parse(s.ended_at) - Date.parse(s.started_at!)) / 60_000)
      lines.push({ ts: s.ended_at, level: level(s), text: `${words[s.status]}: ${s.name} (${m ? `${m} min` : 'less than a minute'})${s.note ? `. ${s.note}` : ''}` })
    }
  }
  return lines.sort((a, b) => a.ts.localeCompare(b.ts))
}

function run(id: string, target: { id: string; label: string }, r: Pick<RunRow, 'status' | 'queued_at' | 'started_at' | 'ended_at' | 'steps'> & Partial<RunRow>): RunRow {
  const done = r.steps.reduce((n, s) => n + s.done, 0)
  return {
    id, module: 'exposure', kind: 'exposure_scan', lane: 'exposure', title: `Scan of ${target.label}`, trigger: 'manual', trigger_note: null, requested_by: 'admin@example.com',
    schedule_id: null, subject: { kind: 'target', id: target.id, label: target.label }, parent_id: null, waiting_for: null, stop_reason: null, error: null,
    total: r.steps.length, done, updated_at: r.ended_at ?? at(0), can_stop: false, can_resume: false, summary: '', blocked_by: null,
    items: [], items_total: 0, log: logOf(r.steps), children: [], ...r,
  }
}

const box = { id: 'xt-14', label: BOX }

/** The box's IP: a deep scan running now. Everything before OpenVAS ran; the templates skipped the ports over their job limit. */
const running = (): RunRow => run('run-x14-3', box, {
  status: 'running', queued_at: at(62), started_at: at(62), ended_at: null,
  steps: [
    step(1, 'Check ownership, terms and safety rules', 'done', 62, 62, 'Deep scan with the disruptive checks: the testing terms are accepted.'),
    step(2, 'Common ports, web pages and certificates', 'done', 62, 61, '6 ports open of the commonly exposed ones.'),
    step(3, 'Find open ports (every TCP port)', 'done', 61, 44, '7 open TCP ports found.'),
    step(4, "Identify services and run nmap's scripts", 'done', 44, 36, "Service identification (nmap -sV) on 7 TCP ports: 6 named by a probe, 1 guessed. nmap's scripts: 21 results, 1 saying VULNERABLE."),
    step(5, 'Templates (nuclei)', 'done', 36, 21, 'deep templates ran, 2 matched. Deep templates: 3 ports were not scanned, over the limit of 40 jobs a scan.'),
    step(6, 'Passive web scan (ZAP)', 'done', 21, 14, 'ZAP scanned 3 of 4 pages, 5 alerts'),
    step(7, 'Compare with exploited CVEs and save the results', 'done', 14, 14, '7 open services (1 new, 0 closed), 3 open issues (1 new).'),
    step(8, 'OpenVAS', 'running', 14, null, '41%'),
  ],
})

/** The box's IP, its last finished scan (the treeSeed row run-x14-2, partly done): port 9443 stopped answering during the templates, ZAP's
 *  image was still downloading, and OpenVAS ran into its 90-minute limit. */
const finished = (): RunRow => run('run-x14-2', box, {
  status: 'partial', error: 'OpenVAS did not finish within 90 minutes; the other steps are kept', queued_at: at(288), started_at: at(288), ended_at: at(193),
  steps: [
    step(1, 'Check ownership, terms and safety rules', 'done', 288, 288, 'Deep scan: the testing terms are accepted.'),
    step(2, 'Common ports, web pages and certificates', 'done', 288, 287, '5 ports open of the commonly exposed ones.'),
    step(3, 'Find open ports (every TCP port)', 'done', 287, 271, '6 open TCP ports found.'),
    step(4, "Identify services and run nmap's scripts", 'done', 271, 265, "Service identification (nmap -sV) on 6 TCP ports: 6 named by a probe. nmap's scripts: 14 results, none saying VULNERABLE."),
    step(5, 'Templates (nuclei)', 'partial', 265, 250, 'deep templates ran, 3 matched; port 9443 stopped answering: 2,156 of its 2,161 templates got no answer, so they say nothing about it.'),
    step(6, 'Passive web scan (ZAP)', 'skipped', null, 250, 'Passive web scan (ZAP) did not run: its image is being downloaded. It runs in the next scan.'),
    step(7, 'Compare with exploited CVEs and save the results', 'done', 250, 250, '6 open services (1 new, 0 closed), 2 open issues (0 new).'),
    step(8, 'OpenVAS', 'failed', 250, 193, 'OpenVAS did not finish within 90 minutes, so its results are not shown. The results of the other steps are kept.'),
  ],
})

/** example.com: a deep scan of its names, one step per address it scanned, the addresses its cap left, and OpenVAS turned off. */
const domain = (): RunRow => run('run-x11-2', { id: 'xt-11', label: 'example.com' }, {
  status: 'done', trigger: 'schedule', requested_by: 'system', queued_at: at(1440), started_at: at(1440), ended_at: at(1398),
  steps: [
    step(1, 'Check ownership, terms and safety rules', 'done', 1440, 1440, 'Deep scan: the testing terms are accepted.'),
    step(2, 'Find names and check their web pages', 'done', 1440, 1437, '5 names found, on 4 addresses.'),
    step(3, 'Deep scan of 203.0.113.20 (example.com, www.example.com)', 'done', 1437, 1418, 'Service identification (nmap -sV) on 3 TCP ports: 3 named by a probe.'),
    step(4, 'Deep scan of 203.0.113.21 (mail.example.com)', 'partial', 1418, 1404, 'nmap did not finish on this address, so nothing is known of its ports this time; its earlier ports are kept.'),
    step(5, 'Addresses left for the next scans', 'skipped', null, 1404, '2 addresses wait for the next scans: one scan deep-scans at most 2 addresses, those scanned longest ago first.'),
    step(6, 'Templates (nuclei)', 'done', 1404, 1404, 'deep templates ran, 1 matched'),
    step(7, 'Passive web scan (ZAP)', 'done', 1404, 1399, 'ZAP scanned 2 pages, 1 alert'),
    step(8, 'Compare with exploited CVEs and save the results', 'done', 1399, 1398, '3 open services (0 new, 0 closed), 2 open issues (1 new).'),
    step(9, 'OpenVAS', 'skipped', null, 1398, 'Optional deep scan with OpenVAS is off. An administrator can turn it on under Settings on the External exposure page.'),
  ],
})

export const exposureStepRuns = (): RunRow[] => [running(), finished(), domain()]
