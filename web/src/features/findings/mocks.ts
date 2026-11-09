// Mock API module findings (S-MIT-1/2/3, S-SCAN-3, S-AI-2). Phát hiện nằm ở findingsStore dùng chung; kết quả AI nằm ở collection mit_ai_outputs. Mọi chuỗi hiển thị bằng tiếng Anh (D-28).
import { http, HttpResponse } from 'msw'
import kev from '@/mocks/fixtures/kev.json'
import { API, audit, body, currentUser, fail, guard } from '@/mocks/http'
import { collection, nowIso } from '@/mocks/db'
import { aiAvailable, aiCandidates, assetsStore, findingsStore, recordAiRun, type AiJob } from '@/mocks/stores'
import type { Asset, Finding } from '@/lib/types'
import { compromise, packs } from './packs'
import type { AiResult, ApplyItem, FindingAsset, FindingDetail, FindingRow, FirewallGuide, KevInfo, MitigationPack, StatusAction } from './types'

interface Vuln { cve: string; vendor: string; product: string; name: string; required_action: string; links: string[]; date_added: string; due_date: string | null; ransomware: boolean; epss: number | null; has_template: boolean }
const vulns = (kev as { vulns: Vuln[] }).vulns

// Gói giảm thiểu và dấu hiệu khai thác là nội dung ký của dự án Vedette (content pack), không phải dữ liệu người dùng: đọc từ packs.ts.
const aiOutputs = collection<Record<string, AiResult>>('mit_ai_outputs', () => ({}))

const APPLY_ITEMS: ApplyItem[] = ['patch', 'workaround', 'fortigate', 'mikrotik', 'generic']
const ACTIONS: StatusAction[] = ['patched', 'mitigated', 'false_positive', 'not_relevant', 'reopen']

const DISPLAY: Record<string, string> = {
  'qnap|photo station': 'Photo Station app on a QNAP NAS',
  'wordpress|wordpress core': 'WordPress website',
  'microsoft|windows': 'Windows computers and servers',
}

function kevInfo(cve: string): KevInfo | null {
  const v = vulns.find((x) => x.cve === cve)
  if (!v) return null
  const display = DISPLAY[`${v.vendor}|${v.product}`.toLowerCase()] ?? `${v.vendor} ${v.product}`
  return { name: v.name, vendor: v.vendor, product: v.product, display, required_action: v.required_action, links: v.links, date_added: v.date_added, due_date: v.due_date, ransomware: v.ransomware, epss: v.epss, has_template: v.has_template }
}

function assetView(a: Asset | undefined): FindingAsset | null {
  return a ? { id: a.id, hostname: a.hostname, ip: a.ip, kind: a.kind, display: a.software[0]?.display ?? a.kind } : null
}

function row(f: Finding): FindingRow {
  return { ...f, asset: assetView(assetsStore.get().find((a) => a.id === f.asset_id)), kev: kevInfo(f.cve) }
}

const fill = (s: string, ip: string, host: string) => s.replaceAll('{IP}', ip).replaceAll('{HOST}', host)

/** Gói theo thiết bị thật: thay IP/tên máy, đánh dấu hãng firewall khách đã khai (S-MIT-1). */
function renderPack(p: MitigationPack, asset: FindingAsset | null): MitigationPack {
  const ip = asset?.ip ?? '<IP-NAS>'
  const host = asset?.hostname ?? ip
  const has = (name: string) => assetsStore.get().some((a) => (a.kind === 'firewall' || a.kind === 'router') && (a.vendor?.value ?? '').toLowerCase() === name)
  const detected: Record<string, boolean> = { fortigate: has('fortinet'), mikrotik: has('mikrotik'), generic: false }
  const out = JSON.parse(fill(JSON.stringify(p), ip, host)) as MitigationPack
  out.firewall = out.firewall.map((g: FirewallGuide) => ({ ...g, detected: detected[g.vendor] ?? false }))
  return out
}

function recheckFor(f: Finding, k: KevInfo | null, a: FindingAsset | null) {
  if (f.cve === 'CVE-2022-27593' && a) {
    return {
      steps: [
        'Sign in to QTS, open App Center and check the Photo Station version. Lower than the fixed version in advisory QSA-22-24 means the flaw is still there.',
        'Run the safe scan template again with the "Rescan this device" button.',
        'Run the command below from a machine on the network: a 200 or 302 reply means Photo Station is running and reachable.',
      ],
      code: `curl -sI http://${a.ip}/photo/`,
    }
  }
  return {
    steps: f.basis === 'scan'
      ? ['Run the scan template again with the "Rescan this device" button.']
      : [
          `Open the admin page of ${a?.hostname ?? 'the device'} and check which version of ${k?.display ?? 'the software'} is running.`,
          'Compare it with the fixed version in the vendor advisory (link in the source section). An older version means the flaw is still there.',
          k?.has_template ? 'This CVE has a safe scan template: click "Rescan this device" to confirm.' : 'This CVE has no safe scan template yet, so Vedette can only conclude from the version. Check by hand as above.',
        ],
  }
}

function detail(f: Finding): FindingDetail {
  const r = row(f)
  const pack = packs()[f.cve]
  const check = compromise()[f.cve] ?? null
  const ip = r.asset?.ip ?? '<IP>'
  const host = r.asset?.hostname ?? ip
  const outs = aiOutputs.get()
  return {
    ...r,
    pack: pack ? renderPack(pack, r.asset) : null,
    compromise: check ? JSON.parse(fill(JSON.stringify(check), ip, host)) : null,
    recheck: recheckFor(f, r.kev, r.asset),
    ai: { explain: outs[`${f.id}:explain`] ?? null, config: outs[`${f.id}:mitigation-config`] ?? null },
    ai_available: { explain: aiAvailable('explain-finding'), config: aiAvailable('mitigation-config') },
    applied: f.history.filter((h) => h.action.startsWith('applied:')).map((h) => ({ item: h.action.slice(8), ts: h.ts, user: h.user })),
  }
}

const who = () => currentUser()?.email ?? 'system'
const find = (id: unknown) => findingsStore.get().find((f) => f.id === String(id))
const patch = (id: string, fn: (f: Finding) => Finding) => findingsStore.update((l) => l.map((f) => (f.id === id ? fn(f) : f)))

const BASIS: Record<Finding['basis'], string> = {
  scan: 'A safe scan template confirmed the flaw is still present on this device.',
  version: 'The device matches by version or operating system. No scan template has confirmed it yet, so this is only suspected.',
  product: 'The device only matches by product name; the version is unknown, so it may not be affected.',
}

const HARDEN: Record<string, string[]> = {
  'wordpress|wordpress core': [
    'Update WordPress to the latest release of the branch you use. Check the fixed version number in the security notice on wordpress.org (Vedette does not assert a version number itself).',
    'Until you update: temporarily block outside access to the admin area and run the upgrade outside peak hours, from a machine on the internal network.',
    'Back up the website and database before upgrading.',
  ],
  'microsoft|windows': [
    'Install the latest security update for Windows Server through Windows Update or WSUS, and check the CVE ID on the MSRC page.',
    'Do not expose the server SMB (445) and RDP (3389) to the Internet.',
    'An AD server is a high-value target: update outside working hours and take a system-state backup first.',
  ],
}

const jobOf = (skill: AiResult['skill']): AiJob => (skill === 'explain' ? 'explain-finding' : 'mitigation-config')
function aiResult(f: Finding, skill: AiResult['skill']): AiResult {
  const r = row(f)
  const k = r.kev
  const dev = r.asset?.hostname ?? r.asset?.ip ?? f.asset_id
  const key = k ? `${k.vendor}|${k.product}`.toLowerCase() : ''
  const date = k ? new Date(k.date_added).toLocaleDateString('en-GB') : ''
  const paragraphs = skill === 'explain'
    ? [
        `${dev} matches ${f.cve}${k ? ` (${k.name})` : ''}. ${BASIS[f.basis]}`,
        k ? `CISA has listed this flaw as exploited in the wild since ${date}${k.ransomware ? ', and ransomware groups have used it' : ''}. So handle it early rather than waiting for the normal update cycle.` : 'There is no KEV information for this CVE yet.',
      ]
    : ['Vedette has no confirmed recommendation for this CVE yet. Below are general suggestions drafted by your AI from public information. Check them against the vendor advisory before applying.']
  const harden = HARDEN[key]
  const steps = skill === 'explain'
    ? ['Patch: follow the vendor advisory in the sources below.', 'If you cannot patch yet: cut the path in from the Internet and turn off the affected component if unused.', 'Signs of exploitation: check access logs and unfamiliar processes around the time the flaw was published.']
    : harden ? harden : ['Update to the fixed version per the vendor advisory.', 'If you cannot patch yet, restrict Internet access to this device (firewall, VPN).', 'Watch the device logs for a few days after applying.']
  const citations = (k?.links ?? []).slice(0, 3).map((u) => ({ title: new URL(u).hostname.replace(/^www\./, ''), url: u }))
  const len = paragraphs.join('').length + steps.join('').length
  const prof = aiCandidates(jobOf(skill))[0]
  return { skill, ts: nowIso(), model: prof?.model ?? '', profile: prof?.name, tokens: { input: 1200 + len, output: Math.round(len / 3.2) }, paragraphs, steps, citations }
}

export const handlers = [
  http.get(`${API}/findings`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const asset = new URL(request.url).searchParams.get('asset')
    const list = findingsStore.get().filter((f) => !asset || f.asset_id === asset)
    return HttpResponse.json({ items: list.map(row) })
  }),

  http.get(`${API}/findings/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const f = find(params.id)
    return f ? HttpResponse.json(detail(f)) : fail(404, 'not_found', 'No such finding. It may have been removed when the sample data was restored.')
  }),

  // Đổi trạng thái kèm ghi chú (S-MIT-1). false_positive / not_relevant bắt buộc ghi chú để lần sau biết vì sao.
  http.post(`${API}/findings/:id/status`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'No such finding.')
    const b = await body<{ action: StatusAction; note: string }>(request)
    if (!b.action || !ACTIONS.includes(b.action)) return fail(400, 'bad_action', 'Choose one of: patched, mitigated, false positive, not relevant, or reopen.')
    const note = typeof b.note === 'string' ? b.note.trim() : ''
    if (note.length > 500) return fail(400, 'note_too_long', 'The note can be at most 500 characters. Shorten it.')
    if ((b.action === 'false_positive' || b.action === 'not_relevant') && note.length < 3) return fail(400, 'note_required', 'Write why this is a false positive or not relevant (at least 3 characters) so the next person understands.')
    const ts = nowIso()
    const user = who()
    if (b.action === 'reopen') {
      if (f.status === 'confirmed' || f.status === 'suspected') return fail(409, 'already_open', 'This finding is already open.')
      patch(f.id, (x) => ({ ...x, status: x.basis === 'scan' ? 'confirmed' : 'suspected', resolved_by: null, resolved_at: null, resolution_note: null, history: [...x.history, { ts, user, action: 'reopened', note: note || undefined }] }))
    } else {
      patch(f.id, (x) => ({ ...x, status: b.action as Finding['status'], resolved_by: user, resolved_at: ts, resolution_note: note || null, history: [...x.history, { ts, user, action: b.action as string, note: note || undefined }] }))
    }
    audit('findings.status', f.id, `${f.cve} → ${b.action}${note ? `: ${note}` : ''}`)
    return HttpResponse.json(detail(find(f.id)!))
  }),

  // "Đã áp dụng": ghi nhật ký, không tự đổi trạng thái; chỉ quét lại mới xác nhận đã hết.
  http.post(`${API}/findings/:id/applied`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'No such finding.')
    if (!packs()[f.cve]) return fail(400, 'no_pack', 'This CVE has no confirmed recommendation yet, so there is nothing to mark as applied.')
    const b = await body<{ item: ApplyItem }>(request)
    if (!b.item || !APPLY_ITEMS.includes(b.item)) return fail(400, 'bad_item', 'Invalid item to apply.')
    if (!f.history.some((h) => h.action === `applied:${b.item}`)) {
      patch(f.id, (x) => ({ ...x, history: [...x.history, { ts: nowIso(), user: who(), action: `applied:${b.item}` }] }))
      audit('findings.applied', f.id, `${f.cve}: ${b.item}`)
    }
    return HttpResponse.json(detail(find(f.id)!))
  }),

  // S-AI-2 / D-21: chạy bằng khoá AI của khách; chỉ khi module ai bật và đã có khoá. Kết quả lưu lại để còn sau khi tải lại trang.
  http.post(`${API}/findings/:id/ai`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const f = find(params.id)
    if (!f) return fail(404, 'not_found', 'No such finding.')
    const b = await body<{ skill: AiResult['skill'] }>(request)
    if (b.skill !== 'explain' && b.skill !== 'mitigation-config') return fail(400, 'bad_skill', 'skill must be explain or mitigation-config.')
    if (!aiAvailable(jobOf(b.skill))) return fail(409, 'ai_unavailable', 'No AI profile is assigned to this job, or the AI assistant is off. Open Settings, AI assistant to set it up.')
    const res = aiResult(f, b.skill)
    aiOutputs.update((m) => ({ ...m, [`${f.id}:${b.skill}`]: res }))
    recordAiRun(jobOf(b.skill), res.tokens.input, res.tokens.output, `${f.cve} ${f.asset_id}`, aiCandidates(jobOf(b.skill))[0])
    audit('findings.ai', f.id, b.skill)
    return HttpResponse.json(detail(find(f.id)!))
  }),
]
