// "Hỏi dữ liệu của tôi" (S-AI-5) — bản mock: câu trả lời soạn sẵn (tiếng Anh, D-28) nhưng bảng và con số TÍNH từ
// assetsStore/findingsStore, nên luôn khớp dữ liệu đang có. Bản thật: skill `ask-my-data` gọi tool chỉ-đọc (AI_ASSISTANT §2); không có tool ghi.
// Câu ngoài dữ liệu thì nói thẳng là không có câu trả lời, không đoán.
import { assetsStore, findingsStore } from '@/mocks/stores'
import { BOX_ID } from '@/features/inventory/mocks'
import type { Asset } from '@/lib/types'
import type { AskTable, ToolCall } from './types'

export interface Answer { answer: string[]; table: AskTable | null; tool_calls: ToolCall[]; citations: { title: string }[] }

const norm = (s: string) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/g, 'd')
const name = (a: Asset) => a.hostname ?? a.model?.value ?? a.ip
const has = (q: string, words: string[]) => words.some((w) => q.includes(w))
const list = (xs: string[]) => (xs.length > 4 ? `${xs.slice(0, 4).join(', ')} and ${xs.length - 4} more` : xs.join(', '))
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

const KIND: Record<string, string> = { firewall: 'Firewall', router: 'Router', switch: 'Switch', ap: 'Wi-Fi', nas: 'NAS', server: 'Server', pc: 'Computer', printer: 'Printer', camera: 'Camera', nvr: 'Recorder', iot: 'IoT', web: 'Website', unknown: 'Unknown' }
const SEV: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }
// Từ chung không nói gì về dữ liệu: bỏ khỏi tìm kiếm theo từ khoá để "weather today" không khớp bừa.
const STOP = new Set(['what', 'which', 'who', 'how', 'many', 'the', 'are', 'any', 'have', 'has', 'show', 'list', 'about', 'with', 'for', 'and', 'does', 'did', 'today', 'weather', 'tell', 'me', 'my', 'our', 'there', 'is', 'of', 'in', 'on', 'to', 'do', 'devices', 'device', 'machines', 'machine', 'still', 'now', 'this', 'that', 'whats', 'when', 'where', 'why', 'can', 'you'])
const DEV = (n: number) => `${plural(n, 'device')}`

export function answerQuestion(question: string): Answer {
  const q = norm(question)
  const assets = assetsStore.get()
  const findings = findingsStore.get()
  // the box itself is named apart, as on Devices and in Reports (modules/ai/ask_tools.go inventoryCite, D-422)
  const others = assets.filter((a) => a.id !== BOX_ID).length
  const inv = { title: others === assets.length ? `Inventory: ${plural(others, 'device')} searched` : others === 0 ? 'Inventory: only the Vedette box searched' : `Inventory: ${plural(others, 'device')} and the Vedette box searched` }
  const tc = (tool: string, args: string, n: number): ToolCall => ({ tool, args, result: DEV(n) })

  function assetTable(rows: Asset[], extra?: { col: string; of: (a: Asset) => string }): AskTable {
    return {
      columns: ['Device', 'IP', 'Type', extra?.col ?? 'Operating system'],
      rows: rows.map((a) => ({ href: `/devices/${a.id}`, cells: [name(a), a.ip, KIND[a.kind] ?? a.kind, extra ? extra.of(a) : a.os?.value ?? 'Unknown'] })),
    }
  }

  // Chưa có kiểm kê thì mọi câu trả lời "không có gì" đều sai lệch: nói thẳng và chỉ việc cần làm.
  if (assets.length === 0) {
    return { answer: ['The inventory has no devices yet, so Vedette has nothing to answer from. Open the Devices page to turn on inventory, import a CSV or add a device by hand, then ask again.'], table: null, tool_calls: [tc('search_assets', '{}', 0)], citations: [inv] }
  }

  if (has(q, ['rdp', '3389', 'remote desktop'])) {
    const rows = assets.filter((a) => a.services.some((s) => s.port === 3389))
    const answer = rows.length
      ? [`${plural(rows.length, 'device')} ${rows.length === 1 ? 'has' : 'have'} RDP (port 3389) open on the internal network: ${list(rows.map(name))}.`, 'This port is open on the internal network; nothing shows it is exposed to the Internet. The External exposure page shows which ports are really visible from outside.']
      : ['No device in the inventory has RDP (port 3389) open.']
    if (rows.some((a) => a.id === 'a-srvad')) answer.push('Start with SRV-AD: it is the domain server and should only allow RDP through the VPN.')
    return { answer, table: rows.length ? assetTable(rows, { col: 'How the port was found', of: (a) => { const s = a.services.find((x) => x.port === 3389)!; return `${s.source}, confidence ${Math.round(s.confidence * 100)}%` } }) : null, tool_calls: [tc('search_assets', '{"port": 3389}', rows.length)], citations: rows.length ? [inv, { title: 'Open services from active and passive sensors' }] : [inv] }
  }

  if (has(q, ['unapproved', 'not approved', 'new device', 'unknown device', 'pending', 'awaiting approval'])) {
    const rows = assets.filter((a) => !a.approved)
    return {
      answer: rows.length ? [`${plural(rows.length, 'device')} ${rows.length === 1 ? 'is' : 'are'} not approved yet: ${list(rows.map(name))}.`, 'Open Devices to approve, mark as unknown or delete. A device using a random MAC address is often a phone; still ask its owner.'] : ['No device is waiting for approval.'],
      table: rows.length ? assetTable(rows, { col: 'First seen', of: (a) => new Date(a.first_seen).toLocaleDateString('en-GB') }) : null,
      tool_calls: [tc('search_assets', '{"approved": false}', rows.length)], citations: [inv],
    }
  }

  if (!has(q, ['nas', 'qnap', 'synology', 'camera', 'hikvision']) && has(q, ['confirmed', 'vulnerab', 'finding', 'urgent', 'critical', 'exploit', 'attack', 'compromis', 'cve'])) {
    const onlyConfirmed = has(q, ['confirmed'])
    const rows = findings.filter((f) => (onlyConfirmed ? f.status === 'confirmed' : f.status === 'confirmed' || f.status === 'suspected'))
    const nameOf = (id: string) => { const a = assets.find((x) => x.id === id); return a ? name(a) : id }
    const conf = rows.filter((f) => f.status === 'confirmed')
    const lst = list(rows.map((f) => `${f.cve} on ${nameOf(f.asset_id)}`))
    return {
      answer: rows.length ? [onlyConfirmed ? `${plural(rows.length, 'finding')} ${rows.length === 1 ? 'is' : 'are'} confirmed: ${lst}.` : `${plural(rows.length, 'finding')} ${rows.length === 1 ? 'is' : 'are'} unresolved, ${conf.length} of them confirmed: ${lst}.`, conf.length ? 'A confirmed finding means a safe scan sample saw signs of the vulnerability; handle these first, then the suspected ones.' : 'All findings are suspected from the version or product; none is confirmed by a scan yet.'] : ['There are no unresolved findings.'],
      table: rows.length ? { columns: ['Device', 'CVE', 'Status', 'Severity'], rows: rows.map((f) => ({ href: `/findings/${f.id}`, cells: [nameOf(f.asset_id), f.cve, f.status === 'confirmed' ? 'Confirmed' : 'Suspected', SEV[f.severity] ?? f.severity] })) } : null,
      tool_calls: [{ tool: 'list_findings', args: onlyConfirmed ? '{"status": "confirmed"}' : '{"status": ["confirmed", "suspected"]}', result: plural(rows.length, 'finding') }], citations: [{ title: `Findings: ${plural(findings.length, 'record')} searched` }],
    }
  }

  if (has(q, ['nas', 'qnap', 'synology'])) {
    const rows = assets.filter((a) => a.kind === 'nas')
    const withF = (a: Asset) => findings.filter((f) => f.asset_id === a.id && (f.status === 'confirmed' || f.status === 'suspected')).length
    if (rows.length === 0) return { answer: ['The inventory has no NAS device.'], table: null, tool_calls: [tc('search_assets', '{"kind": "nas"}', 0)], citations: [inv] }
    return {
      answer: [`There ${rows.length === 1 ? 'is' : 'are'} ${rows.length} NAS: ${list(rows.map((a) => `${name(a)} (${a.os?.value ?? 'version unknown'})`))}.`, ...rows.filter((a) => withF(a) > 0).map((a) => `${name(a)} has ${plural(withF(a), 'unresolved finding')}.`)],
      table: assetTable(rows, { col: 'Unresolved findings', of: (a) => String(withF(a)) }),
      tool_calls: [tc('search_assets', '{"kind": "nas"}', rows.length), { tool: 'list_findings', args: `{"asset_id": [${rows.map((a) => `"${a.id}"`).join(', ')}]}`, result: plural(rows.reduce((n, a) => n + withF(a), 0), 'finding') }], citations: [inv, { title: 'Findings per device' }],
    }
  }

  if (has(q, ['camera', 'hikvision', 'nvr', 'recorder'])) {
    const rows = assets.filter((a) => a.kind === 'camera' || a.kind === 'nvr')
    if (rows.length === 0) return { answer: ['The inventory has no camera or recorder.'], table: null, tool_calls: [tc('search_assets', '{"kind": ["camera", "nvr"]}', 0)], citations: [inv] }
    return {
      answer: [`There ${rows.length === 1 ? 'is' : 'are'} ${plural(rows.length, 'camera or recorder', 'cameras and recorders')}: ${list(rows.map(name))}.`, 'Cameras are fragile devices, so Vedette only listens passively and never scans them actively. Block cameras from reaching the Internet.'],
      table: assetTable(rows, { col: 'Vendor and model', of: (a) => `${a.vendor?.value ?? '–'} ${a.model?.value ?? ''}`.trim() }),
      tool_calls: [tc('search_assets', '{"kind": ["camera", "nvr"]}', rows.length)], citations: [inv],
    }
  }

  if (has(q, ['end of support', 'end-of-support', 'unsupported', 'outdated', 'old os', 'operating system', 'windows 10', 'server 2016'])) {
    const rows = assets.filter((a) => /windows 10|server 2016/i.test(a.os?.value ?? ''))
    return {
      answer: rows.length ? [`${plural(rows.length, 'device')} run${rows.length === 1 ? 's' : ''} an operating system that is out of support or about to be: ${list(rows.map(name))}.`, 'Windows 10 free support ended in 10/2025; Windows Server 2016 extended support ends in 01/2027. Plan the upgrade before then.'] : ['No device in the inventory runs an operating system close to end of support.'],
      table: rows.length ? assetTable(rows) : null,
      tool_calls: [{ tool: 'search_assets', args: '{"os_matches": ["Windows 10", "Server 2016"]}', result: DEV(rows.length) }], citations: [inv, { title: 'Microsoft support lifecycle' }],
    }
  }

  const words = norm(question).split(/[^a-z0-9.]+/).filter((w) => w.length >= 3 && !STOP.has(w))
  const rows = words.length ? assets.filter((a) => {
    const hay = norm([a.hostname, a.ip, a.vendor?.value, a.model?.value, a.os?.value, ...a.software.map((s) => s.display)].filter(Boolean).join(' ')).split(/[^a-z0-9.]+/)
    return words.some((w) => hay.some((h) => h === w || (w.length >= 4 && h.startsWith(w))))
  }) : []
  if (rows.length) return { answer: [`Found ${plural(rows.length, 'device')} matching keywords in the question: ${list(rows.map(name))}.`], table: assetTable(rows), tool_calls: [{ tool: 'search_assets', args: JSON.stringify({ text: words.join(' ') }), result: DEV(rows.length) }], citations: [inv] }
  return { answer: ['Nothing in this box matches the question, so there is no answer. The AI only answers from the inventory and findings on this box. Try a device name, IP, vendor or port, for example "Which machines still expose RDP?".'], table: null, tool_calls: [{ tool: 'search_assets', args: JSON.stringify({ text: words.join(' ') }), result: DEV(0) }], citations: [] }
}
