// 3 sample findings tied to real KEV CVEs. Fixed ids: f-1 (NAS, confirmed), f-2 (WordPress, suspected), f-3 (Windows Server 2016, suspected).
// The findings module owns this file (it may add findings); other modules only read through findingsStore.
import type { Finding } from '@/lib/types'
import type { Basis, CveSeverity, EventKind, FindingEvent, FixKind, PossibleCheck, Reason, Resolution, UndecidedReason, Verified, Via, QuestionKind } from '@/features/findings/types'

const D = (days: number, h = 0) => new Date(Date.now() - days * 864e5 - h * 36e5).toISOString()

export function seedFindings(): Finding[] {
  return [
    {
      id: 'f-1', asset_id: 'a-nas02', cve: 'CVE-2022-27593', status: 'confirmed', severity: 'critical', confidence: 0.95, basis: 'scan',
      evidence: {
        summary: 'The nuclei-templates safe scan template for CVE-2022-27593 matched both conditions on the Photo Station of NAS-PHOTOS.',
        template: 'http/cves/2022/CVE-2022-27593.yaml',
        request: 'GET http://192.168.10.21/photo/… HTTP/1.1 (shortened)',
        response: 'HTTP/1.1 200 OK, the response body matches the template signature (shortened)',
        checked_at: D(0, 3),
      },
      first_seen: D(2), last_seen: D(0, 3), resolved_by: null, resolved_at: null, resolution_note: null,
      history: [{ ts: D(2), user: 'system', action: 'created', note: 'Matched product QNAP Photo Station' }, { ts: D(0, 3), user: 'system', action: 'confirmed', note: 'Confirmed by scan match' }],
    },
    {
      id: 'f-2', asset_id: 'a-web01', cve: 'CVE-2026-119977', status: 'suspected', severity: 'high', confidence: 0.5, basis: 'product',
      evidence: { summary: 'WEB01 runs WordPress (read from the generator tag, medium confidence). It is not yet known whether the version is in the affected range.', checked_at: D(0, 6) },
      first_seen: D(3), last_seen: D(0, 6), resolved_by: null, resolved_at: null, resolution_note: null,
      history: [{ ts: D(3), user: 'system', action: 'created', note: 'New KEV entry matches product WordPress Core' }],
    },
    {
      id: 'f-3', asset_id: 'a-srvad', cve: 'CVE-2026-96951', status: 'suspected', severity: 'high', confidence: 0.6, basis: 'version',
      evidence: { summary: 'SRV-AD runs Windows Server 2016 (identified by active scan). There is no installed-patch data to rule it out yet.', checked_at: D(1) },
      first_seen: D(24), last_seen: D(1), resolved_by: null, resolved_at: null, resolution_note: null,
      history: [{ ts: D(24), user: 'system', action: 'created', note: 'KEV entry matches Microsoft Windows' }],
    },
  ]
}

// ---------- The findings model (one row per device, CVE and software line), read by GET /findings/devices, /fixes, /input,
// /handled, /overview and /findings/{id}/view. Sample data only: invented host names, addresses of the sample network.

/** A stored finding, as the box keeps it: detection, handling and urgency are separate fields. */
export interface FindingRecord {
  id: string
  asset_id: string
  cve: string
  /** The software line; null only for a safe-check hit on a device with no row for the product. */
  software: { id: string; name: string; version: string | null } | null
  verified: Verified
  basis: Basis
  verified_by: string | null
  verified_at: string | null
  fix: { key: string; kind: FixKind; product: string; version: string | null; ref: string | null; url: string | null; channel?: 'public' | 'ubuntu_pro' | 'esu' }
  state: 'open' | 'handled'
  resolution: Resolution | null
  via: Via | null
  resolved_by: string | null
  resolved_at: string | null
  note: string | null
  accepted_until: string | null
  from_version: string | null
  to_version: string | null
  layer: 1 | 2 | 3 | 4 | 5
  urgency_at: string
  reasons: Reason[]
  internet: string | null
  first_seen: string
  last_seen: string
  reopened: { why: 'still_detected' | 'detected_again' | 'acceptance_expired'; at: string; by?: string | null } | null
  events: FindingEvent[]
  /** A finding a person confirmed from an AI proposal: the AI's check it rests on. */
  ai_check?: PossibleCheck
}

/** A question only a person can answer (not a finding). */
export interface QuestionRecord {
  id: string
  kind: QuestionKind
  asset_id: string
  software: { id: string; name: string; version: string | null } | null
  cve: string | null
  cves: number
  asked_at: string
  url: string | null
  command: string | null
  choices: { label: string; os?: string; ask?: ('os' | 'pkg_version')[] }[]
  /** older_line: the CVEs, the device's line and the newest fix of each newer line; no_range_data: whether the CVE lists versions. */
  cve_list?: string[]
  fixes?: string[]
  line?: string | null
  versions_listed?: boolean
  /** not_comparable: the build attribute NVD pins that decides it (edition, architecture, platform). */
  attribute?: 'edition' | 'architecture' | 'platform' | 'unlisted_line' | null
  /** A "not affected" answer, kept so it can be taken back; absent while the question waits. */
  answered?: { by: string; at: string }
  /** Why the CVE is undecided (a possible finding's reason); absent: the usual reason of its kind. */
  undecided?: { reason: UndecidedReason; ranges?: string[]; text?: string; url?: string }
}

const day = (days: number) => D(days).slice(0, 10)
const ahead = (days: number) => new Date(Date.now() + days * 864e5).toISOString().slice(0, 10)

/** The CVSS of the sample CVEs (null = not scored yet). */
export const SAMPLE_SEVERITY: Record<string, CveSeverity | null> = {
  'CVE-2024-21762': { band: 'critical', score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2024-23113': { band: 'critical', score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2026-123158': { band: 'medium', score: 5.3, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' },
  'CVE-2026-123159': { band: 'high', score: 7.5, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' },
  'CVE-2026-123160': { band: 'low', score: 3.7, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N' },
  'CVE-2026-123890': { band: 'high', score: 8.1, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2026-119977': { band: 'high', score: 8.5, version: '4.0', vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N' },
  'CVE-2024-4577': { band: 'critical', score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2025-29824': { band: 'high', score: 7.8, version: '3.1', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2026-21589': { band: 'high', score: 7.5, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
  'CVE-2022-27593': { band: 'critical', score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2026-114938': { band: 'high', score: 8.1, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2026-131402': null,
  'CVE-2025-21333': { band: 'high', score: 7.8, version: '3.1', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2024-49112': { band: 'critical', score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2025-21418': { band: 'high', score: 7.8, version: '3.1', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
  'CVE-2026-117730': { band: 'medium', score: 6.1, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
  'CVE-2026-109112': { band: 'medium', score: 4.3, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N' },
}

const fixOf = (productKey: string, product: string, kind: FixKind, version: string | null, ref: string | null = null, url: string | null = null) =>
  ({ key: `${productKey}|${kind}|${version ?? ref ?? ''}`, kind, product, version, ref, url })
const ev = (days: number, kind: EventKind, extra: Partial<FindingEvent> = {}): FindingEvent =>
  ({ ts: D(days), actor: 'system', kind, layer: null, resolution: null, via: null, note: null, ...extra })
const kev = (added: number, due: number): Reason => ({ layer: 2, source: 'cisa-kev', name: 'CISA KEV', date: day(added), url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', detail: null, due: day(due) })
const edge = (since: number): Reason => ({ layer: 4, source: 'cvss', name: 'Critical on an edge device', date: day(since), url: null, detail: 'CVSS 9.8, network, no login', due: null })

type Open = Pick<FindingRecord, 'id' | 'asset_id' | 'cve' | 'software' | 'verified' | 'basis' | 'fix' | 'layer' | 'reasons'> & Partial<FindingRecord>
function open(f: Open, seen: number): FindingRecord {
  return {
    verified_by: null, verified_at: f.verified === 'no' ? null : D(seen), state: 'open', resolution: null, via: null, resolved_by: null, resolved_at: null, note: null,
    accepted_until: null, from_version: null, to_version: null, urgency_at: D(seen), internet: null, first_seen: D(seen), last_seen: D(0, 2), reopened: null,
    events: [ev(seen, 'created'), ...(f.layer < 5 ? [ev(seen, 'urgency_changed', { layer: f.layer })] : [])], ...f,
  }
}
function handled(f: Open & Pick<FindingRecord, 'resolution' | 'via' | 'resolved_by'> & Partial<FindingRecord>, seen: number, at: number): FindingRecord {
  const base = open(f, seen)
  return { ...base, ...f, state: 'handled', resolved_at: D(at), events: [...base.events, ev(at, 'handled', { actor: f.resolved_by!, resolution: f.resolution, via: f.via, note: f.note ?? null })] }
}

const OPENSSH = 'openbsd:openssh'
const ssh = { id: 's-fw01-ssh-agent', name: 'OpenSSH', version: '10.2p1' }
const fortios = { id: 's-fw01', name: 'FortiGate firewall', version: '7.2' }
const winSrv16 = { id: 's-srvad', name: 'Windows Server 2016', version: 'Server 2016 (1607)' }

export function seedFindingRecords(): FindingRecord[] {
  return [
    // FW-HQ: an exploited FortiOS flaw, critical on an edge device and seen from the Internet; OpenSSH updates from the agent's version.
    open({ id: 'fv-fw01-fos-1', asset_id: 'a-fw01', cve: 'CVE-2024-21762', software: fortios, verified: 'device', basis: 'device_version',
      fix: fixOf('fortinet:fortios', 'FortiOS', 'update', '7.2.7', null, 'https://fortiguard.example.com/psirt/FG-IR-24-015'), layer: 2,
      reasons: [kev(300, 293), edge(320)], internet: day(1) }, 30),
    open({ id: 'fv-fw01-fos-2', asset_id: 'a-fw01', cve: 'CVE-2024-23113', software: fortios, verified: 'device', basis: 'device_version',
      fix: fixOf('fortinet:fortios', 'FortiOS', 'update', '7.2.7', null, 'https://fortiguard.example.com/psirt/FG-IR-24-029'), layer: 4, reasons: [edge(280)] }, 30),
    open({ id: 'fv-fw01-ssh-1', asset_id: 'a-fw01', cve: 'CVE-2026-123159', software: ssh, verified: 'device', basis: 'package', fix: fixOf(OPENSSH, 'OpenSSH', 'update', '10.6'), layer: 5, reasons: [] }, 12),
    open({ id: 'fv-fw01-ssh-2', asset_id: 'a-fw01', cve: 'CVE-2026-123158', software: ssh, verified: 'device', basis: 'package', fix: fixOf(OPENSSH, 'OpenSSH', 'update', '10.6'), layer: 5, reasons: [] }, 12),
    open({ id: 'fv-fw01-ssh-3', asset_id: 'a-fw01', cve: 'CVE-2026-123160', software: ssh, verified: 'device', basis: 'package', fix: fixOf(OPENSSH, 'OpenSSH', 'update', '10.6'), layer: 5, reasons: [] }, 12),
    // BN340: exploited per Rapid7 (not in CISA KEV), read from a scan banner only: not confirmed yet, no safe check.
    open({ id: 'fv-bn340-ssh-1', asset_id: 'a-bn340', cve: 'CVE-2026-123890', software: { id: 's-bn340-ssh', name: 'OpenSSH', version: '10.2' }, verified: 'no', basis: 'banner_version',
      fix: fixOf(OPENSSH, 'OpenSSH', 'update', '10.6'), layer: 2,
      reasons: [{ layer: 2, source: 'rapid7', name: 'Rapid7', date: day(1), url: 'https://www.rapid7.example.com/blog/post/sample', detail: null, due: null }] }, 1),
    open({ id: 'fv-bn340-ssh-2', asset_id: 'a-bn340', cve: 'CVE-2026-123159', software: { id: 's-bn340-ssh', name: 'OpenSSH', version: '10.2' }, verified: 'no', basis: 'banner_version',
      fix: fixOf(OPENSSH, 'OpenSSH', 'update', '10.6'), layer: 5, reasons: [] }, 12),
    // WEB01: a public exploit on WordPress confirmed by a safe check; PHP exploited, from a banner, a safe check exists.
    open({ id: 'fv-web01-wp-1', asset_id: 'a-web01', cve: 'CVE-2026-119977', software: { id: 's-web01-wp', name: 'WordPress website', version: '7.1.x' }, verified: 'scan', basis: 'scan',
      fix: fixOf('wordpress:wordpress', 'WordPress', 'update', '7.1.5'), layer: 3,
      reasons: [{ layer: 3, source: 'nuclei', name: 'Nuclei templates', date: day(3), url: 'https://github.com/projectdiscovery/nuclei-templates', detail: null, due: null },
        { layer: 3, source: 'github-poc', name: 'GitHub', date: day(2), url: 'https://github.example.com/sample/poc', detail: '244 stars', due: null }], internet: day(2) }, 3),
    open({ id: 'fv-web01-php-1', asset_id: 'a-web01', cve: 'CVE-2024-4577', software: { id: 's-web01-php', name: 'PHP', version: '8.1' }, verified: 'no', basis: 'banner_version',
      fix: fixOf('php:php', 'PHP', 'update', '8.1.29'), layer: 2, reasons: [kev(360, 339)] }, 20),
    // SRV-AD: the monthly update fixes an exploited flaw; another was marked patched and a newer reading still shows it.
    open({ id: 'fv-srvad-win-1', asset_id: 'a-srvad', cve: 'CVE-2025-29824', software: winSrv16, verified: 'device', basis: 'device_version',
      fix: fixOf('microsoft:windows_server_2016', 'Windows Server 2016', 'os_update', '14393.7969', 'KB5055521', 'https://msrc.example.com/update-guide'), layer: 2,
      reasons: [{ layer: 2, source: 'msrc', name: 'Microsoft', date: day(200), url: 'https://msrc.example.com/update-guide/vulnerability/CVE-2025-29824', detail: null, due: null }, kev(200, 179)] }, 40),
    { ...open({ id: 'fv-srvad-win-2', asset_id: 'a-srvad', cve: 'CVE-2026-21589', software: winSrv16, verified: 'device', basis: 'device_version',
      fix: fixOf('microsoft:windows_server_2016', 'Windows Server 2016', 'os_update', '14393.7969', 'KB5055521', 'https://msrc.example.com/update-guide'), layer: 5, reasons: [] }, 40),
      reopened: { why: 'still_detected', at: D(0, 5), by: null },
      events: [ev(40, 'created'), ev(3, 'handled', { actor: 'it@acme.example', resolution: 'patched', via: 'person', note: 'Updated over the weekend' }), ev(0, 'reopened', { note: 'Still detected after it was marked patched' })] },
    // NAS-PHOTOS: an exploited flaw a safe check confirmed.
    open({ id: 'fv-nas02-ps-1', asset_id: 'a-nas02', cve: 'CVE-2022-27593', software: { id: 's-nas02-ps', name: 'QNAP Photo Station', version: '6.0.20' }, verified: 'scan', basis: 'scan',
      fix: fixOf('qnap:photo_station', 'Photo Station', 'update', '6.0.22', null, 'https://www.qnap.example.com/en/security-advisory/qsa-22-24'), layer: 2, reasons: [kev(1500, 1479)] }, 2),
    // A printer nobody added yet, with a flaw the vendor has not fixed.
    open({ id: 'fv-prn03-fw-1', asset_id: 'a-prn03', cve: 'CVE-2026-131402', software: { id: 's-prn03-fw', name: 'Brother printer firmware', version: '1.05' }, verified: 'device', basis: 'device_version',
      fix: fixOf('brother:printer_firmware', 'Brother printer firmware', 'none_yet', null, 'BR-2026-07', 'https://support.brother.example.com/security'), layer: 5, reasons: [] }, 1),
    // PC-ACCOUNTS-01: one CVE on two Java lines side by side: two findings, each with its own fix.
    open({ id: 'fv-pc01-java8-1', asset_id: 'a-pc01', cve: 'CVE-2026-114938', software: { id: 's-pc01-java8', name: 'Eclipse Temurin JRE 8', version: '8u462' }, verified: 'device', basis: 'device_version',
      fix: fixOf('eclipse:temurin-8', 'Java 8', 'update', '8u501'), layer: 3,
      reasons: [{ layer: 3, source: 'github-poc', name: 'GitHub', date: day(3), url: 'https://github.example.com/sample/java-poc', detail: '5 independent authors', due: null }] }, 5),
    open({ id: 'fv-pc01-java21-1', asset_id: 'a-pc01', cve: 'CVE-2026-114938', software: { id: 's-pc01-java21', name: 'Eclipse Temurin JDK 21', version: '21.0.7' }, verified: 'device', basis: 'device_version',
      fix: fixOf('eclipse:temurin-21', 'Java 21', 'update', '21.0.9'), layer: 3,
      reasons: [{ layer: 3, source: 'github-poc', name: 'GitHub', date: day(3), url: 'https://github.example.com/sample/java-poc', detail: '5 independent authors', due: null }] }, 5),
    open({ id: 'fv-pc01-java21-2', asset_id: 'a-pc01', cve: 'CVE-2026-117730', software: { id: 's-pc01-java21', name: 'Eclipse Temurin JDK 21', version: '21.0.7' }, verified: 'device', basis: 'device_version',
      fix: fixOf('eclipse:temurin-21', 'Java 21', 'update', '21.0.9'), layer: 5, reasons: [] }, 5),

    // Handled, each with who and how.
    handled({ id: 'fv-pc02-win-1', asset_id: 'a-pc02', cve: 'CVE-2025-21333', software: { id: 's-pc1', name: 'Windows', version: '11 Pro 23H2' }, verified: 'device', basis: 'device_version',
      fix: fixOf('microsoft:windows_11_23h2', 'Windows 11 23H2', 'os_update', '22631.4751', 'KB5050021'), layer: 2, reasons: [kev(300, 279)],
      resolution: 'patched', via: 'version_moved', resolved_by: 'system', from_version: '22631.4602', to_version: '22631.4751' }, 60, 2),
    handled({ id: 'fv-srvacc-sql-1', asset_id: 'a-srvacc', cve: 'CVE-2024-49112', software: { id: 's-srvacc-sql', name: 'Microsoft SQL Server', version: '2019' }, verified: 'device', basis: 'device_version',
      fix: fixOf('microsoft:sql_server_2019', 'SQL Server 2019', 'update', '15.0.4415.2'), layer: 4, reasons: [edge(120)],
      resolution: 'mitigated', via: 'person', resolved_by: 'it@acme.example', note: 'Port 1433 closed at the firewall until the update window' }, 30, 4),
    handled({ id: 'fv-pc03-win-1', asset_id: 'a-pc03', cve: 'CVE-2025-21418', software: { id: 's-pc2', name: 'Windows', version: '10 Pro 22H2' }, verified: 'device', basis: 'device_version',
      fix: fixOf('microsoft:windows_10_22h2', 'Windows 10 22H2', 'os_update', '19045.5487', 'KB5051974'), layer: 5, reasons: [],
      resolution: 'accepted', via: 'person', resolved_by: 'admin@acme.example', note: 'Replaced next month', accepted_until: ahead(30) }, 20, 6),
    handled({ id: 'fv-web01-wp-2', asset_id: 'a-web01', cve: 'CVE-2026-109112', software: { id: 's-web01-wp', name: 'WordPress website', version: '7.1.x' }, verified: 'no', basis: 'banner_version',
      fix: fixOf('wordpress:wordpress', 'WordPress', 'update', '7.1.5'), layer: 5, reasons: [],
      resolution: 'not_relevant', via: 'data_corrected', resolved_by: 'system' }, 9, 1),
  ]
}

export function seedQuestions(): QuestionRecord[] {
  const line = (n: number, cve: string): QuestionRecord => ({ id: `fq-nas01-line-${n}`, kind: 'older_line', asset_id: 'a-nas01', software: { id: 's-nas01', name: 'Synology NAS (DSM)', version: '7.2' },
    cve, cves: 1, asked_at: D(1), url: null, command: null, choices: [], fixes: ['7.3.2-86009 Update 5', '7.4.1-90080 Update 1'], line: '7.2' })
  return [
    { id: 'fq-srvfile-sql', kind: 'version_needed', asset_id: 'a-srvfile', software: { id: 's-srvfile-sql', name: 'Microsoft SQL Server', version: null }, cve: null, cves: 4,
      asked_at: D(5), url: null, command: 'SELECT @@VERSION', choices: [], cve_list: ['CVE-2026-131810', 'CVE-2026-131811', 'CVE-2026-131812', 'CVE-2026-131813'] },
    { id: 'fq-bn340-platform', kind: 'platform', asset_id: 'a-bn340', software: { id: 's-bn340-ssh', name: 'OpenSSH', version: '10.2' }, cve: 'CVE-2026-123158', cves: 1,
      asked_at: D(2), url: 'https://security.alpinelinux.example.com/vuln/CVE-2026-123158', command: 'cat /etc/alpine-release',
      choices: [{ label: 'Alpine Linux 3.23', os: 'Alpine Linux 3.23' }, { label: 'Another system', ask: ['os', 'pkg_version'] }] },
    { id: 'fq-nas01-range', kind: 'no_range_data', asset_id: 'a-nas01', software: { id: 's-nas01', name: 'Synology NAS (DSM)', version: '7.2' }, cve: 'CVE-2026-118204', cves: 1,
      asked_at: D(1), url: 'https://www.synology.example.com/en-global/security/advisory', command: null, choices: [] },
    // the vendor names fixes only on newer lines: one question per CVE
    line(1, 'CVE-2026-118210'), line(2, 'CVE-2026-118211'), line(3, 'CVE-2026-118212'),
    { id: 'fq-unk02-fgt', kind: 'not_comparable', asset_id: 'a-unk02', software: { id: 's-unk02-fgt', name: 'FortiGate', version: 'latest' }, cve: null, cves: 3,
      asked_at: D(1), url: null, command: 'get system status', choices: [], cve_list: ['CVE-2026-124401', 'CVE-2026-124402', 'CVE-2026-124403'] },
    ...routerQuestions(),
    ...sqlQuestions(),
  ]
}

/** CVEs of the possible findings that are on an exploited list. */
export const POSSIBLE_EXPLOITED = new Set(['CVE-2026-240101', 'CVE-2026-240104', 'CVE-2026-240107', 'CVE-2026-240111', 'CVE-2026-240118', 'CVE-2026-240125', 'CVE-2026-240131',
  'CVE-2026-240133', 'CVE-2026-118204', 'CVE-2026-245502'])

/** The reasons the router's 30 possible CVEs are undecided, in turn: what a real record of a network OS often looks like. */
const ROUTER_REASONS: QuestionRecord['undecided'][] = [
  { reason: 'no_ranges' },
  { reason: 'exact_releases_only', ranges: ['cpe:2.3:o:mikrotik:routeros:7.15:*:*:*:*:*:*:* [7.15, 7.15]', 'cpe:2.3:o:mikrotik:routeros:7.16:*:*:*:*:*:*:* [7.16, 7.16]'] },
  { reason: 'ranges_start_at_branch_only', ranges: ['cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:* [7.16, 7.16.2)'] },
  { reason: 'unparsed_vendor_text', text: 'RouterOS long-term releases are affected until the fix is published; stable 7.16.2 and later are not affected.', url: 'https://mikrotik.example.com/security/advisories' },
  { reason: 'eol_line_unlisted' },
  { reason: 'nvd_pending' },
]

/** A MikroTik router with 30 possible CVEs (exploited ones among them), some already checked: the realistic large case. */
function routerQuestions(): QuestionRecord[] {
  return Array.from({ length: 32 }, (_, i): QuestionRecord => {
    const cve = `CVE-2026-2401${String(i + 1).padStart(2, '0')}`
    const u = ROUTER_REASONS[i % ROUTER_REASONS.length]!
    return {
      id: `fq-rt02-${i + 1}`, kind: u.reason === 'eol_line_unlisted' ? 'older_line' : 'no_range_data', asset_id: 'a-rt02',
      software: { id: 's-rt02', name: 'MikroTik RouterOS', version: '7.14' }, cve, cves: 1, asked_at: D(3), url: 'https://mikrotik.example.com/security/advisories',
      command: null, choices: [], versions_listed: u.reason !== 'no_ranges', undecided: u, ...(u.reason === 'eol_line_unlisted' ? { line: '7.14', fixes: ['7.16.2 (stable)', '7.15.3 (long-term)'] } : {}),
    }
  })
}

/** A software line with a very long name on a server, three possible CVEs. */
function sqlQuestions(): QuestionRecord[] {
  const sw = { id: 's-srvacc-sql', name: 'Microsoft SQL Server 2019 Enterprise Edition (64-bit) with Reporting Services and Integration Services', version: '15.0.4385.2' }
  return [
    { id: 'fq-srvacc-1', kind: 'no_range_data', asset_id: 'a-srvacc', software: sw, cve: 'CVE-2026-245501', cves: 1, asked_at: D(2), url: null, command: null, choices: [], undecided: { reason: 'no_ranges' } },
    { id: 'fq-srvacc-2', kind: 'no_range_data', asset_id: 'a-srvacc', software: sw, cve: 'CVE-2026-245502', cves: 1, asked_at: D(2), url: null, command: null, choices: [], versions_listed: true,
      undecided: { reason: 'exact_releases_only', ranges: ['cpe:2.3:a:microsoft:sql_server_2019:15.0.4360.2:*:*:*:*:*:x64:* [15.0.4360.2, 15.0.4360.2]'] } },
    { id: 'fq-srvacc-3', kind: 'no_range_data', asset_id: 'a-srvacc', software: sw, cve: 'CVE-2026-245503', cves: 1, asked_at: D(2), url: null, command: null, choices: [], undecided: { reason: 'fetch_failed' } },
  ]
}

/** The evidence identity of one possible CVE (64 hex), as the match computes it from the CVE, the line and the version. */
export function checkKeyOf(q: Pick<QuestionRecord, 'id' | 'kind' | 'software' | 'undecided'>, cve: string): string {
  const reason = q.undecided?.reason
  // nothing a check can read decides these: the person's input does (the version, the system, the package release, the edition)
  if (q.kind === 'version_needed' || q.kind === 'platform' || q.kind === 'package_release' || reason === 'nvd_pending' || !q.software?.version) return ''
  let h = 2166136261
  let out = ''
  for (let round = 0; round < 8; round++) {
    for (const c of `${round}|${cve}|${q.software.id}|${q.software.version}`) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0
    out += h.toString(16).padStart(8, '0')
  }
  return out
}

/** A stored check of a possible CVE, keyed by its evidence identity. */
export type CheckRecord = PossibleCheck
const AI_SOURCES = [
  { url: 'https://mikrotik.example.com/security/advisories/routeros-2026-07', title: 'MikroTik security advisory: RouterOS WinBox and WebFig', status: 'ok' as const, cited: true },
  { url: 'https://nvd.example.org/vuln/detail', status: 'ok' as const },
  { url: 'https://blog.example.net/routeros-analysis', status: 'failed' as const, note: 'the page answered 403' },
]

/** The checks already made: AI proposals waiting (one exploited "not affected", confirmed one by one), an unsure one, a rejected one
 *  and two the box settled from the vendor's advisory. */
export function seedPossibleChecks(): Record<string, CheckRecord> {
  const rt = (i: number) => ({ id: `fq-rt02-${i}`, kind: 'no_range_data' as const, software: { id: 's-rt02', name: 'MikroTik RouterOS', version: '7.14' }, undecided: ROUTER_REASONS[(i - 1) % ROUTER_REASONS.length] })
  const at = D(0, 3)
  const ai = (q: ReturnType<typeof rt>, cve: string, verdict: CheckRecord['verdict'], confidence: CheckRecord['confidence'], quote: string, reason: string, extra: Partial<CheckRecord> = {}): [string, CheckRecord] => {
    const key = checkKeyOf(q, cve)
    return [key, { key, decided_by: 'ai', verdict, confidence, reason, quote, sources: AI_SOURCES, model: 'qwen3:8b', checked_by: 'it@example.com', checked_at: at, rejected: false, reading: null, ...extra }]
  }
  // the AI's reading of the vendor's statement for the release line (stored once per line, applied to every device on it)
  const reading = (host: string, status: NonNullable<CheckRecord['reading']>['status'], vendor: boolean, found = true, statedLine: string | null = '7.15') =>
    ({ reading: { status, line: '7.14', stated_line: statedLine, introduced: null, fixed_in: null, last_affected: null, host, vendor_page: vendor, quote_found: found } })
  const advisory = (q: ReturnType<typeof rt>, cve: string, quote: string): [string, CheckRecord] => {
    const key = checkKeyOf(q, cve)
    return [key, { key, decided_by: 'advisory', verdict: 'not_affected', confidence: null, reason: 'The vendor lists the affected releases from 7.15 on; 7.14 is older than the first affected release.',
      quote, sources: [AI_SOURCES[0]!], model: null, checked_by: 'it@example.com', checked_at: at, rejected: false, reading: null }]
  }
  const sql = { id: 'fq-srvacc-1', kind: 'no_range_data' as const, software: { id: 's-srvacc-sql', name: 'Microsoft SQL Server 2019 Enterprise Edition (64-bit) with Reporting Services and Integration Services', version: '15.0.4385.2' }, undecided: { reason: 'no_ranges' as const } }
  return Object.fromEntries([
    ai(rt(1), 'CVE-2026-240101', 'affected', 'confident', 'RouterOS versions 7.10 through 7.15.2 are affected; upgrade to 7.15.3 or 7.16.2.',
      'The advisory names the range 7.10 through 7.15.2, which covers 7.14.'),
    ai(rt(2), 'CVE-2026-240102', 'not_affected', 'likely', 'Only devices running the container package are affected.', 'The advisory limits it to the container package; nothing says it is installed.'),
    ai(rt(8), 'CVE-2026-240108', 'unsure', null, 'RouterOS 7.14 is not affected by this issue.', 'A third-party analysis says 7.14 is not affected; the vendor\'s page says nothing about it.',
      { ...reading('blog.example.net', 'not_affected', false, true, '7.14'), sources: [{ url: 'https://blog.example.net/routeros-analysis', status: 'ok' as const, cited: true }] }),
    ai(rt(7), 'CVE-2026-240107', 'not_affected', 'confident', 'This issue affects RouterOS 7.15 and later releases only; 7.14 is not affected.', 'The vendor names 7.15 and later; 7.14 is older.',
      reading('mikrotik.example.com', 'not_affected', true, true, '7.14')),
    ai(rt(9), 'CVE-2026-240109', 'unsure', null, '', 'The pages do not name RouterOS versions.', reading('mikrotik.example.com', 'unsure', true, false, null)),
    ai(rt(10), 'CVE-2026-240110', 'unsure', null, 'All RouterOS v7 releases before 7.16 are affected.', 'The advisory says all v7 releases before 7.16.',
      { rejected: true, ...reading('mikrotik.example.com', 'fixed', true) }),
    [checkKeyOf(rt(19), 'CVE-2026-240119'), { key: checkKeyOf(rt(19), 'CVE-2026-240119'), decided_by: 'structured' as const, verdict: 'unsure' as const, confidence: null,
      reason: 'The CVE\'s reference pages have no advisory text the box can read (they may need a browser).', quote: '',
      sources: [{ url: 'https://portal.example.com/kb/A1190', status: 'failed' as const, note: 'the page has no advisory text the box can read (it may need a browser)' }],
      model: null, checked_by: 'system', checked_at: at, rejected: false, reading: null }],
    ai(rt(13), 'CVE-2026-240113', 'affected', 'likely', 'Versions up to 7.15 are vulnerable when WebFig is enabled.', 'The advisory says up to 7.15 with WebFig on.'),
    ai(sql, 'CVE-2026-245501', 'affected', 'likely', 'SQL Server 2019 CU28 and earlier are affected.', 'The bulletin lists SQL Server 2019 up to CU28; 15.0.4385.2 is CU28.'),
    advisory(rt(31), 'CVE-2026-240131', '7.15 versions from 7.15rc1 before 7.15.3'),
    advisory(rt(32), 'CVE-2026-240132', '7.16 versions before 7.16.2'),
  ])
}
