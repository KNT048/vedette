// API contract of the reports module. The UI types are inferred from the schemas here (types.ts).
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

const iso = z.iso.datetime()
const email = z.string().max(120)
// One open finding of the assessment's risks.
export const FindingRow = z.object({
  id: z.string(), cve: z.string(), device: z.string(), asset_id: z.string(), product: z.string(),
  status: z.enum(['confirmed', 'suspected', 'mitigated', 'patched', 'false_positive', 'not_relevant', 'risk_accepted']),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']), since: iso,
  agent: z.boolean().optional().describe("The version compared is the one the device's own agent reports (findings evidence.agent): the status reads \"Detected by the agent\", not \"Suspected\"; absent in reports sent before it"),
  device_approved: z.boolean().optional().describe('False when the device is still to review, not in the Devices list yet; absent in reports made before it (read as approved)'),
})
export const AiSummary = z.object({ paragraphs: z.array(z.string()), model: z.string(), profile: z.string().optional().describe('AI profile that answered'), tokens: z.object({ input: z.number(), output: z.number() }), generated_at: iso })

export const DataVolume = z.enum(['lt1k', '1k_10k', '10k_100k', 'gte100k'])
export const OrgSize = z.enum(['household', 'micro', 'small', 'startup', 'other'])
export const PdplOrg = z.object({
  name: z.string(), tax_code: z.string(), address: z.string(), sector: z.string(), employees: z.number().int(), data_volume: DataVolume,
  size: OrgSize.describe('Organization size under the small and medium enterprise law; decides whether Article 41 of Decree 356/2025/NĐ-CP applies'),
  processing_service: z.boolean().describe('Provides personal data processing services to others'),
  contact_name: z.string(), contact_email: z.string(), contact_phone: z.string(),
  sensitive: z.boolean(), cross_border: z.boolean(), processors: z.boolean(),
  level: z.enum(['', '1', '2', '3', '4', '5']).describe('Information system security level; empty = not determined. Not part of the personal data protection law'),
})
export const Measure = z.object({ id: z.enum(['firewall', 'patching', 'eol', 'unapproved', 'remote', 'logging', 'honeypot', 'scan', 'backup']), status: z.enum(['ok', 'attention', 'unknown']), n: z.number(), names: z.array(z.string()) })
export const Obligation = z.object({
  id: z.enum(['dpia', 'dpo', 'breach', 'consent', 'sensitive', 'cross_border', 'processors']),
  applies: z.boolean(),
  regime: z.enum(['required', 'optional', 'exempt']).describe('For dpia and dpo under Article 38 of Law 91/2025/QH15 and Article 41 of Decree 356/2025/NĐ-CP; other items are always required'),
  done: z.boolean().nullable(),
})
export const PdplInventory = z.object({
  total: z.number(), approved: z.number(), unapproved: z.number(), fragile: z.number(),
  by_kind: z.array(z.object({ kind: z.string(), n: z.number() })),
  key_systems: z.array(z.object({ id: z.string(), name: z.string(), ip: z.string(), kind: z.string(), os: z.string() })),
  sources: z.array(z.object({ source: z.string(), n: z.number() })),
})
export const PdplReport = z.object({
  id: z.string(), generated_at: iso, org: PdplOrg,
  inventory: PdplInventory,
  measures: z.array(Measure), risks: z.array(FindingRow), obligations: z.array(Obligation),
  coverage: z.array(z.object({ module: z.string(), on: z.boolean() })), ai_summary: AiSummary.nullable(),
  approved_only: z.object({ inventory: PdplInventory, measures: z.array(Measure), risks: z.array(FindingRow) }).optional()
    .describe('The inventory, measures and risks again without the devices not in the Devices list (not approved yet) and their findings; the unapproved measure stays the full one. Absent in reports generated before it'),
})
export const PdplState = z.object({ org: PdplOrg.nullable(), defaults: z.object({ name: z.string() }), report: PdplReport.nullable(), ai_available: z.boolean() })

// ---- The periodic security report: one definition (options, recipients), the document it makes, the sent documents ----
// Statuses, severity, reasons, verification, fix and the handled line are the findings vocabulary and shapes; incident
// kinds are the detection ones; proof states and issue engines are the exposure ones. Copied field for field while those
// contracts live on their own branches: import them when they merge.

// Same shape as the findings contract (lib/statusCodes.ts); import it when the findings branch merges.
export const OpenStatus = z.enum(['under_attack', 'exploited', 'public_exploit', 'critical_edge', 'update_recommended'])
  .describe('The open statuses: the urgency layers 1 to 5 in order')
// Same shape as the findings contract (Resolution); import it when the findings branch merges.
export const HandledStatus = z.enum(['patched', 'mitigated', 'accepted', 'not_relevant', 'false_positive'])
  .describe('How a finding was handled; a handled finding\'s status is its resolution')
export const FindingStatus = z.enum([...OpenStatus.options, ...HandledStatus.options]).describe('The one status of a finding, most urgent first')
// Same shape as the findings contract; import it when the findings branch merges.
export const Via = z.enum(['person', 'version_moved', 'software_removed', 'distro_fixed', 'scan_clear', 'data_corrected', 'not_installed'])
  .describe('How it was handled: person = a person marked it; version_moved = the software moved past the affected version; software_removed = the software is gone; distro_fixed = the distribution says the installed package is fixed; scan_clear = a safe check that had matched came back clear; data_corrected = no longer detected while nothing on the device changed (never patch credit); not_installed = a person said the software is not installed')
// Same shape as the findings contract; import it when the findings branch merges.
export const Verified = z.enum(['no', 'device', 'scan', 'person'])
// Same shape as the findings contract; import it when the findings branch merges.
export const Basis = z.enum(['scan', 'device_version', 'package', 'banner_version', 'statement', 'person'])
// Same shape as the findings contract; import it when the findings branch merges.
export const FixKind = z.enum(['update', 'distro_update', 'os_update', 'feature_update', 'restart', 'none_yet', 'unknown'])
// Same shape as the findings contract; import it when the findings branch merges.
export const SeverityBand = z.enum(['critical', 'high', 'medium', 'low', 'none'])
// Same shape as the detection contract (DetectionKind); import it when the detection branch merges.
export const DetectionKind = z.enum(['trap', 'bad_address', 'log_anomaly', 'unknown_device', 'intrusion'])
// Same shape as the exposure contract (ProofState, IssueEngine); import them when the exposure branch merges.
export const ProofState = z.enum(['proven', 'covered', 'missing', 'expired', 'not_current'])
export const IssueEngine = z.enum(['surface', 'nuclei', 'zap', 'openvas', 'match'])
const slug = z.string().regex(/^[a-z0-9-]{1,40}$/)

// Same shape as the findings contract (CveSeverity); import it when the findings branch merges.
export const CveSeverity = z.object({
  band: SeverityBand,
  score: z.number().min(0).max(10),
  version: z.enum(['4.0', '3.1', '3.0', '2.0']),
  vector: z.string().min(1).max(200),
}).describe('The CVSS base score of the CVE and its band. Never changes the status. null = "Not scored yet", never 0')
export const DeviceRef = z.object({
  id: z.string().describe('The device id when the report was made; the device may be gone since'),
  name: z.string().max(200),
  added: z.boolean().describe('false = "Not added yet"'),
})
// Same shape as the findings contract; import it when the findings branch merges.
export const Verification = z.object({
  verified: Verified,
  basis: Basis,
  by: z.string().nullable().describe('verified person: who confirmed it'),
  at: iso.nullable().describe('When it was confirmed; null while not confirmed'),
})
// Same shape as the findings contract; import it when the findings branch merges.
export const Fix = z.object({
  key: z.string().min(1).max(400).describe('The "By fix" group; opaque'),
  kind: FixKind,
  product: z.string().describe('The product the fix is for, as people name it'),
  version: z.string().nullable().describe('update, distro_update, feature_update: the version or release to install; os_update: the build when known'),
  ref: z.string().nullable().describe('os_update: the KB number; none_yet: the advisory id when known'),
  url: z.url().nullable().describe('The vendor advisory or release notes'),
  channel: z.enum(['public', 'ubuntu_pro', 'esu']).optional().describe('Where the fix is published: ubuntu_pro = only Ubuntu Pro (ESM) has it; esu = only Windows Extended Security Updates; public or absent = an ordinary update (absent in documents sent before it was kept)'),
})
// Same shape as the findings contract; import it when the findings branch merges.
export const Reason = z.object({
  layer: z.number().int().min(1).max(4),
  source: slug.describe('The signal source: cisa-kev, msrc, chrome, cisco, fortinet, apple, android, rapid7, gti, nuclei, metasploit, exploit-db, github-poc; ids for an attack seen here (layer 1); cvss for layer 4'),
  name: z.string().describe('The source as people name it: "CISA KEV", "Rapid7", "GitHub"'),
  date: z.iso.date().describe('When the source said so; layer 1: the newest alert; layer 4: since when the rule holds'),
  url: z.url().nullable(),
  detail: z.string().max(120).nullable().describe('A short fact of the signal: "244 stars", the attacker address for layer 1'),
  due: z.iso.date().nullable().describe('Layer 2: the day the list asks for the fix (CISA KEV due date); null otherwise'),
}).describe('One urgency layer that applies, with its evidence')
// Same shape as the findings contract; import it when the findings branch merges.
export const Handled = z.object({
  resolution: HandledStatus,
  via: Via,
  by: z.string().describe('"system" when Vedette handled it; else the person'),
  at: iso,
  note: z.string().nullable(),
  accepted_until: z.iso.date().nullable().describe('accepted: the last day; null otherwise'),
  from_version: z.string().nullable().describe('via version_moved: the version that was affected'),
  to_version: z.string().nullable().describe('via version_moved: the version now installed'),
}).describe('Who and how, from stored fields: "Patched by Vedette: version moved 6.24 → 7.23 (18 Nov)"')

export const ReportFinding = z.object({
  finding_id: z.string(), cve: z.string(), device: DeviceRef,
  product: z.string().max(200).describe('The software line the CVE is on, as Findings names it'),
  version: z.string().max(80).nullable().describe('The version the finding was matched on'),
  status: FindingStatus, reasons: z.array(Reason).describe('Every layer 1 to 4 that applies, most urgent first; empty for layer 5'),
  severity: CveSeverity.nullable(), verification: Verification, fix: Fix, first_seen: iso,
})
export const HandledItem = z.object({
  finding_id: z.string(), cve: z.string(), product: z.string().max(200), severity: CveSeverity.nullable(),
  handled: Handled,
  reopened_at: iso.optional().describe('It opened again after this handling, inside the period, and is open at its end (listed in Still open too); absent otherwise and in reports sent before it existed'),
}).describe('One finding handled in the period')
export const PeriodKind = z.enum(['last_7_days', 'last_30_days', 'calendar_month'])
  .describe('calendar_month = the last whole calendar month in the organisation time zone')
export const ReportOptions = z.object({
  period: PeriodKind,
  grouping: z.enum(['device', 'cve']).describe('How Still open is grouped'),
  include_not_added: z.boolean().describe('Count and list devices not added yet (default on)'),
  include_not_relevant: z.boolean().describe('Count and list findings handled as not relevant (default off)'),
  sections: z.object({
    summary: z.boolean(), handled: z.boolean(), open: z.boolean(), new: z.boolean(), exposure: z.boolean(), detections: z.boolean(), coverage: z.boolean(),
  }).describe('Which sections the report has'),
  charts: z.boolean(),
})
export const ReportDefinition = z.object({
  id: z.string(), name: z.string().min(1).max(80),
  options: ReportOptions,
  recipients: z.array(email).max(20),
  schedule_key: z.string().describe('The owner key of its schedule in the shared schedules (GET/PUT /schedules/{owner_key}), reports.def:<id>'),
  updated_at: iso, updated_by: z.string(),
}).describe('The one report: a single template with section switches, its period, recipients and schedule')
export const ReportDefinitionInput = ReportDefinition.pick({ name: true, options: true, recipients: true })

export const ReportSummary = z.object({
  open_by_status: z.array(z.object({ status: OpenStatus, n: z.number().int() })).describe('Open findings now, one row per status that has any'),
  open_now: z.number().int().describe('Open at the end of the period'),
  open_before: z.number().int().describe('Open at the start of the period'),
  new: z.number().int().describe('Findings first seen in the period, whether still open or handled since (the New section counts the same)'),
  handled: z.number().int().describe('Findings handled in the period (the Handled section counts the same). open_before + new - handled + reopened differs from open_now only by other changes: a finding left out since the start'),
  reopened: z.number().int().optional().describe('Findings open at the end that opened again in the period after a handling; absent when none and in reports sent before it existed'),
  first: z.array(z.object({
    status: OpenStatus, cve: z.string(), finding_id: z.string().describe('Its most urgent finding'), product: z.string().max(200),
    severity: CveSeverity.nullable(), fix: Fix, devices: z.array(DeviceRef).max(3), device_count: z.number().int(), finding_count: z.number().int(),
  })).max(3).describe('The three things to do first, most urgent first'),
})
export const ReportHandled = z.object({
  totals: z.array(z.object({ resolution: HandledStatus, via: Via, n: z.number().int() })).describe('Handled in the period by resolution'),
  devices: z.array(z.object({ device: DeviceRef, items: z.array(HandledItem) })),
  more: z.number().int().describe('Handled findings not listed (a report lists 100 at most)'),
  median_days: z.number().min(0).nullable().describe('Median days from first seen to handled, of the findings patched or mitigated in the period; null when none'),
  not_relevant_left_out: z.number().int().min(0).optional().describe('Findings closed as not relevant in the period that this report leaves out ("Include not relevant" off): why its count is lower than Findings › Handled. Absent when none, and in documents sent before it existed'),
})
export const ReportOpen = z.object({
  grouping: z.enum(['device', 'cve']), total: z.number().int(),
  groups: z.array(z.object({
    key: z.string().describe('The device id or the CVE'), label: z.string().max(200), status: OpenStatus.describe('The most urgent status in the group'),
    items: z.array(ReportFinding),
    total: z.number().int().optional().describe('Every open finding of the group, listed or not (items stops at the 100 rows a report lists); absent in reports sent before it was counted'),
  })).describe('Most urgent first'),
  more: z.number().int().describe('Open findings not listed (a report lists 100 at most)'),
})
export const ReportNew = z.object({ total: z.number().int().describe('Findings first seen in the period, open or handled since; equals summary.new'),
  open: z.number().int().optional().describe('Of total, the findings still open at the end of the period, listed or not; absent in reports sent before it was counted'), items: z.array(ReportFinding).describe('Found in the period, with their status now (open or how it was handled)'), more: z.number().int() })
export const ExposureService = z.object({
  ip: z.string(), port: z.number().int().min(1).max(65535), proto: z.enum(['tcp', 'udp']),
  name: z.string().max(80).nullable(), product: z.string().max(200).nullable(), version: z.string().max(80).nullable(),
  change: z.enum(['new', 'closed']).nullable().describe('Opened or closed during the period; null = unchanged'),
  cert_expires_at: iso.nullable().describe('When the TLS certificate it serves expires'),
})
export const ExposureTarget = z.object({
  target_id: z.string(), kind: z.enum(['domain', 'ip']), value: z.string().max(253),
  parent: z.string().max(253).nullable().describe('The apex domain this target sits under'),
  proof: ProofState.describe('proven: its own proof holds; covered: the proof of a parent domain covers it; missing; expired; not_current'),
  last_scan_at: iso.nullable(),
  services: z.array(ExposureService).describe('Open ports, then those closed in the period'),
  issues: z.array(z.object({ engine: IssueEngine, severity: z.enum(['critical', 'high', 'medium', 'low', 'info']), open: z.number().int(), new: z.number().int() })),
})
export const ReportExposure = z.object({
  module_on: z.boolean().describe('False when external exposure is off: the section says so instead of showing nothing'),
  targets: z.array(ExposureTarget),
})
export const ReportDetections = z.object({
  module_on: z.boolean().describe('False when detection is off'),
  by_kind: z.array(z.object({ kind: DetectionKind, n: z.number().int(), last_at: iso })),
  top: z.array(z.object({ kind: DetectionKind, title: z.string().max(200), severity: z.enum(['critical', 'high', 'medium', 'low', 'info']), device: DeviceRef.nullable(),
    device_count: z.number().int().min(2).optional().describe('How many devices the incident names when more than one (device is the first); absent for one device and in reports sent before it existed'),
    at: iso })).max(5),
})
export const ReportCoverage = z.object({
  devices: z.number().int(), with_agent: z.number().int(), not_added: z.number().int(),
  sources: z.array(z.object({ id: slug.describe('The module that sees it: sensor-passive, sensor-active, agent-intake, honeypot, logs, exposure, ids'), on: z.boolean() })),
  feeds: z.array(z.object({ id: slug.describe('The feed id: cisa-kev, vulncheck-kev, nvd, or a custom feed id'), name: z.string().max(80), last_ok_at: iso.nullable(), stale: z.boolean() })),
})
export const ReportDocument = z.object({
  definition_id: z.string(), title: z.string().max(120), generated_at: iso,
  org: z.string().max(120).describe('The organisation name when the report was made, so a sent report keeps it'),
  period: z.object({ kind: PeriodKind, from: iso, to: iso, tz: z.string().max(64) }),
  options: ReportOptions.describe('The options the document was made with'),
  summary: ReportSummary.optional(), handled: ReportHandled.optional(), open: ReportOpen.optional(), new: ReportNew.optional(),
  exposure: ReportExposure.optional(), detections: ReportDetections.optional(), coverage: ReportCoverage.optional(),
  ai_summary: AiSummary.nullable(),
}).describe('The report as made at generated_at; a section switched off is absent')
export const SentReportItem = z.object({
  id: z.string(), definition_id: z.string(), title: z.string().max(120), sent_at: iso,
  period: z.object({ from: iso, to: iso }),
  trigger: z.enum(['manual', 'schedule']), recipients: z.array(email), status: z.enum(['sent', 'failed']), error: z.string().nullable(),
  sent_by: z.string().nullable().describe('Who pressed Send now; null for a scheduled send'),
})
export const SentReport = SentReportItem.extend({ document: ReportDocument.describe('Exactly what was sent') })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/reports/definition', summary: 'The report definition: name, options, section switches, recipients and the key of its schedule', stories: ['S-REP-1'], role: 'viewer', response: ReportDefinition },
  { method: 'put', path: '/reports/definition', summary: 'Save the report name, options and recipients (emails validated, max 20)', stories: ['S-REP-1'], role: 'admin', body: ReportDefinitionInput, response: ReportDefinition },
  { method: 'get', path: '/reports/document', summary: 'The report of the current period, made with the saved options when opened', stories: ['S-REP-1'], role: 'viewer', response: ReportDocument },
  { method: 'post', path: '/reports/send', summary: 'Make the report now and send it to the saved recipients; the sent document is kept', stories: ['S-REP-1'], role: 'operator', response: SentReportItem },
  { method: 'get', path: '/reports/history', summary: 'Reports sent, newest first', stories: ['S-REP-1'], role: 'viewer', response: z.object({ items: z.array(SentReportItem) }) },
  { method: 'get', path: '/reports/history/{id}', summary: 'One sent report, the document exactly as it was sent', stories: ['S-REP-1'], role: 'viewer', params: z.object({ id: z.string() }), response: SentReport, example: { params: { id: 'rh-1' } } },
  { method: 'get', path: '/reports/pdpl', summary: 'Organization details and the generated assessment report', stories: ['S-REP-2'], role: 'viewer', response: PdplState },
  { method: 'put', path: '/reports/pdpl/org', summary: 'Save organization details for the assessment report (each field validated)', stories: ['S-REP-2'], role: 'operator', body: PdplOrg, response: PdplOrg },
  { method: 'post', path: '/reports/pdpl/generate', summary: 'Generate the assessment report from inventory, findings and module status', stories: ['S-REP-2'], role: 'operator', response: PdplReport },
  { method: 'post', path: '/reports/pdpl/ai-summary', summary: 'Draft a commentary for the assessment report with the customer AI', stories: ['S-REP-2', 'S-AI-6'], role: 'operator', response: AiSummary },
])
