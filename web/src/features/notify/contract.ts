// Hợp đồng API module notify (D-18). Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

const iso = z.iso.datetime()

export const ChannelType = z.enum(['telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook'])
export const RouteSeverity = z.enum(['critical', 'high', 'medium', 'low'])
export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info'])

export const TestResult = z.object({ at: iso, ok: z.boolean(), detail: z.string() })
export const Approver = z.object({ user_id: z.string(), address: z.string().describe('Slack member ID · Telegram user ID · sign-in email · Zalo user ID or phone') })
export const Channel = z.object({
  type: ChannelType,
  configured: z.boolean(),
  enabled: z.boolean(),
  fields: z.record(z.string(), z.string()).describe('Non-secret fields: telegram chat_id · zalo oa_id, user_id · zalo-personal user_id (recipient user or group ID; session is the secret) · email host, port, security (starttls|ssl|none), username, from, to · webhook url · slack label (optional), channel_id (approvals only)'),
  secret_last4: z.string().nullable().describe('Secrets (token, password, signing key) are never returned, only the last 4 characters (SYS-4)'),
  min_severity: RouteSeverity,
  last_test: TestResult.nullable(),
  approvals: z.boolean().describe('Approve actions from this channel (Slack, Telegram, Email, Zalo personal; D-38, D-46)'),
  approvers: z.array(Approver).describe('Vedette users (operator or admin) allowed to approve from this channel, with their address on it'),
  approval_last4: z.object({ app_token: z.string().nullable(), bot_token: z.string().nullable() }).describe('Slack Socket Mode tokens (xapp-, xoxb-): only the last 4 characters are returned'),
})
export const ChannelInput = z.object({
  enabled: z.boolean(),
  fields: z.record(z.string(), z.string()),
  secret: z.string().optional().describe('Leave blank to keep the saved secret'),
  min_severity: RouteSeverity,
  approvals: z.boolean().optional().describe('Slack, Telegram, Email and Zalo personal only; Zalo OA and webhook reject it'),
  approvers: z.array(Approver).optional().describe('Required (at least one) when approvals is on'),
  app_token: z.string().optional().describe('Slack app-level token (xapp-…) for Socket Mode; leave blank to keep the saved one'),
  bot_token: z.string().optional().describe('Slack bot token (xoxb-…); leave blank to keep the saved one'),
})
export const Quiet = z.object({ enabled: z.boolean(), from: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/), to: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/), allow_critical: z.boolean() })
export const Grouping = z.object({ enabled: z.boolean(), window_min: z.union([z.literal(15), z.literal(60), z.literal(240)]) })
export const Rules = z.object({ quiet: Quiet, grouping: Grouping })
export const ChannelsResponse = z.object({ channels: z.array(Channel), quiet: Quiet, grouping: Grouping, email_code_users: z.number().int().describe('Users who sign in with two-step email codes: they cannot sign in while the email channel is off or removed') })

export const IncidentKind = z.enum(['trap', 'bad_address', 'log_anomaly', 'unknown_device'])
export const IncidentStatus = z.enum(['new', 'acknowledged', 'resolved'])
export const SendRecord = z.object({ id: z.string(), channel: ChannelType, to: z.string(), at: iso, ok: z.boolean(), error: z.string().optional() })
export const Incident = z.object({
  id: z.string(),
  kind: IncidentKind,
  title: z.string().describe('One plain-words sentence: who did what'),
  link: z.string().describe('Where to view the source: /honeypot/hits/<id> (trap), /logs (bad address, log anomaly), /devices/<id> (unknown device)'),
  devices: z.array(z.object({ id: z.string(), name: z.string() })),
  severity: Severity,
  what: z.string(),
  action: z.string(),
  first_seen: iso,
  last_seen: iso,
  count: z.number().int().describe('Repeats of the same thing are grouped into one incident'),
  status: IncidentStatus,
  handled_by: z.string().nullable().describe('Who acknowledged or resolved it'),
  handled_at: iso.nullable(),
  note: z.string().nullable(),
  sends: z.array(SendRecord),
})
export const Preview = z.object({ channel: ChannelType, subject: z.string().optional(), text: z.string() })
export const IncidentDetail = z.object({ incident: Incident, previews: z.array(Preview) })
export const IncidentsResponse = z.object({ incidents: z.array(Incident) })
export const HistoryItem = z.object({
  id: z.string(), at: iso, channel: ChannelType, to: z.string(), ok: z.boolean(), error: z.string().optional(),
  kind: z.enum(['incident', 'vuln', 'approval']), what: z.string(), link: z.string(),
})
export const HistoryResponse = z.object({ items: z.array(HistoryItem), suppressed: z.object({ count: z.number().int(), days: z.number().int() }) })
export const FindingNotices = z.object({ sends: z.array(SendRecord) })
export const LegacyTarget = z.object({ to: z.string() })

const id = z.object({ id: z.string() })
const type = z.object({ type: ChannelType })

export const endpoints = defineEndpoints([
  { method: 'get', path: '/notify/incidents', summary: 'List incidents: trap touched, connection to a known-bad address, log anomaly, unknown device (repeats grouped); no vulnerabilities', stories: ['S-ALERT-3'], role: 'viewer', response: IncidentsResponse },
  { method: 'get', path: '/notify/incidents/{id}', summary: 'Incident details: what happened, content sent per channel, delivery log', stories: ['S-ALERT-3'], role: 'viewer', params: id, response: IncidentDetail, example: { params: { id: 'al-4' } } },
  { method: 'patch', path: '/notify/incidents/{id}', summary: 'Acknowledge, resolve or reopen an incident, with a note', stories: ['S-ALERT-3'], role: 'operator', params: id, body: z.object({ status: IncidentStatus, note: z.string().max(500).optional() }), response: IncidentDetail },
  { method: 'get', path: '/notify/history', summary: 'Every message sent (incidents, vulnerability notices, approval requests) and the count of new vulnerabilities matching no device (not sent)', stories: ['S-ALERT-1', 'S-NOT-1'], role: 'admin', response: HistoryResponse },
  { method: 'post', path: '/notify/history/{id}/resend', summary: 'Send a message again through the same channel', stories: ['S-NOT-1'], role: 'operator', params: id, response: HistoryItem },
  { method: 'get', path: '/notify/findings/{id}/notices', summary: 'Who was notified about this finding, on which channel, and whether it arrived', stories: ['S-ALERT-1'], role: 'viewer', params: id, response: FindingNotices, example: { params: { id: 'f-1' } } },
  { method: 'get', path: '/notify/alerts/{id}/target', summary: 'Old alert link: the incident or the finding it became (D-52)', stories: ['S-ALERT-3'], role: 'viewer', params: id, response: LegacyTarget, example: { params: { id: 'al-1' } } },
  { method: 'get', path: '/notify/channels', summary: 'Alert channels, quiet hours, batching rules (without secrets), and how many users sign in with email codes', stories: ['S-NOT-1'], role: 'admin', response: ChannelsResponse },
  { method: 'put', path: '/notify/channels/{type}', summary: 'Save the configuration of one channel (Telegram, Slack, Zalo OA, Zalo personal, Email, Webhook), including approvals (switch + approvers list) per channel; the email channel also carries two-step sign-in codes', stories: ['S-NOT-1', 'S-NOT-2', 'S-RESP-2'], role: 'admin', params: type, body: ChannelInput, response: Channel },
  { method: 'delete', path: '/notify/channels/{type}', summary: 'Delete the saved configuration and secret of a channel', stories: ['S-NOT-1'], role: 'admin', params: type, response: null },
  { method: 'post', path: '/notify/channels/{type}/test', summary: 'Send a test message through the saved channel', stories: ['S-NOT-1'], role: 'admin', params: type, response: TestResult },
  { method: 'put', path: '/notify/rules', summary: 'Save quiet hours and batching rules', stories: ['S-NOT-1'], role: 'admin', body: Rules, response: Rules },
])
