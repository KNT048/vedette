// Hợp đồng API module notify (D-18). Kiểu UI suy ra từ schema ở đây (types.ts), nên UI ↔ mock ↔ OpenAPI không lệch.
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'

const iso = z.iso.datetime()

export const ChannelType = z.enum(['telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook'])
export const RouteSeverity = z.enum(['critical', 'high', 'medium', 'low'])
export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info'])

export const TestResult = z.object({ at: iso, ok: z.boolean(), detail: z.string() })
export const Approver = z.object({ user_id: z.string(), address: z.string().describe('Slack member ID · Telegram user ID · sign-in email · Zalo user ID (digits, not a phone number); unique per channel'), name: z.string().optional().describe('Zalo personal: the shown name of the approver\'s Zalo account, from the picker (D-447)') })
export const Channel = z.object({
  type: ChannelType,
  configured: z.boolean(),
  enabled: z.boolean(),
  fields: z.record(z.string(), z.string()).describe('Non-secret fields: telegram chat_id · zalo oa_id, user_id, app_id (the Zalo app of the refresh-token flow, D-483; absent for a channel with only an access token) · zalo-personal user_id (recipient user or group ID), group ("true" for a group), name (shown name of the recipient), account (shown name of the signed-in Zalo account; set by the box from the QR sign-in, D-447; the session is the secret) · email provider (preset, D-449: custom|gmail|yahoo|icloud|zoho|fastmail|sendgrid|mailgun|ses|postmark|brevo|microsoft365|google-workspace; D-480 user sign-ins: microsoft365-user|outlook|gmail-oauth, saved with signin; absent = custom), host, port, security (starttls|ssl|none), username (the mailbox for microsoft365 and google-workspace; none for postmark, whose server token is the secret), tenant_id (microsoft365, microsoft365-user, outlook) and client_id (those and gmail-oauth), from, to, secret_for (written by the box: the sign-in method, server and port the saved secret is for; changing one needs the secret again) · webhook url (a secret: sealed on save, returned only as scheme://host/… followed by its last 4 characters; send it empty, or as returned, to keep the saved one) · slack label (optional), channel_id (approvals only)'),
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
  secret: z.string().optional().describe('Leave blank to keep the saved secret (email: only while the sign-in method of the provider stays the same). Email: password, app password or API key; the Microsoft 365 client secret; the Google Workspace service account key file (JSON)'),
  min_severity: RouteSeverity,
  approvals: z.boolean().optional().describe('Slack, Telegram, Email and Zalo personal only; Zalo OA and webhook reject it'),
  approvers: z.array(Approver).optional().describe('Required (at least one) when approvals is on'),
  app_token: z.string().optional().describe('Slack app-level token (xapp-…) for Socket Mode; leave blank to keep the saved one'),
  bot_token: z.string().optional().describe('Slack bot token (xoxb-…); leave blank to keep the saved one'),
  zalo_login: z.boolean().optional().describe('Zalo personal: save the session of your finished QR sign-in (D-447); without it the saved session is kept. The session is never sent by the client'),
  signin: z.string().optional().describe('Email user sign-in (D-480): the id of a finished sign-in of the same admin; its refresh token becomes the secret and its mailbox the username'),
  secret_key: z.string().optional().describe('Zalo OA (D-483): the Secret key of the Zalo app; leave blank to keep the saved one'),
  refresh_token: z.string().optional().describe('Zalo OA (D-483): the OA refresh token (about 3 months, single use; the box refreshes the access token and keeps the rotated refresh token); leave blank to keep the saved one. With it, secret is the current access token, optional'),
})
export const EmailSigninStart = z.object({
  provider: z.enum(['microsoft365-user', 'outlook', 'gmail-oauth']),
  tenant_id: z.string().optional().describe('Microsoft: Directory (tenant) ID, a domain, organizations, or consumers (Outlook.com)'),
  client_id: z.string().describe("The customer's own app registration (Microsoft, public client flows on) or Desktop OAuth client (Google)"),
  client_secret: z.string().optional().describe('Google Desktop client secret; never returned'),
})
export const EmailSignin = z.object({
  id: z.string(),
  provider: z.enum(['microsoft365-user', 'outlook', 'gmail-oauth']),
  flow: z.enum(['device', 'paste']).describe('device: Microsoft device code, the box polls; paste: Google consent, the admin pastes the loopback address back'),
  status: z.enum(['waiting', 'signed_in', 'expired', 'declined']),
  user_code: z.string().optional(),
  verification_uri: z.string().optional(),
  interval: z.number().int().optional().describe('Seconds between checks of a device sign-in'),
  consent_url: z.string().optional(),
  expires_at: iso,
  mailbox: z.string().optional().describe('The account that signed in'),
})
export const Quiet = z.object({ enabled: z.boolean(), from: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/), to: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/), allow_critical: z.boolean() })
export const Grouping = z.object({ enabled: z.boolean(), window_min: z.union([z.literal(15), z.literal(60), z.literal(240)]) })
export const Rules = z.object({ quiet: Quiet, grouping: Grouping })
export const ChannelsResponse = z.object({ channels: z.array(Channel), quiet: Quiet, grouping: Grouping, email_code_users: z.number().int().describe('Users who sign in with two-step email codes: they cannot sign in while the email channel is off or removed') })

export const IncidentKind = z.enum(['trap', 'bad_address', 'log_anomaly', 'unknown_device'])
export const IncidentStatus = z.enum(['new', 'acknowledged', 'resolved'])
export const SendRecord = z.object({ id: z.string(), channel: ChannelType, to: z.string(), at: iso, ok: z.boolean(), error: z.string().optional(),
  delayed: z.boolean().describe('The provider asked to slow down (HTTP 429, Zalo -32): the message waits in the queue and is sent again by itself; not a failure, no Resend (D-483)') })
export const Incident = z.object({
  id: z.string(),
  kind: IncidentKind,
  attempt: z.boolean().describe('bad_address only: the device that logged the connection blocked it, so it was an attempt, not a connection (D-227); false for the other kinds'),
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
  delayed: z.boolean().describe('A "Delayed (rate limited)" row: the message is sent again by itself after the wait the provider asked for (D-483)'),
  kind: z.enum(['incident', 'vuln', 'approval']), what: z.string(), link: z.string(),
})
export const HistoryResponse = z.object({ items: z.array(HistoryItem), suppressed: z.object({ count: z.number().int(), days: z.number().int() }) })
export const FindingNotices = z.object({ sends: z.array(SendRecord) })
export const LegacyTarget = z.object({ to: z.string() })

// Zalo personal set-up (D-447): QR sign-in, friends and groups, look-up of an invite link or a phone number, approvers' link state.
export const ZaloQR = z.object({ size: z.number().int().describe('Side of the square view box, quiet zone included'), path: z.string().describe('SVG path of the dark cells, redrawn by the box from Zalo\'s image') })
export const ZaloLoginState = z.enum(['none', 'waiting', 'scanned', 'signed_in', 'expired', 'declined', 'failed'])
export const ZaloLogin = z.object({
  state: ZaloLoginState,
  qr: ZaloQR.nullable().describe('Set while waiting or scanned'),
  name: z.string().describe('scanned: the name the Zalo app shows for who scanned; signed_in: the signed-in account\'s display name'),
  error: z.string().describe('failed: why'),
  expires_at: iso.nullable().describe('When the QR code expires (waiting, scanned)'),
})
export const ZaloContact = z.object({ id: z.string(), name: z.string(), group: z.boolean(), members: z.number().int().describe('Group size; 0 when not given') })
export const ZaloContacts = z.object({ friends: z.array(ZaloContact), groups: z.array(ZaloContact) })
export const ZaloFound = ZaloContact.extend({ member: z.boolean().describe('false: a group the signed-in account is not a member of (messages would not reach it)') })
// The link state of an approver of a confirm-link channel: Zalo personal (D-447) and Telegram (D-414) share it.
export const ZaloApproverState = z.enum(['linked', 'sending', 'waiting', 'not_sent'])
export const ZaloApprover = z.object({ user_id: z.string(), address: z.string(), name: z.string(), state: ZaloApproverState, sent_at: iso.nullable(), error: z.string().describe('not_sent: why (failed, expired, or no link made)'),
  self: z.boolean().describe('The administrator asking'),
  box_account: z.boolean().describe('The address is the box\'s own signed-in Zalo account (the QR sign-in proved it); only your own row with it skips the message'),
  link: z.string().optional().describe('Only in the answer of POST …/code for your own row with the box\'s own account: the confirm page (/link/zalo?c=…) to open in this session; any other Zalo gets the link by message') })
export const ZaloApprovers = z.object({ items: z.array(ZaloApprover) })

export const TelegramChat = z.object({ id: z.string().describe('Chat ID as Telegram writes it: a person is positive, a group negative (-100…)'), kind: z.enum(['private', 'group', 'supergroup', 'channel']),
  name: z.string().describe('The person\'s name or the group\'s title, cleaned and shortened'), username: z.string().describe('Public name without @; empty when none') })
export const TelegramChats = z.object({ items: z.array(TelegramChat).describe('Chats the bot has seen, newest first, at most 10; empty when no message has reached it yet') })

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
  { method: 'post', path: '/notify/email-signin', summary: 'Start a user sign-in for the email channel (D-480): a Microsoft device code, or a Google consent address to open and paste back', stories: ['S-NOT-1'], role: 'admin', body: EmailSigninStart, response: EmailSignin },
  { method: 'post', path: '/notify/email-signin/{id}', summary: 'Check a user sign-in: ask Microsoft once when the interval has passed, or finish a Google sign-in with the pasted address', stories: ['S-NOT-1'], role: 'admin', params: id, body: z.object({ url: z.string().max(4096).optional().describe('Google: the whole address the browser showed after approving') }), response: EmailSignin },
  { method: 'post', path: '/notify/zalo/login', summary: 'Start a Zalo personal QR sign-in for the signed-in administrator (one at a time per box; at most one start in 30 s and five an hour)', stories: ['S-NOT-1'], role: 'admin', response: ZaloLogin },
  { method: 'get', path: '/notify/zalo/login', summary: 'State of your Zalo QR sign-in: waiting, scanned, signed in, expired, declined or failed', stories: ['S-NOT-1'], role: 'admin', response: ZaloLogin },
  { method: 'delete', path: '/notify/zalo/login', summary: 'Cancel your Zalo QR sign-in (a finished one is dropped unsaved)', stories: ['S-NOT-1'], role: 'admin', response: null },
  { method: 'get', path: '/notify/zalo/contacts', summary: 'Friends and groups of the Zalo account (your finished sign-in, else the saved session)', stories: ['S-NOT-1', 'S-RESP-2'], role: 'admin', response: ZaloContacts },
  { method: 'post', path: '/notify/zalo/resolve', summary: 'Find the group of a zalo.me/g/ invite link, the person of a phone number, or take a numeric Zalo ID', stories: ['S-NOT-1', 'S-RESP-2'], role: 'admin', body: z.object({ query: z.string().max(200) }), response: ZaloFound },
  { method: 'get', path: '/notify/zalo/approvers', summary: 'Approvers of the Zalo personal channel and whether each confirmed the link sent to their Zalo while signed in as themself (linked)', stories: ['S-RESP-2'], role: 'admin', response: ZaloApprovers },
  { method: 'post', path: '/notify/telegram/chats', summary: 'Find the chats a Telegram bot has seen, for the Chat ID picker (D-491): the token in the body, or the saved one when empty; asks Telegram once without confirming any update. 400 bad_token (not valid), 409 telegram_busy (approval buttons on, a webhook or another reader), 502 telegram_failed', stories: ['S-NOT-1'], role: 'admin', body: z.object({ token: z.string().max(200).optional().describe('Bot token from the form; empty or absent uses the saved channel\'s token, which never leaves the box') }), response: TelegramChats },
  { method: 'get', path: '/notify/telegram/approvers', summary: 'Approvers of the Telegram channel and whether each confirmed the link the bot sent them while signed in as themself (linked); box_account is always false (D-414)', stories: ['S-RESP-2'], role: 'admin', response: ZaloApprovers },
  { method: 'post', path: '/notify/telegram/approvers/{user_id}/code', summary: 'Send an approver a new confirm link by the Telegram bot (the old one stops working): only privately to their user ID; when the bot may not write to them yet, 502 send_failed and a note without the link in the approval chat asks them to press Start (D-414)', stories: ['S-RESP-2'], role: 'admin', params: z.object({ user_id: z.string() }), response: ZaloApprover, example: { params: { user_id: 'u-op' } } },
  { method: 'post', path: '/notify/zalo/approvers/{user_id}/code', summary: 'Send an approver a new confirm link to their Zalo (the old one stops working); for your own row, return the link to confirm now instead', stories: ['S-RESP-2'], role: 'admin', params: z.object({ user_id: z.string() }), response: ZaloApprover, example: { params: { user_id: 'u-op' } } },
  { method: 'put', path: '/notify/rules', summary: 'Save quiet hours and batching rules', stories: ['S-NOT-1'], role: 'admin', body: Rules, response: Rules },
])
