// API contract for the response module. Stories S-RESP-1..4, S-AI-8. Decisions D-40, D-41, D-44, D-46, D-47, D-48, D-51 (D-51 wins).
// Rules are WHEN (trigger with typed fields) -> IF (conditions) -> THEN (ordered catalog actions with typed parameters).
// Security: the client never sends a command. A request names a rule, a proposal or a catalog action with parameters; the server holds the
// templates, validates every value by type, escapes it for the transport and enforces every gate (the UI only mirrors them).
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { ConnectionKind } from '@/lib/connections'

const iso = z.iso.datetime()
const id = z.string().regex(/^[\w.-]{1,96}$/)

export const RISK_PHRASE = 'I ACCEPT THE RISK'
export const AI_MIN_CONFIDENCE = 0.8
export const AI_REPEAT_DAYS = 7

export const ActionStatus = z.enum(['pending', 'approved', 'rejected', 'expired', 'executed', 'failed', 'rolled_back'])
export const ItemStatus = z.enum(['pending', 'skipped', 'executed', 'failed', 'rolled_back'])
export const ApprovedVia = z.enum(['app', 'slack', 'telegram', 'email', 'zalo', 'zalo-personal', 'auto'])
export const ChatChannel = z.enum(['slack', 'telegram', 'zalo-personal'])
export const TriggerKind = z.enum(['honeypot', 'ioc_connection', 'finding', 'unknown_device', 'log_threshold', 'new_port', 'schedule', 'manual'])
export const Trigger = TriggerKind
export const Risk = z.enum(['low', 'medium', 'high'])
// `id`: whole number 1 to 2147483647 (a policy number); `name`: letters, numbers, . _ - up to 64 (API_CONVENTIONS, action-templates §1.2). `text` is for message actions only.
export const ParamType = z.enum(['ip', 'cidr', 'domain', 'port', 'mac', 'vlan', 'interface', 'id', 'name', 'text'])
export const FieldType = z.enum(['ip', 'cidr', 'domain', 'port', 'mac', 'vlan', 'interface', 'id', 'name', 'text', 'number', 'flag', 'choice'])
// Packs are labels from the template library (data, D-58): "box" and "generic" are built in, any other pack is named by the library or the customer.
export const Pack = z.string().min(1).max(60)
export const ConnKind = ConnectionKind

export const Tpl = z.object({
  cli: z.string().max(2000).describe('Command text with typed placeholders such as {ip}, {cidr}, {domain}, {port}, {mac}, {vlan}, {interface}, {id}, {name} ({text} only for message actions); shell characters are refused. Values Vedette reads or derives when it runs (such as {seq}, {previous_vlan}, {found_id}, {expiry_s}, {timeout}, {rules_before}) are shown as <seq> and so on'),
  method: z.enum(['', 'GET', 'PUT', 'PATCH', 'POST', 'DELETE']), path: z.string().max(300).describe('API path under the connection address, starts with /'),
  body: z.string().max(2000).describe('JSON body (for an MCP server: the tool arguments as JSON), may be empty'),
  headers: z.string().max(600).describe('HTTP headers, one "Name: value" per line, may be empty. Authorization, Cookie, Host, Proxy-*, hop-by-hop, Forwarded, X-Forwarded*, Via, X-Real-IP, X-Original-URL, X-Rewrite-URL and the method override headers are refused: the connection sets them or they change what the call means'),
  expect: z.string().max(200).optional().describe('Read-back only (empty elsewhere): text the read-back output must contain after the action and must not contain after the undo. Typed placeholders allowed. Without it the action is "not checked" (verified is null)'),
})
export const PrecheckRefuse = z.array(z.string().min(1).max(80)).max(8).describe('Texts that make the check before refuse: when its output contains one, nothing is written. Needed (at least one) for any device action that can name a port: {interface}, and in a custom action {port}, {id} or {name} in a command or path')
export const PrecheckExpect = z.string().max(80).describe('Text the output of the check before must contain, or nothing is written (printable ASCII, case-sensitive). Empty = none. An empty output always refuses')

export const RestCall = z.object({
  method: z.enum(['GET', 'PUT', 'PATCH', 'POST', 'DELETE']), url: z.string(), body: z.string().nullable(),
  headers: z.record(z.string(), z.string()).describe('The headers of the template with the typed values filled in, exactly as sent; the sign-in is the connection\'s and never listed'),
})
const rest = RestCall.nullable().describe('The exact API call, or null when the action is a command only')
export const Change = z.object({
  before: z.string().describe('State of the target before the change, in plain words'),
  after: z.string().describe('State of the target after the change, in plain words'),
  cli: z.string().describe('The same change as a device command, for people who want to check it by hand (may be empty)'),
  rest,
  rollback: z.object({ title: z.string(), cli: z.string(), rest }),
  verify: z.string().describe('How Vedette reads the result back after running the change: the exact call (method and URL) or command lines (empty when the action cannot be read back)'),
  precheck: z.string().describe('The check Vedette runs right before the change: the exact call or command lines (empty when there is none)'),
  precheck_rules: z.string().describe('When the check refuses the change, in plain words (empty when there is no check)'),
  verify_rule: z.string().describe('What the read-back must contain after the change and must not contain after the undo (empty when there is none)'),
})

// ---- AI proposals from plans (S-RESP-1) ----
export const ProposalState = z.enum(['ready', 'execution_off', 'tool_not_allowed', 'tool_unavailable'])
export const Proposal = z.object({
  id, title: z.string(), tool_key: z.string().describe('connection id / tool name'), tool: z.string(),
  connector_id: z.string(), connection: z.string(), asset_id: z.string(), asset_name: z.string(), change: Change,
  state: ProposalState.describe('ready = a request can be made now; the others say what blocks it'),
  request_id: z.string().nullable().describe('Open (pending) or executed request for this proposal'),
})
export const PlanStep = z.object({ kind: z.enum(['contain', 'check', 'patch']), title: z.string(), detail: z.string(), proposal: Proposal.nullable() })
export const Plan = z.object({
  id, finding_id: z.string(), cve: z.string(), asset_id: z.string(), asset_name: z.string(), generated_at: iso,
  model: z.string(), profile: z.string().describe('Name of the AI profile that drafted the plan (D-29)'),
  path: z.string().describe('How the device is reachable, from the inventory and read-only connection calls'),
  reads: z.array(z.object({ connection: z.string(), tool: z.string(), summary: z.string() })),
  steps: z.array(PlanStep),
  sent_to: z.array(z.string()).describe('Report channels that received the plan, for example "Slack #security"'),
})
export const PlanList = z.object({ items: z.array(Plan), ai_available: z.boolean(), execution: z.boolean() })

// ---- Requests: one bundled request per rule run ----
export const EmailLink = z.object({ approver: z.string(), address: z.string(), url: z.string(), expires_at: iso, used: z.boolean() })
export const RequestItem = z.object({
  id, action_id: z.string(), title: z.string(), risk: Risk, reversible: z.boolean(),
  connector_id: z.string().nullable().describe('null = the action does not change another device (block list, message)'), connection: z.string().nullable(), tool: z.string(),
  targets: z.number().int().describe('How many addresses or objects the action touches'), change: Change,
  ttl_min: z.number().int().nullable().describe('Minutes after execution until the change is undone automatically'),
  status: ItemStatus, executed_at: iso.nullable(), remove_at: iso.nullable(), rolled_back_at: iso.nullable(),
  result: z.string().nullable(), verified: z.object({ ok: z.boolean(), detail: z.string() }).nullable().describe('Result of the read-back after the action ran'),
  state_unknown: z.boolean().describe('A failed item whose step was sent and whose outcome is not known: it may be in force, so it can be undone to be sure'),
})
export const Approval = z.object({ user_id: z.string(), name: z.string(), email: z.string(), via: ApprovedVia, at: iso, items: z.array(z.string()).describe('Item ids this person approved') })
export const Evidence = z.object({ kind: z.enum(['finding', 'ioc_hit', 'config_read']), id: z.string(), summary: z.string() })
export const AiMeta = z.object({
  confidence: z.number().min(0).max(1), evidence: z.array(Evidence), why: z.string(),
  second_check: z.object({ ok: z.boolean(), notes: z.string() }).nullable().describe('Deterministic second checker, only for high-risk actions'),
  in_app_only: z.boolean().describe('High risk: only an in-app approval with the two-step code counts'),
})
export const ActionRequest = z.object({
  id, source: z.enum(['ai', 'rule']), proposal_id: z.string(), rule_id: z.string().nullable(), rule_name: z.string().nullable(),
  trigger: TriggerKind.nullable(), trigger_summary: z.string().nullable(),
  finding_id: z.string().nullable(), cve: z.string().nullable(), asset_id: z.string().nullable(), asset_name: z.string(),
  title: z.string(), items: z.array(RequestItem), risk: Risk.describe('Highest risk among the actions'),
  status: ActionStatus, requested_at: iso, expires_at: iso, decided_at: iso.nullable(),
  requires_approvals: z.number().int().min(1).max(2), two_because: z.string().nullable().describe('Why two different approvers are needed'),
  approvals: z.array(Approval),
  sent_to: z.array(z.string()).describe('Channels that received the approval request'),
  email_links: z.array(EmailLink).describe('Preview build only, admin only: the approval links that would be emailed'),
  note: z.string().nullable(), pre_approved: z.boolean().describe('Carried out by the rule pre-approval option, without a person'),
  ai: AiMeta.nullable(),
})
export const ActionList = z.object({ items: z.array(ActionRequest) })

// ---- Settings and the safety envelope ----
export const Window = z.object({ id, name: z.string().max(80), start: iso, end: iso })
export const AiGates = z.object({
  triggers: z.array(TriggerKind).describe('Triggers the AI may send requests for'),
  budget_hour: z.number().int().min(1).max(20), budget_day: z.number().int().min(1).max(100),
  paused_at: iso.nullable().describe('Set when the quality breaker paused AI proposals'), paused_reason: z.string().nullable(),
})
export const Settings = z.object({
  execution: z.boolean().describe('OFF by default (D-41); gates actions that change another device'),
  accepted_by: z.string().nullable(), accepted_at: iso.nullable(),
  max_per_hour: z.number().int().min(1).max(20).describe('Approved device actions per hour'),
  expiry_min: z.number().int().min(15).max(30).describe('Minutes an approval request stays open (15 to 30)'),
  approval_channels: z.array(z.string()).describe('Channel types that receive approval requests'),
  breaker_max_per_hour: z.number().int().min(1).max(200).describe('More actions than this in one hour pauses everything'),
  breaker_tripped_at: iso.nullable(), breaker_notified: z.array(z.string()),
  multi_target_max: z.number().int().min(1).max(1000).describe('An action touching more targets than this needs a second approver'),
  maintenance: z.array(Window).describe('No rule or AI request is created during a window'),
  ai: AiGates,
})
export const SettingsView = Settings.extend({
  channels: z.array(z.object({ type: z.string(), label: z.string(), ready: z.boolean().describe('Configured, enabled, approvals on and at least one approver'), approvers: z.number().int(), link: z.boolean().describe('Approves through a one-time link (email, Zalo OA)'),
    linked: z.number().int().describe('Approvers who proved this address themselves in My account (D-191); only they can approve with buttons or links'),
    unlinked: z.array(z.string()).describe('Names of the approvers who have not linked their address yet') })),
})

// ---- Approver identities (S-RESP-2, D-191): each approver proves the address or ID an administrator typed for them ----
export const IdentityMethod = z.enum(['email_code', 'chat_code', 'unavailable'])
export const Identity = z.object({
  channel: z.string(), label: z.string(), address: z.string().describe('The address or ID on the approver list of the channel, as an administrator saved it'),
  linked: z.boolean().describe('Proved by this person for exactly this address; a changed address or sign-in email is not linked'), linked_at: iso.nullable(),
  method: IdentityMethod.describe('email_code: Vedette mails a code to this address. chat_code: press Approve or Reject on an approval message (Zalo personal: reply with one of your codes) and Vedette answers you privately with a code. unavailable: this channel cannot answer privately yet, so it cannot be linked (approve in Vedette)'),
  code_waiting: z.boolean().describe('A code was sent or shown and can be entered now'),
})
export const IdentityList = z.object({ items: z.array(Identity) })
export const CodeSent = z.object({ sent_to: z.string().describe('The address, masked'), resend_after: z.number().int(), preview_code: z.string().optional().describe('Preview build only; never sent by a real box') })
export const SettingsInput = z.object({
  max_per_hour: z.number().int(), expiry_min: z.number().int(), approval_channels: z.array(z.string()),
  breaker_max_per_hour: z.number().int(), multi_target_max: z.number().int(), maintenance: z.array(Window),
  ai: z.object({ triggers: z.array(TriggerKind), budget_hour: z.number().int(), budget_day: z.number().int() }),
})

// ---- Trigger catalog ----
export const TriggerField = z.object({ key: z.string(), label: z.string(), type: FieldType, example: z.string(), choices: z.array(z.string()) })
export const TriggerInfo = z.object({ id: TriggerKind, name: z.string(), description: z.string(), fields: z.array(TriggerField), ai_allowed: z.boolean() })
export const TriggerList = z.object({ items: z.array(TriggerInfo) })

// ---- Action catalog ----
export const Connection = z.object({
  id: z.string(), name: z.string(), enabled: z.boolean(), kind: ConnKind,
  write_tools: z.array(z.string()).describe('Enabled write tools; empty = read-only, cannot carry out actions'), read_only: z.boolean(),
})
export const CatalogAction = z.object({
  id, builtin: z.boolean(), pack: Pack, name: z.string(), description: z.string(),
  connection_id: z.string().nullable(), connection: z.string().nullable(), connection_kind: ConnKind.nullable(), tool: z.string().nullable().describe('Write tool on the connection'),
  rollback_tool: z.string().nullable(),
  run: Tpl, rollback: Tpl, verify: Tpl,
  precheck: Tpl.describe('Check before: a read-only command or GET that runs right before the action; empty when there is none'), precheck_refuse: PrecheckRefuse, precheck_expect: PrecheckExpect,
  params: z.array(ParamType).describe('Placeholders the templates use'), risk: Risk, enabled: z.boolean().describe('Allowed = enabled'),
  reversible: z.boolean().describe('Has a rollback step'), ai_may_propose: z.boolean().describe('The AI may send a request for this action'),
  device: z.boolean().describe('Changes another device, so the execution switch applies'), available: z.boolean(), unavailable_reason: z.string().nullable(),
})
export const CatalogInput = z.object({
  name: z.string().min(1).max(80), description: z.string().max(300), connection_id: z.string(),
  tool: z.string().nullable().describe('MCP server: the write tool to call; other kinds: null'), rollback_tool: z.string().nullable(),
  run: Tpl, rollback: Tpl, verify: Tpl, precheck: Tpl.optional(), precheck_refuse: PrecheckRefuse.optional(), precheck_expect: PrecheckExpect.optional(), risk: Risk, enabled: z.boolean(), ai_may_propose: z.boolean(),
})
export const CatalogUpdate = z.object({
  name: z.string().optional(), description: z.string().optional(), connection_id: z.string().nullable().optional(), tool: z.string().nullable().optional(), rollback_tool: z.string().nullable().optional(),
  run: Tpl.optional(), rollback: Tpl.optional(), verify: Tpl.optional(), precheck: Tpl.optional(), precheck_refuse: PrecheckRefuse.optional(), precheck_expect: PrecheckExpect.optional(), risk: Risk.optional(), enabled: z.boolean().optional(), ai_may_propose: z.boolean().optional(),
}).describe('Built-in actions accept only enabled, ai_may_propose and connection_id; custom actions accept everything')
export const Catalog = z.object({ items: z.array(CatalogAction), connections: z.array(Connection) })

// ---- Rules: WHEN -> IF -> THEN ----
export const Op = z.enum(['eq', 'in', 'in_cidr', 'gte', 'lte', 'device_type', 'count_window', 'first_time'])
export const Condition = z.object({
  field: z.string().max(40).describe('Trigger field; empty for the device type test'), op: Op, value: z.string().max(200),
  n: z.number().int().nullable().describe('count_window: at least this many; first_time: hours'), window_min: z.number().int().nullable().describe('count_window: minutes'),
})
export const RuleAction = z.object({
  action_id: id, params: z.record(z.string(), z.string().max(200)).describe('Placeholder name to a literal or a trigger field such as {{trigger.source_ip}}'),
  ttl_min: z.number().int().min(5).max(43200).nullable().describe('Undo after this many minutes (null = keep until undone by hand)'),
})
export const Rule = z.object({
  id, name: z.string(), enabled: z.boolean(), live: z.boolean().describe('false = dry run: matches are logged, nothing is requested or run'),
  trigger: TriggerKind, match: z.enum(['all', 'any']), conditions: z.array(Condition).max(10), actions: z.array(RuleAction).min(1).max(6),
  pre_approved: z.boolean().describe('Admin only, off by default: run without a person, for low-risk reversible actions with an undo time of 24 hours or less'),
  max_per_hour: z.number().int().min(1).max(100), schedule_min: z.number().int().nullable().describe('Schedule trigger: run every this many minutes (15 to 10080)'),
  template_id: z.string().nullable(), last_fired: iso.nullable(),
})
export const RuleInput = Rule.omit({ id: true, last_fired: true, template_id: true })
export const RuleList = z.object({ items: z.array(Rule) })
export const EventView = z.object({
  id, trigger: TriggerKind, ts: iso, summary: z.string(), fields: z.record(z.string(), z.string()),
  device_kind: z.string().nullable(), handled_by: z.array(z.string()).describe('Rules that already acted on it'),
})
export const EventList = z.object({ items: z.array(EventView) })
export const RunSummary = z.object({ matched: z.number().int(), dry_run: z.number().int(), requests: z.number().int(), executed: z.number().int(), refused: z.number().int(), deduped: z.number().int() })
export const Simulation = z.object({
  event: EventView.nullable().describe('The latest event of this trigger that was used'), matched: z.boolean(),
  conditions: z.array(z.object({ text: z.string(), ok: z.boolean() })),
  steps: z.array(z.object({ action: z.string(), risk: Risk, ok: z.boolean(), error: z.string().nullable(), change: Change.nullable() })),
  notes: z.array(z.string()), approvals: z.number().int().describe('How many different approvers a live run would need'), executed: z.literal(0),
})
export const Allowlist = z.object({ items: z.array(z.object({ value: z.string().describe('IP address, CIDR range or domain'), label: z.string() })) })
export const Template = z.object({ id, name: z.string(), description: z.string(), trigger: TriggerKind, risk: Risk, approvals: z.number().int(), rule: RuleInput })
export const TemplateList = z.object({ items: z.array(Template) })

// ---- Block list ----
export const BlockEntry = z.object({ value: z.string(), source: z.string(), reason: z.string(), added_at: iso, expires_at: iso.nullable() })
export const Blocklist = z.object({
  url: z.string().describe('Tokenised LAN address your firewall pulls'), token_last4: z.string(), entries: z.array(BlockEntry),
  last_fetch: z.object({ at: iso, from: z.string() }).nullable(),
})

// ---- Log ----
export const LogKind = z.enum(['rule_fired', 'proposal', 'request', 'approved', 'rejected', 'executed', 'rolled_back', 'ttl_removed', 'refused', 'expired', 'failed', 'settings', 'emergency_stop', 'blocklist_token', 'dry_run', 'simulated', 'deduped', 'breaker', 'ai_note'])
export const LogEntry = z.object({
  id, ts: iso, kind: LogKind, actor: z.string(), detail: z.string(),
  prev_hash: z.string().describe('hash of the previous entry; 64 zeros for the first'),
  hash: z.string().describe('lowercase hex SHA-256 of prev_hash + "\\n" + JSON.stringify([id, ts, kind, actor, detail])'),
})
export const LogList = z.object({ items: z.array(LogEntry).describe('Oldest first, so the chain can be checked from the start') })

export const ApprovalView = z.object({
  state: z.enum(['ready', 'expired', 'used', 'decided', 'unknown']), title: z.string().nullable(),
  items: z.array(z.object({ title: z.string(), risk: Risk, change: Change })), approver: z.string().nullable(), expires_at: iso.nullable(), status: ActionStatus.nullable(),
  requires_approvals: z.number().int().nullable(), approved_so_far: z.number().int().nullable(),
  ai_generated: z.boolean().describe('true when an AI proposed the request: the page shows the AI-generated label (rules/legal.md). false unless state is ready'),
})

// ---- AI requests: gates enforced here, not by prompt ----
export const AiNote = z.object({ id, ts: iso, kind: z.enum(['suggestion', 'digest']), title: z.string(), why: z.string(), confidence: z.number(), action_id: z.string(), target: z.string(), evidence: z.array(Evidence) })
export const Hint = z.object({ id, ts: iso, kind: z.enum(['rule', 'memory']), text: z.string(), from_request: z.string() })
export const AiState = z.object({
  gates: AiGates, min_confidence: z.number(), repeat_days: z.number().int(),
  usage: z.object({ hour: z.number().int(), day: z.number().int() }),
  quality: z.object({ decided: z.number().int(), rejected: z.number().int(), paused: z.boolean() }).describe('Of the last 10 decided AI requests'),
  notes: z.array(AiNote), hints: z.array(Hint),
})
export const ProposeBody = z.object({
  trigger: TriggerKind, action_id: id, params: z.record(z.string(), z.string().max(200)),
  confidence: z.number().min(0).max(1), evidence: z.array(z.object({ kind: z.enum(['finding', 'ioc_hit', 'config_read']), id: z.string().max(120) })).max(10), why: z.string().max(400),
}).describe('The AI names a catalog action and typed values only. It never sends a command: any command, request or template field is refused')
export const ProposeResult = z.object({ outcome: z.enum(['request', 'suggestion', 'digest']), request: ActionRequest.nullable(), note: z.string() })
export const Stat = z.object({ sent: z.number().int(), approved: z.number().int(), rejected: z.number().int(), expired: z.number().int(), pending: z.number().int(), acceptance_rate: z.number().nullable(), median_approve_min: z.number().nullable() })
export const Metrics = z.object({
  ai: Stat, rules: Stat, suggestions: z.number().int(), digested: z.number().int(),
  rejected: z.array(z.object({ id, title: z.string(), source: z.enum(['ai', 'rule']), reason: z.string(), at: iso })),
})

const idParams = z.object({ id })
const chanParams = z.object({ channel: z.string().regex(/^[a-z-]{1,20}$/) })
const tokenParams = z.object({ token: z.string() })
const R = (e: Parameters<typeof defineEndpoints>[0][number]) => e
export const endpoints = defineEndpoints([
  R({ method: 'get', path: '/response/plans', summary: 'AI response plans for unresolved critical findings, with the proposed actions and what blocks them', stories: ['S-RESP-1'], role: 'viewer',
    query: z.object({ finding: z.string().optional() }), response: PlanList }),
  R({ method: 'get', path: '/response/actions', summary: 'Requests (one bundled request per rule run or AI proposal) with items, approvals, status, exact changes, rollback and read-back result', stories: ['S-RESP-2', 'S-RESP-3'], role: 'viewer', response: ActionList }),
  R({ method: 'post', path: '/response/proposals/{id}/request', status: 201, summary: 'Ask for approval of one action proposed in an AI plan (refused when execution is off, the action is not enabled or a request is already open)', stories: ['S-RESP-2'], role: 'operator',
    params: idParams, response: ActionRequest }),
  R({ method: 'post', path: '/response/actions/{id}/approve', summary: 'Approve a request in the app: all actions or the ones picked. High-risk requests need a second, different approver; AI high-risk requests need the two-step code', stories: ['S-RESP-2'], role: 'operator',
    params: idParams, body: z.object({ items: z.array(z.string()).optional(), code: z.string().optional() }), response: ActionRequest }),
  R({ method: 'post', path: '/response/actions/{id}/reject', summary: 'Reject a pending request; for an AI request the reason can be saved as a rule or memory hint', stories: ['S-RESP-2'], role: 'operator',
    params: idParams, body: z.object({ reason: z.string().max(300).optional(), remember: z.enum(['none', 'rule', 'memory']).optional() }), response: ActionRequest }),
  R({ method: 'post', path: '/response/actions/{id}/rollback', summary: 'Undo every executed action of a request with its rollback step (device actions are refused when execution is off)', stories: ['S-RESP-2'], role: 'operator', params: idParams, response: ActionRequest }),
  R({ method: 'post', path: '/response/actions/{id}/chat-decision', summary: 'Preview build only: simulate an approval or rejection typed in Slack, Telegram or Zalo; counts only when the address is on that channel approver list and the user is an operator or admin', stories: ['S-RESP-2'], role: 'admin',
    params: idParams, body: z.object({ channel: ChatChannel, external_id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/), decision: z.enum(['approve', 'reject']) }), response: ActionRequest }),
  R({ method: 'get', path: '/response/approve/{token}', summary: 'Public: what an emailed approval link would change. Read only: opening the link never approves', stories: ['S-RESP-2'], role: 'public', params: tokenParams, response: ApprovalView }),
  R({ method: 'post', path: '/response/approve/{token}', summary: 'Public: approve or reject through an emailed link. The token is single-use, valid 30 minutes and bound to one request and one approver', stories: ['S-RESP-2'], role: 'public',
    params: tokenParams, body: z.object({ decision: z.enum(['approve', 'reject']) }), response: ActionRequest }),
  R({ method: 'get', path: '/response/me/identities', summary: 'My approver identities: each approval channel whose approver list names me, with the address, whether I linked it myself and how to link it (D-191)', stories: ['S-RESP-2'], role: 'operator', response: IdentityList }),
  R({ method: 'post', path: '/response/me/identities/{channel}/code', summary: 'Mail a 6-digit link code to my address on the email approval channel (my sign-in email). 10 minutes, one at a time, a new one after 60 seconds, 5 an hour. Chat channels get their code by pressing a button on an approval message', stories: ['S-RESP-2'], role: 'operator',
    params: chanParams, response: CodeSent }),
  R({ method: 'post', path: '/response/me/identities/{channel}/confirm', summary: 'Link my address on a channel with the code it received. Single use; 5 wrong codes cancel it', stories: ['S-RESP-2'], role: 'operator',
    params: chanParams, body: z.object({ code: z.string() }), response: Identity }),
  R({ method: 'delete', path: '/response/me/identities/{channel}', summary: 'Unlink my address on a channel: buttons and links from it stop counting until I link it again', stories: ['S-RESP-2'], role: 'operator', params: chanParams, response: null }),
  R({ method: 'get', path: '/response/settings', summary: 'AI response settings: execution switch, safety envelope (circuit breaker, multi-target limit, maintenance windows), AI gates and approval channels', stories: ['S-RESP-2', 'S-AI-8'], role: 'admin', response: SettingsView }),
  R({ method: 'put', path: '/response/settings', summary: 'Save the hourly limit, approval expiry (15 to 30 minutes), approval channels, circuit breaker, multi-target limit, maintenance windows and AI gates (does not touch the execution switch)', stories: ['S-RESP-2', 'S-AI-8'], role: 'admin',
    body: SettingsInput, response: SettingsView }),
  R({ method: 'post', path: '/response/execution', summary: 'Turn execution on (admin with two-step sign-in on, exact phrase "I ACCEPT THE RISK") or off', stories: ['S-RESP-2'], role: 'admin',
    body: z.object({ enabled: z.boolean(), phrase: z.string().optional() }), response: SettingsView }),
  R({ method: 'post', path: '/response/emergency-stop', summary: 'Emergency stop: turn execution off at once and cancel every pending request', stories: ['S-RESP-2'], role: 'operator',
    response: z.object({ cancelled: z.number().int() }) }),
  R({ method: 'post', path: '/response/breaker/reset', summary: 'Resume after the global circuit breaker paused all response actions', stories: ['S-RESP-2'], role: 'admin', response: SettingsView }),

  R({ method: 'get', path: '/response/triggers', summary: 'Trigger catalog: each WHEN with its typed fields for conditions and parameters, and whether the AI may use it', stories: ['S-RESP-3'], role: 'viewer', response: TriggerList }),
  R({ method: 'get', path: '/response/rules', summary: 'Rules: trigger, conditions, ordered actions, dry-run or live, pre-approved option and limits', stories: ['S-RESP-3'], role: 'viewer', response: RuleList }),
  R({ method: 'post', path: '/response/rules', status: 201, summary: 'Add a rule. It always starts in dry run (log only). Parameters are checked by type; pre-approved is refused unless every action is low risk, reversible and undone within 24 hours', stories: ['S-RESP-3'], role: 'admin', body: RuleInput, response: Rule }),
  R({ method: 'put', path: '/response/rules/{id}', summary: 'Change a rule, switch it on or off, or switch it from dry run to live', stories: ['S-RESP-3'], role: 'admin', params: idParams, body: RuleInput, response: Rule }),
  R({ method: 'delete', path: '/response/rules/{id}', summary: 'Delete a rule', stories: ['S-RESP-3'], role: 'admin', params: idParams, response: null }),
  R({ method: 'post', path: '/response/rules/run', summary: 'Preview build only: check the current events against the enabled rules now (on a real box this runs continuously)', stories: ['S-RESP-3'], role: 'operator', response: RunSummary }),
  R({ method: 'post', path: '/response/rules/simulate', summary: 'Simulate a rule (saved or not) with the latest event of its trigger: shows the rendered commands and requests and executes nothing', stories: ['S-RESP-3'], role: 'operator',
    body: z.object({ rule: RuleInput, event_id: z.string().optional() }), response: Simulation }),
  R({ method: 'post', path: '/response/rules/{id}/manual', summary: 'Run a manual-trigger rule on a chosen device', stories: ['S-RESP-3'], role: 'operator', params: idParams, body: z.object({ asset_id: z.string() }), response: RunSummary }),
  R({ method: 'get', path: '/response/events', summary: 'Recent events the triggers watch for, with their typed fields: honeypot touches, known-bad connections, findings, unknown devices, log thresholds, new ports', stories: ['S-RESP-3'], role: 'viewer', response: EventList }),
  R({ method: 'get', path: '/response/templates', summary: 'Gallery of ready-made rules (disabled, dry run) to clone and edit', stories: ['S-RESP-3'], role: 'viewer', response: TemplateList }),
  R({ method: 'post', path: '/response/templates/{id}/clone', status: 201, summary: 'Clone a template into a new rule that is switched off and in dry run', stories: ['S-RESP-3'], role: 'admin', params: idParams, response: Rule }),
  R({ method: 'get', path: '/response/allowlist', summary: 'Never-touch list: gateway, DNS servers, domain controllers, this box, management IPs and services you declared', stories: ['S-RESP-3'], role: 'viewer', response: Allowlist }),
  R({ method: 'put', path: '/response/allowlist', summary: 'Replace the never-touch list (IP addresses, CIDR ranges or domains)', stories: ['S-RESP-3'], role: 'admin', body: Allowlist, response: Allowlist }),

  R({ method: 'get', path: '/response/blocklist', summary: 'The block list your firewall pulls: tokenised address, entries with source, reason and expiry, last fetch', stories: ['S-RESP-3'], role: 'admin', response: Blocklist }),
  R({ method: 'post', path: '/response/blocklist/token', summary: 'Regenerate the block list token; the old address stops working at once', stories: ['S-RESP-3'], role: 'admin', response: Blocklist }),
  R({ method: 'get', path: '/response/blocklist/{token}.txt', summary: 'Plain-text block list (one IP address per line) for firewalls to pull; the token in the address is the only credential', stories: ['S-RESP-3'], role: 'public', params: tokenParams, response: 'file' }),

  R({ method: 'get', path: '/response/catalog', summary: 'Action catalog in plain words: template packs from the library (data, D-58), generic actions and custom ones; connections with their kind and whether they can write', stories: ['S-RESP-4'], role: 'viewer', response: Catalog }),
  R({ method: 'post', path: '/response/catalog', status: 201, summary: 'Add a custom action. The fields must fit the connection kind (API: method, path, body; SSH: command; MCP: write tool and arguments) and the connection must have an enabled write tool', stories: ['S-RESP-4'], role: 'admin', body: CatalogInput, response: CatalogAction }),
  R({ method: 'put', path: '/response/catalog/{id}', summary: 'Change a custom action, or enable a built-in one, choose its connection and set whether the AI may propose it', stories: ['S-RESP-4'], role: 'admin', params: idParams, body: CatalogUpdate, response: CatalogAction }),
  R({ method: 'delete', path: '/response/catalog/{id}', summary: 'Delete a custom action that no rule uses', stories: ['S-RESP-4'], role: 'admin', params: idParams, response: null }),

  R({ method: 'get', path: '/response/ai', summary: 'AI request state: gates, usage against the budget, quality breaker, suggestions, digest and saved hints', stories: ['S-RESP-2', 'S-AI-8'], role: 'viewer', response: AiState }),
  R({ method: 'post', path: '/response/ai/proposals', summary: 'Preview build only (D-97): on a real box the AI sends its requests inside the process and this route answers 404. The gates it applies: allowed trigger, action flagged for AI, real evidence, confidence of 0.8 or more, one open request per target and action, 7 days after a rejection, hourly and daily budget, quality breaker, second checker for high risk. 201 when an approval request was created, 200 for a suggestion note or a digest (the generated file documents 200)', stories: ['S-RESP-2'], role: 'operator',
    body: ProposeBody, response: ProposeResult }),
  R({ method: 'post', path: '/response/ai/resume', summary: 'Resume AI requests after the quality breaker paused them', stories: ['S-RESP-2'], role: 'admin', response: AiState }),
  R({ method: 'get', path: '/response/metrics', summary: 'Acceptance rate, time to approve and rejected requests, for the AI and for rules', stories: ['S-RESP-2', 'S-AI-8'], role: 'viewer', response: Metrics }),

  R({ method: 'get', path: '/response/log', summary: 'Tamper-evident response log: every rule, dry run, simulation, proposal, request, decision, execution, rollback, removal and refusal, hash-chained', stories: ['S-RESP-2', 'S-RESP-3', 'S-AI-8'], role: 'operator', response: LogList }),
])
