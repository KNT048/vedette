// Hợp đồng API module core (D-18), gồm cả các endpoint nền ở src/mocks/core.ts: /me, /setup, /auth/*, /modules.
// Kiểu UI suy ra từ schema ở đây (types.ts).
import { z } from 'zod'
import { defineEndpoints } from '@/lib/contract'
import { ConnectionKind, KIND_AUTH } from '@/lib/connections'

const ts = z.iso.datetime()
const Role = z.enum(['viewer', 'operator', 'admin'])
const ModuleId = z.enum([
  'core', 'feeds', 'inventory', 'notify', 'sensor-passive', 'sensor-active', 'findings', 'mitigation', 'exposure', 'scan',
  'scan-credentialed', 'honeypot', 'logs', 'agent-intake', 'ai', 'reports', 'mcp-server', 'auth-oidc', 'response',
])
const Ok = z.object({ ok: z.literal(true) })
const Tier = z.enum(['core', 'standard', 'optional'])
export const TwofaMethod = z.enum(['app', 'email']).describe('app = authenticator app (TOTP), email = 6-digit code sent to the sign-in email')

// ---- nền ----
export const Me = z.object({ id: z.string(), name: z.string(), email: z.string(), role: Role, org: z.string(), twofa: z.boolean(), twofa_method: TwofaMethod.nullable(), password_change_required: z.boolean().describe('The password was set by an administrator (D-180): until the user changes it, every call except GET /me, POST /core/account/password and POST /auth/logout answers 403 password_change_required, and the GUI shows the Choose a new password screen') })
export const SetupStatus = z.object({ complete: z.boolean(), org: z.string(), data_mode: z.enum(['sample', 'clean']).describe('sample = trial build with sample data; clean = real install, every table starts empty') })
export const LoginBody = z.object({ email: z.string(), password: z.string(), code: z.string().optional().describe('6-digit code when the account has two-step sign-in; a missing code gives 401 twofa_required with method (app|email) and, for email, sent_to (masked address) and resend_after (seconds). The email code is sent by that same call. Email channel off or unconfigured: 503 twofa_email_unavailable, never password-only') })
export const EmailCodeSent = z.object({ sent_to: z.string().describe('Masked sign-in email, like a•••@acme.example'), resend_after: z.number().int().describe('Seconds before another code can be sent (60)') })
export const ModuleState = z.object({ id: ModuleId, enabled: z.boolean(), tier: Tier, depends: z.array(ModuleId), enabled_at: ts.nullable() })
export const ModulesResponse = z.object({ modules: z.array(ModuleState) })
export const ToggleResponse = z.object({ modules: z.array(ModuleState), affected: z.array(ModuleId).describe('Enabled modules that depend on the module just turned off') })

// ---- cài đặt ban đầu ----
export const BundleId = z.enum(['smb', 'mid', 'custom'])
export const SetupModule = z.object({ id: ModuleId, tier: Tier, depends: z.array(ModuleId) })
export const SetupPayload = z.object({
  sample: z.boolean().optional().describe('true = use sample data and sign in as the sample administrator; other fields are ignored'),
  org: z.string().optional(),
  admin: z.object({ name: z.string(), email: z.string(), password: z.string() }).optional(),
  lan: z.array(z.string()).optional(),
  commitment: z.boolean().optional().describe('true = the user confirms the ranges belong to their company and they may scan them actively'),
  bundle: BundleId.optional(),
  modules: z.array(ModuleId).optional(),
  setup_code: z.string().optional().describe('The one-time setup code the box prints in its log while setup is open (D-75). Required to create the first administrator: missing or wrong gives 403 invalid_setup_code, 429 rate_limited after repeated wrong tries'),
})

// ---- chung ----
export const GeneralSettings = z.object({ name: z.string(), timezone: z.string() })
export const AuthOptions = z.object({ oidc: z.boolean() })

// ---- tài khoản ----
export const AccountSession = z.object({ id: z.string(), device: z.string(), ip: z.string(), started_at: ts, last_seen: ts, current: z.boolean() })
export const Account = z.object({
  user: z.object({ id: z.string(), name: z.string(), email: z.string(), role: Role, twofa: z.boolean(), twofa_method: TwofaMethod.nullable(), created_at: ts, last_login: ts.nullable(), sso: z.boolean().describe('The account signs in only through SSO (D-195): no Vedette password, two-step sign-in is the identity provider\'s') }),
  twofa_email: z.object({
    available: z.boolean().describe('true only when the notify module is on and an email channel is configured and enabled'),
    reason: z.enum(['module_off', 'channel_not_ready']).nullable().describe('Why the email method cannot be chosen, null when available'),
    sent_to: z.string().describe('Masked sign-in email where codes would go'),
  }),
  sessions: z.array(AccountSession),
})
export const TotpStart = z.object({ secret: z.string().describe('20-byte base32 key (RFC 4648), typed by hand into the authenticator app'), otpauth: z.string().describe('URI otpauth://totp/Vedette:<email>?secret=…&issuer=Vedette&algorithm=SHA1&digits=6&period=30') })

// ---- người dùng, OIDC ----
export const AdminUser = z.object({ id: z.string(), name: z.string(), email: z.string(), role: Role, twofa: z.boolean(), twofa_method: TwofaMethod.nullable(), disabled: z.boolean(), created_at: ts, last_login: ts.nullable(), sso: z.boolean().describe('Created by an SSO sign-in (D-195): signs in only through the identity provider; its role follows the IdP groups at every sign-in, so it cannot be changed here (409 sso_user), nor can its password be reset') })
export const UserCreated = z.object({ user: AdminUser, temp_password: z.string().describe('Returned once only') })
const OidcRoleRow = z.object({ group: z.string(), role: Role })
const OidcCaCert = z.object({ subject: z.string(), expires_at: ts })
export const OidcConfig = z.object({
  issuer: z.string(), client_id: z.string(), secret_last4: z.string().nullable(),
  scopes: z.string().describe('Space-separated scopes asked for at sign-in; always contains openid (D-194). Default "openid email profile"; add "groups" for IdPs that need it (Okta, Authentik)'),
  groups_claim: z.string().describe('Name of the ID-token claim that lists the person\'s groups (default "groups")'),
  default_role: Role.nullable().describe('Role for a person in none of the mapped groups; null = no access, the default (D-195)'),
  role_map: z.array(OidcRoleRow).describe('Group to role; a person in several mapped groups gets the highest of their roles'),
  redirect_uri: z.string().describe('The address to register at the identity provider: this box\'s address as the browser reached it, plus /sso/callback'),
  sso_users: z.number().int().describe('Accounts that sign in only through SSO; they cannot sign in while the module is off'),
  ca_pem: z.string().describe('PEM of the CA certificates the box trusts for calls to this identity provider only, in addition to the system roots (D-378); empty = system roots only'),
  ca_certs: z.array(OidcCaCert).describe('The saved CA certificates, one row each'),
})
export const OidcSave = z.object({
  issuer: z.string(), client_id: z.string(), client_secret: z.string().describe('Empty keeps the stored secret'),
  scopes: z.string(), groups_claim: z.string(), default_role: Role.nullable(), role_map: z.array(OidcRoleRow),
  ca_pem: z.string().optional().describe('D-378: 1 to 5 PEM CA certificates, at most 64 KB (400 invalid_ca: not PEM, another block such as a private key, not a CA, expired). Absent keeps the saved ones; empty removes them'),
})
export const OidcStart = z.object({ authorize_url: z.string().describe('The identity provider\'s authorization endpoint with client_id, redirect_uri, scope, state, nonce, code_challenge (S256)'), binding: z.string().describe('Random value the page keeps in session storage and sends back with the callback, so the sign-in can only finish in the tab that started it') })
export const OidcCallback = z.object({ code: z.string(), state: z.string(), binding: z.string() })
export const OidcTest = z.object({ ok: z.literal(true), endpoints: z.record(z.string(), z.string()) })

// ---- audit ----
export const AuditRow = z.object({ id: z.string(), ts, user: z.string(), action: z.string(), target: z.string(), detail: z.string().optional() })
export const AuditQuery = z.object({ q: z.string().optional(), user: z.string().optional(), group: z.string().optional(), from: z.string().optional(), to: z.string().optional() })
export const AuditResult = z.object({ items: z.array(AuditRow), total: z.number(), users: z.array(z.string()), groups: z.array(z.string()) })

// ---- cập nhật ----
export const UpdateChannel = z.enum(['stable', 'beta'])
export const UpdateComponent = z.object({ id: z.string(), kind: z.enum(['software', 'data', 'content']), version: z.string(), previous: z.string().nullable(), installed_at: ts, signature: z.enum(['valid', 'invalid', 'unsigned']),
  rollback_restores_data: z.boolean().describe('Rolling back also puts back the database from before the update (the running release says rollback.safe=false): data written since is lost, so the rollback needs confirm_data_loss') })
export const UpdateAvailable = z.object({ component: z.string(), version: z.string(), channel: UpdateChannel, size_kb: z.number(), note: z.string() })
export const UpdateHistory = z.object({ id: z.string(), ts, component: z.string(), from: z.string().nullable(), to: z.string(), action: z.enum(['update', 'rollback', 'bundle']), user: z.string() })
export const Advisory = z.object({ id: z.string(), title: z.string(), severity: z.enum(['critical', 'high', 'medium']), published: z.string(), fixed_in: z.string(), summary: z.string(), status: z.enum(['affected', 'fixed']) })
export const ManagedPackage = z.object({ id: z.string(), name: z.string(), version: z.string(), status: z.enum(['ok', 'update_pending']) })
const UpdateStep = z.enum(['download', 'start', 'restore', 'restart'])
export const UpdateRun = z.object({
  id: z.string().describe('Stays the same across the restart of Vedette in the middle of the run: the run is kept where the restart cannot lose it'),
  action: z.enum(['update', 'rollback']), component: z.string().describe('"software": the whole release, every service in lockstep'),
  from: z.string().nullable().describe('Release running when the run started'), to: z.string().describe('Release the run installs (update) or goes back to (rollback)'),
  status: z.enum(['running', 'done', 'failed', 'reverted']).describe('reverted: the target was not healthy and the box went back to "from" by itself; failed: it stopped before or without that'),
  steps: z.array(UpdateStep).describe('The steps of this run in order: update = download, start, restart; rollback = start, then restore (only when it puts back the database), restart'),
  step: UpdateStep.nullable().describe('One of steps while running; null when ended. download: fetch and verify the signed images; start: the other services; restore: put back the database from before the update; restart: Vedette itself restarts (the page loses its connection for a moment)'),
  started_at: ts, finished_at: ts.nullable(), user: z.string().describe('"system" for the automatic updater'),
  error: z.string().nullable().describe('Only when failed or reverted: why, in words, naming the service that failed'),
})
export const UpdatesState = z.object({
  channel: UpdateChannel, mode: z.enum(['auto', 'manual']), check_enabled: z.boolean(), last_check: ts,
  components: z.array(UpdateComponent), available: z.array(UpdateAvailable), history: z.array(UpdateHistory).describe('Latest 20'), advisories: z.array(Advisory),
  run: UpdateRun.nullable().describe('The software install or rollback running now, or one that ended in the last 24 hours; null otherwise'),
  managed: z.array(ManagedPackage).describe('Packages Vedette pins itself (nmap, OpenCanary, osquery mirror, nuclei templates)'),
})

// ---- hệ điều hành của hộp (D-53). Chạy qua trình trợ giúp đặc quyền `vedette-host`: danh sách lệnh apt cố định, web không bao giờ chạy shell (SYS-1). ----
const hhmm = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/)
export const MaintenanceWindow = z.object({
  mode: z.enum(['always', 'window']).describe('"always" = no restriction; "window" = only on the days and hours below'),
  days: z.array(z.number().int().min(1).max(7)).describe('1 = Monday … 7 = Sunday; used only when mode is "window"'),
  from: hhmm, to: hhmm.describe('Earlier than "from" means it crosses midnight'),
})
export const OsPackage = z.object({ name: z.string(), current: z.string(), new: z.string(), security: z.boolean(), cves: z.array(z.string()).describe('CVE ids fixed by the new version, where known') })
export const OsInfo = z.object({
  distro: z.enum(['ubuntu', 'debian']), name: z.string().describe('For example "Ubuntu 24.04.3 LTS"'), release: z.string(), kernel: z.string(),
  support_end: z.string().describe('End of standard support, YYYY-MM-DD'), extended_end: z.string().nullable().describe('End of extended support (Debian LTS), YYYY-MM-DD'),
  booted_at: ts, last_check: ts, mirrors: z.array(z.string()).describe('Package mirror host names the box contacts'),
})
export const ReleaseUpgrade = z.object({ to: z.string(), steps: z.array(z.string()) }).describe('Guidance only; Vedette never runs a release upgrade')
export const OsState = z.object({
  os: OsInfo, pending: z.array(OsPackage),
  reboot_required: z.boolean(), reboot_reasons: z.array(z.string()).describe('Packages that need a reboot to take effect'), reboot_scheduled_at: ts.nullable(),
  auto_security: z.boolean().describe('unattended-upgrades installs security updates by itself'), window: MaintenanceWindow,
  release_upgrade: ReleaseUpgrade.nullable(), busy: z.boolean().describe('An install run is in progress; only one at a time'),
})
export const OsRunResult = z.object({
  installed: z.number().int(), security: z.number().int(), backup: z.string().describe('Database backup taken before the run'),
  health: z.array(z.object({ name: z.string(), ok: z.boolean() })).describe('Checks after the run'), reboot_required: z.boolean(),
})
export const OsRun = z.object({
  id: z.string(), scope: z.enum(['security', 'all']), status: z.enum(['running', 'done', 'failed']), started_at: ts, finished_at: ts.nullable(), user: z.string(),
  lines: z.array(z.string()).describe('apt output so far'), result: OsRunResult.nullable(),
  error: z.string().nullable().describe('Only for a failed run: why, in words (the lines keep the raw output)'),
})
export const BoxBackup = z.object({
  id: z.string(), kind: z.enum(['manual', 'pre_os_update', 'pre_update', 'pre_restore']).describe('manual = Download backup or a backup by hand; pre_os_update / pre_update / pre_restore = taken by the box before an operating system install, a Vedette update or a restore'),
  created_at: ts, size: z.number().int().describe('Bytes'), includes_key: z.boolean().describe('Holds the decryption key, so it restores on this box without the key file'),
})
export const BoxBackups = z.object({ backups: z.array(BoxBackup).describe('Newest first') })
export const RestoreRun = z.object({
  id: z.string(), backup_id: z.string(), backup_created_at: ts, status: z.enum(['running', 'done', 'reverted', 'failed']).describe('reverted = the restored data did not start, so the box put back the data from before the restore'),
  started_at: ts, finished_at: ts.nullable(), user: z.string(),
  pre_restore_backup_id: z.string().nullable().describe('The copy of the data from before the restore, kept in the list as pre_restore'),
  error: z.string().nullable().describe('Only when not done: why, in words'),
})
export const OsRebootBody = z.object({ when: z.enum(['now', 'window', 'custom']), at: z.string().optional().describe('Local time HH:MM, only for "custom"; must fall inside the maintenance window') })
export const UpdateCheck = UpdatesState.extend({ applied: z.number().describe('Items installed automatically in automatic mode') })
export const BundleUpload = z.object({ name: z.string(), size: z.number(), sha256: z.string(), content: z.string().describe('Bundle file content, base64 (UTF-8)') })

// ---- quyền riêng tư ----
export const PrivacyFlow = z.object({ id: z.number().int().min(1).max(14), state: z.enum(['on', 'off', 'conditional']), control: z.enum(['switch', 'reason']), configured: z.boolean().optional() })
export const PrivacyState = z.object({
  flows: z.array(PrivacyFlow).describe('Exactly the 14 flows listed in PRIVACY.md'),
  telemetry: z.object({ enabled: z.boolean(), last_sent: ts.nullable(), payload: z.record(z.string(), z.unknown()).describe('Anonymous-signal payload verbatim, exactly what will be sent next hour') }),
  update_check: z.boolean(),
})

// ---- kết nối tới thiết bị (D-93, D-94; S-AI-7, S-RESP-4) ----
// Generic kinds only (D-58): src/lib/connections.ts. No vendor field: brand knowledge is template data.
export const ConnectorKind = ConnectionKind
export const CONNECTOR_AUTH = KIND_AUTH
const ConnectorAuthType = z.enum(['none', 'token', 'basic', 'ssh-key'])
export const ConnectorTool = z.object({ name: z.string(), access: z.enum(['read', 'write']), description: z.string(), enabled: z.boolean() })
export const ConnectorPin = z.object({
  kind: z.enum(['tls_sha256', 'tls_roots', 'ssh_hostkey']).describe('tls_sha256 = SHA-256 of the public key (SubjectPublicKeyInfo) of the HTTPS leaf certificate, when no public authority vouches for the chain; tls_roots = a public authority vouched for the chain at the first test, and every later test requires that again (a self-signed certificate is refused); ssh_hostkey = the SSH server host key'),
  value: z.string().describe('tls_sha256: 64 hex characters; tls_roots: "system roots"; ssh_hostkey: key type and SHA256 fingerprint'),
  first_seen: ts,
}).describe('Pinned at the first successful Test (trust on first use, D-94). A changed certificate or host key is refused until an administrator forgets the pin')
export const Connector = z.object({
  id: z.string(), name: z.string(), kind: ConnectorKind, target: z.string().describe('Base URL or host:port. "mcp-stdio" rows are not supported (D-94)'), asset_id: z.string().nullable(),
  auth: z.object({
    type: ConnectorAuthType, header: z.string().nullable().describe('Token sign-in only: the name of the header the token is sent in (D-174), for a device whose API wants a key header. null sends Authorization: Bearer <token>. The token itself stays in the vault'), last4: z.string().nullable().describe('Last 4 characters of a token or password; null for an SSH key and for no sign-in. The full secret is never returned (SYS-4)'),
    key_fingerprint: z.string().nullable().describe('SSH key only: SHA256:<base64> fingerprint of the saved private key, like GitHub shows for a key. The mock uses a hash of the key body; the backend computes the public-key fingerprint'),
  }),
  username: z.string().nullable().describe('User name for SSH and for Basic sign-in; null for the other sign-ins'),
  pin: ConnectorPin.nullable().describe('Read-only. null until the first Test, or after the pin was forgotten'),
  allow: z.array(z.string()).describe('Hosts, URL prefixes or commands that may be used through this connection'),
  tools: z.array(ConnectorTool), enabled: z.boolean(), status: z.enum(['ok', 'error', 'untested']), last_test: ts.nullable(),
})
export const ConnectorInput = z.object({
  name: z.string().min(1).max(40), kind: ConnectorKind, target: z.string(), asset_id: z.string().nullable().optional(),
  auth_type: ConnectorAuthType, secret: z.string().optional().describe('Leave blank when editing to keep the old secret'),
  username: z.string().regex(/^[^\s:\p{Cc}\p{Cf}]{1,64}$/u).nullable().optional().describe('Required for SSH and for Basic sign-in (400 username_required); 1 to 64 characters without spaces, colons or control characters; ignored for the other sign-ins'),
  auth_header: z.string().max(64).nullable().optional().describe('Token sign-in only (D-174): the header name the token is sent in, for example X-API-Key; empty or null sends Authorization: Bearer <token>. An RFC 7230 token that is not Host, Content-Length, Transfer-Encoding, Connection and the like (400 invalid_auth_header); with another sign-in 400 invalid'),
  clear_pin: z.boolean().optional().describe('true = forget the pinned certificate or host key; the next Test pins again. It is also forgotten when the kind changes or the host or port changes (a trailing slash or path does not count); a change of sign-in keeps it'),
  allow: z.array(z.string()), enabled: z.boolean(), tools: z.array(z.object({ name: z.string(), enabled: z.boolean(), access: z.enum(['read', 'write']).optional().describe('Only for an MCP server (mcp-http): other kinds answer 400 invalid_tool_access, their tools are fixed. A tool found on an MCP server starts as write and off') })).optional().describe('Per-tool enable; tools not listed keep their state'),
})
export const ConnectorTestResult = z.object({ ok: z.literal(true), latency_ms: z.number(), tools_found: z.number().int(), message: z.string(), connector: Connector })

// ---- MCP ----
export const McpToken = z.object({ id: z.string(), name: z.string(), scopes: z.array(z.string()), last4: z.string(), created_at: ts, last_used: ts.nullable() })
export const McpState = z.object({
  enabled: z.boolean(), bind: z.string(), port: z.number(), endpoint: z.string(), tokens: z.array(McpToken),
  listening: z.boolean().describe('The port is open. False while it cannot be opened (another process holds it): do not give a token to that address'),
  listen_error: z.string().nullable().describe('Why the port could not be opened; null while listening'),
  tools: z.array(z.object({ name: z.string(), scope: z.string() })), scopes: z.array(z.string()),
})
export const McpTokenCreated = z.object({ token: z.string().describe('Returned once, at creation'), item: McpToken })

const id = z.object({ id: z.string() })


// ---- mạng của hộp (D-56, S-CORE-8) ----
export const IfaceRole = z.enum(['management', 'span', 'unused'])
export const NetInterface = z.object({ name: z.string(), role: IfaceRole, link: z.boolean(), speed: z.string().nullable(), mac: z.string(), address: z.string().nullable().describe('address/prefix, only on the management interface') })
export const Management = z.object({ mode: z.enum(['dhcp', 'static']), address: z.string().nullable(), prefix: z.number().int().nullable(), gateway: z.string().nullable(), dns: z.array(z.string()) })
export const SpanExtract = z.object({ dns: z.boolean(), tls_sni: z.boolean(), http_host: z.boolean(), flows: z.boolean() }).describe('What is read from mirrored traffic. Packet contents are never stored.')
export const SpanFilter = z.object({ type: z.enum(['cidr', 'host', 'port']), value: z.string() })
export const SpanConfig = z.object({ enabled: z.boolean(), interface: z.string().nullable(), extract: SpanExtract, filters: z.array(SpanFilter), cpu_percent: z.number().int().min(5).max(50), memory_mb: z.number().int().min(128).max(2048) })
export const SpanStatus = z.object({
  verdict: z.enum(['off', 'ok', 'own_only', 'no_traffic', 'no_link', 'sensor_unreachable']).describe('sensor_unreachable = the box could not tell the passive sensor which port to listen on (it is retried at every look); own_only = packets arrive but only the box\'s own; no_traffic = link up, nothing arrives; no_link = no cable signal'),
  interface: z.string().nullable(), packets_per_s: z.number().int(), other_macs: z.number().int().describe('Distinct source MAC addresses other than the box\'s own'), last_packet_at: ts.nullable(),
})
export const NtpConfig = z.object({ mode: z.enum(['default', 'custom']), servers: z.array(z.string()).describe('Only for mode custom; empty for the default pool') })
export const PendingManagement = z.object({ expires_at: ts, previous_address: z.string().nullable(), window_s: z.number().int().describe('Seconds the box waits for the confirmation (the whole window, not what is left)'), reboot_at: ts.nullable().describe('Set when the box could not go back to the old settings by itself: it restarts at this time, and the saved settings on disk are the old ones (D-100)') })
export const NetworkState = z.object({
  interfaces: z.array(NetInterface), management: Management, span: SpanConfig, span_status: SpanStatus, ntp: NtpConfig,
  default_ntp: z.string(), decoy_ips: z.array(z.string()), pending: PendingManagement.nullable().describe('A management address change waiting for confirmation from the new address; the box reverts at expires_at'),
})
export const ManagementBody = z.object({
  mode: z.enum(['dhcp', 'static']), address: z.string().optional(), prefix: z.number().int().optional(), gateway: z.string().optional(), dns: z.array(z.string()).optional(),
  confirm: z.boolean().optional().describe('Required when the address, prefix, gateway or mode changes: 409 confirm_required (with new_ip; null with DHCP, where the server picks the address) otherwise. DNS-only changes apply at once. dhcp with any static field: 400 dhcp_no_static'),
})

export const endpoints = defineEndpoints([
  // nền
  { method: 'get', path: '/me', summary: 'The signed-in user (401 when not signed in)', stories: ['S-CORE-3'], role: 'viewer', response: Me },
  { method: 'get', path: '/setup', summary: 'Whether first-run setup is done', stories: ['S-CORE-1'], role: 'public', response: SetupStatus },
  { method: 'post', path: '/auth/login', summary: 'Sign in with email and password (plus the two-step code when on; email-code users get a code sent and 401 twofa_required). An expired temporary password is 400 temp_password_expired (D-180)', stories: ['S-CORE-3'], role: 'public', body: LoginBody, response: Ok },
  { method: 'post', path: '/auth/login/resend-code', summary: 'Send a new two-step email code during sign-in (needs the password again; 429 resend_too_soon within 60 s, too_many_codes after 5 per hour)', stories: ['S-CORE-3'], role: 'public', body: z.object({ email: z.string(), password: z.string() }), response: EmailCodeSent },
  { method: 'post', path: '/auth/logout', summary: 'Sign out', stories: ['S-CORE-3'], role: 'public', response: null },
  { method: 'get', path: '/modules', summary: 'On/off state of every module', stories: ['S-CORE-1'], role: 'viewer', response: ModulesResponse },
  { method: 'patch', path: '/modules/{id}', summary: 'Turn a module on or off; turning on with missing dependencies gives 409 missing_dependencies', stories: ['S-CORE-1'], role: 'admin',
    params: id, body: z.object({ enabled: z.boolean(), with_dependencies: z.boolean().optional() }), response: ToggleResponse },
  // cài đặt ban đầu
  { method: 'get', path: '/core/setup/modules', summary: 'Modules and dependencies for the bundle step (does not reveal what is on)', stories: ['S-CORE-1'], role: 'public', response: z.object({ modules: z.array(SetupModule) }) },
  { method: 'post', path: '/core/setup', summary: 'First-run setup: create the organization and administrator, choose a module bundle, or use sample data', stories: ['S-CORE-1'], role: 'public', body: SetupPayload, response: Ok },
  { method: 'get', path: '/core/auth-options', summary: 'Whether the sign-in page shows the SSO button', stories: ['S-CORE-3'], role: 'public', response: AuthOptions },
  { method: 'post', path: '/auth/oidc/start', summary: 'Start an SSO sign-in (D-194): returns the identity provider address to open, with state, nonce and a PKCE challenge, and a binding the page keeps until the callback. 400 oidc_off when SSO is off or not set up, 502 idp_unreachable when the discovery document cannot be read, 429 rate_limited', stories: ['S-CORE-3'], role: 'public', response: OidcStart },
  { method: 'post', path: '/auth/oidc/callback', summary: 'Finish an SSO sign-in (D-194, D-195): the page posts the code and state from /sso/callback with its binding; the box exchanges the code, checks the ID token and signs the person in like a password sign-in (session and CSRF cookies). 400 sso_expired, 400 sso_failed, 403 no_access, 403 email_unverified, 403 disabled, 409 email_in_use, 502 idp_unreachable', stories: ['S-CORE-3'], role: 'public', body: OidcCallback, response: Ok },
  // chung
  { method: 'get', path: '/core/general', summary: 'Organization name and time zone', stories: ['S-CORE-1'], role: 'viewer', response: GeneralSettings },
  { method: 'put', path: '/core/general', summary: 'Save organization name and time zone', stories: ['S-CORE-1'], role: 'admin', body: GeneralSettings, response: GeneralSettings },
  // tài khoản
  { method: 'get', path: '/core/account', summary: 'My profile and sign-in sessions', stories: ['S-CORE-3'], role: 'viewer', response: Account },
  { method: 'patch', path: '/core/account', summary: 'Change display name', stories: ['S-CORE-3'], role: 'viewer', body: z.object({ name: z.string() }), response: Ok },
  { method: 'post', path: '/core/account/password', summary: 'Change password (needs the current password). The same call ends the temporary-password limit of D-180: the new password must differ from the temporary one', stories: ['S-CORE-3'], role: 'viewer', body: z.object({ current: z.string(), next: z.string() }), response: Ok },
  { method: 'post', path: '/core/account/2fa/start', summary: 'Authenticator app: create a TOTP key waiting for confirmation (needs the current password, D-76; wrong password 400 wrong_password, counted like a failed sign-in)', stories: ['S-CORE-3'], role: 'viewer', body: z.object({ password: z.string() }), response: TotpStart },
  { method: 'post', path: '/core/account/2fa/confirm', summary: 'Authenticator app: confirm the TOTP key with a 6-digit code to turn on two-step sign-in', stories: ['S-CORE-3'], role: 'viewer', body: z.object({ code: z.string() }), response: Ok },
  { method: 'post', path: '/core/account/2fa/email/start', summary: 'Email code: send a 6-digit code to my own sign-in email (409 when the email channel is not ready or two-step is already on; same limits as sign-in codes; needs the current password, D-76)', stories: ['S-CORE-3'], role: 'viewer', body: z.object({ password: z.string() }), response: EmailCodeSent },
  { method: 'post', path: '/core/account/2fa/email/confirm', summary: 'Email code: enter the code to prove the mailbox works and turn on two-step sign-in (expires in 10 min, single use, 5 wrong tries cancel it)', stories: ['S-CORE-3'], role: 'viewer', body: z.object({ code: z.string() }), response: Ok },
  { method: 'post', path: '/core/account/2fa/disable', summary: 'Turn off two-step sign-in (needs the password)', stories: ['S-CORE-3'], role: 'viewer', body: z.object({ password: z.string() }), response: Ok },
  { method: 'delete', path: '/core/account/sessions/{id}', summary: 'End one of my other sessions', stories: ['S-CORE-3'], role: 'viewer', params: id, response: null },
  { method: 'post', path: '/core/account/sessions/revoke-others', summary: 'End all my other sessions', stories: ['S-CORE-3'], role: 'viewer', response: z.object({ ok: z.literal(true), revoked: z.number() }) },
  // người dùng, OIDC
  { method: 'get', path: '/core/users', summary: 'List users', stories: ['S-CORE-3'], role: 'admin', response: z.object({ items: z.array(AdminUser) }) },
  { method: 'post', path: '/core/users', status: 201, summary: 'Create a user with a role; returns a temporary password once. The user must change it at first sign-in and it expires after 72 hours (D-180)', stories: ['S-CORE-3'], role: 'admin', body: z.object({ name: z.string(), email: z.string(), role: Role }), response: UserCreated },
  { method: 'patch', path: '/core/users/{id}', summary: 'Change role or disable/re-enable; blocks disabling yourself and removing the last administrator', stories: ['S-CORE-3'], role: 'admin',
    params: id, body: z.object({ role: Role.optional(), disabled: z.boolean().optional() }), response: z.object({ user: AdminUser }) },
  { method: 'post', path: '/core/users/{id}/reset-password', summary: 'Reset password: temporary password once (changed at first sign-in, expires after 72 hours, D-180), ends all of that user\'s sessions', stories: ['S-CORE-3'], role: 'admin', params: id, response: z.object({ temp_password: z.string() }) },
  { method: 'post', path: '/core/users/{id}/2fa/reset', summary: 'Reset two-step sign-in for a user who lost the phone or mailbox: turns it off and writes an audit entry (an administrator cannot reset their own)', stories: ['S-CORE-3'], role: 'admin', params: id, response: Ok },
  { method: 'get', path: '/core/oidc', summary: 'OIDC sign-in settings (secret shows only the last 4 characters)', stories: ['S-CORE-3'], role: 'admin', response: OidcConfig },
  { method: 'put', path: '/core/oidc', summary: 'Save OIDC settings', stories: ['S-CORE-3'], role: 'admin', body: OidcSave, response: OidcConfig },
  { method: 'post', path: '/core/oidc/test', summary: 'Try reading the IdP discovery document', stories: ['S-CORE-3'], role: 'admin', response: OidcTest },
  // audit
  { method: 'get', path: '/core/audit', summary: 'Audit log filtered by text, user, group and date (at most 200 rows)', stories: ['S-CORE-3'], role: 'admin', query: AuditQuery, response: AuditResult, example: { query: { group: 'core' } } },
  { method: 'get', path: '/core/audit/export', summary: 'Export the audit log to CSV with the same filters', stories: ['S-CORE-3'], role: 'admin', query: AuditQuery, response: 'file' },
  // cập nhật
  { method: 'get', path: '/core/updates', summary: 'Versions, new builds, history and security advisories of Vedette', stories: ['S-CORE-2'], role: 'viewer', response: UpdatesState },
  { method: 'patch', path: '/core/updates', summary: 'Change channel (stable/beta) and mode (automatic/manual)', stories: ['S-CORE-2'], role: 'admin', body: z.object({ channel: UpdateChannel.optional(), mode: z.enum(['auto', 'manual']).optional() }), response: UpdatesState },
  { method: 'post', path: '/core/updates/check', summary: 'Check for updates now (409 when turned off under Privacy)', stories: ['S-CORE-2'], role: 'operator', response: UpdateCheck },
  { method: 'post', path: '/core/updates/apply', summary: 'Install the new version of one component; for the software it starts a run (UpdatesState.run, 409 busy while one runs)', stories: ['S-CORE-2'], role: 'admin', body: z.object({ component: z.string() }), response: UpdatesState },
  { method: 'post', path: '/core/updates/rollback', summary: 'Go back to the previous version of one component; 409 confirm_required when it restores the database and confirm_data_loss is not true', stories: ['S-CORE-2'], role: 'admin', body: z.object({ component: z.string(), confirm_data_loss: z.boolean().optional().describe('Required (true) when the component has rollback_restores_data') }), response: UpdatesState },
  { method: 'get', path: '/core/updates/os', summary: 'Operating system of the box: release, kernel, end of support, pending packages, reboot state, maintenance window', stories: ['S-CORE-7'], role: 'viewer', response: OsState },
  { method: 'post', path: '/core/updates/os/check', summary: 'Run the equivalent of apt update now (409 when update checks are off under Privacy)', stories: ['S-CORE-7'], role: 'operator', response: OsState },
  { method: 'post', path: '/core/updates/os/install', status: 202, summary: 'Install security updates or all updates through vedette-host; one run at a time (409 when busy), database backup first', stories: ['S-CORE-7'], role: 'admin', body: z.object({ scope: z.enum(['security', 'all']) }), response: OsRun },
  { method: 'get', path: '/core/updates/os/run', summary: 'The current or latest install run with its live apt output; null before the first run', stories: ['S-CORE-7'], role: 'viewer', response: OsRun.nullable() },
  { method: 'patch', path: '/core/updates/os/settings', summary: 'Turn automatic security updates (unattended-upgrades) on/off and set the maintenance window', stories: ['S-CORE-7'], role: 'admin', body: z.object({ auto_security: z.boolean().optional(), window: MaintenanceWindow.optional() }), response: OsState },
  { method: 'post', path: '/core/updates/os/reboot', summary: 'Reboot now, at the next maintenance window, or at a chosen time inside the window; 409 while an install runs', stories: ['S-CORE-7'], role: 'admin', body: OsRebootBody, response: OsState },
  { method: 'delete', path: '/core/updates/os/reboot', summary: 'Cancel a scheduled reboot', stories: ['S-CORE-7'], role: 'admin', response: OsState },
  { method: 'get', path: '/core/updates/bundle', summary: 'Export a signed offline bundle for an air-gapped box', stories: ['S-CORE-2'], role: 'operator', response: 'file' },
  { method: 'post', path: '/core/updates/bundle', summary: 'Import an offline bundle; a bad signature is rejected', stories: ['S-CORE-2'], role: 'admin', body: BundleUpload, response: z.object({ applied: z.number(), state: UpdatesState }) },
  // quyền riêng tư
  { method: 'get', path: '/core/privacy', summary: 'The 14 data flows leaving the box and the verbatim anonymous-signal payload', stories: ['S-CORE-4'], role: 'viewer', response: PrivacyState },
  { method: 'patch', path: '/core/privacy', summary: 'Turn the anonymous signal and update checks on/off', stories: ['S-CORE-4'], role: 'admin', body: z.object({ telemetry: z.boolean().optional(), update_check: z.boolean().optional() }), response: PrivacyState },
  // MCP
  { method: 'get', path: '/core/connections', summary: 'Connections to devices and services that response actions and the AI use: HTTP API, SSH, RESTCONF, automation platform, MCP server', stories: ['S-AI-7', 'S-RESP-4'], role: 'admin', response: z.object({ items: z.array(Connector) }) },
  { method: 'post', path: '/core/connections', status: 201, summary: 'Add a connection with its allow-list. Write tools start off and run only through approved response actions. "mcp-stdio" is refused: 400 kind_unsupported. The address may be public when the administrator declares it (privacy flow 12)', stories: ['S-AI-7', 'S-RESP-4'], role: 'admin', body: ConnectorInput, response: Connector },
  { method: 'put', path: '/core/connections/{id}', summary: 'Edit a connection, its allow-list and per-tool enable (blank secret = keep the old one; clear_pin = forget the pin)', stories: ['S-AI-7', 'S-RESP-4'], role: 'admin', params: z.object({ id: z.string() }), body: ConnectorInput, response: Connector },
  { method: 'delete', path: '/core/connections/{id}', summary: 'Delete a connection; 409 in_use while a response change made through it is still in force', stories: ['S-AI-7', 'S-RESP-4'], role: 'admin', params: z.object({ id: z.string() }), response: null },
  { method: 'post', path: '/core/connections/{id}/test', summary: 'Test a connection, pin its certificate or host key on first use, and refresh its tool list', stories: ['S-AI-7', 'S-RESP-4'], role: 'admin', params: z.object({ id: z.string() }), response: ConnectorTestResult },
  { method: 'get', path: '/core/mcp', summary: 'MCP server state, tokens (last 4 characters only) and the read-only tool list. The server is the mcp-server module: turn it on and off with PATCH /modules/mcp-server (D-230); while it is off every /core/mcp path answers 404', stories: ['S-MCP-1'], role: 'admin', response: McpState },
  { method: 'post', path: '/core/mcp/tokens', status: 201, summary: 'Create a read-only token by scope; returns the full token once. At most 10 tokens (400 too_many)', stories: ['S-MCP-1'], role: 'admin', body: z.object({ name: z.string(), scopes: z.array(z.string()) }), response: McpTokenCreated },
  { method: 'delete', path: '/core/mcp/tokens/{id}', summary: 'Revoke an MCP token', stories: ['S-MCP-1'], role: 'admin', params: id, response: null },
  // dữ liệu
  { method: 'get', path: '/core/data/backup', summary: 'Download a backup (password hashes, never passwords or keys)', stories: ['S-CORE-1'], role: 'admin', response: 'file' },
  { method: 'get', path: '/core/logs/export', summary: 'Download the box logs (audit, AI activity, response, scan probes, alerts, device logs, known-bad connections, honeypot hits) as one JSON or CSV file; secrets are removed, hash-chained logs keep their hashes for offline verification; a category whose module has no log source yet is listed as missing; chained categories (audit, response, AI activity) are exported unscrubbed with their chain anchor and head; one download at a time (409 busy), at most one a minute (429 rate_limited), over 128 MB is refused (413 logs_too_large); the download, and a refusal, are audited', stories: ['S-CORE-6'], role: 'admin', query: z.object({ categories: z.string().optional().describe('Comma list: audit, ai_activity, response, scan_probes, alerts, device_logs, known_bad, honeypot; none or an unknown one is 400 invalid_categories'), from: z.string().optional().describe('Start date, YYYY-MM-DD, inclusive, in the organization time zone'), to: z.string().optional().describe('End date, YYYY-MM-DD, inclusive, in the organization time zone; before from is 400 invalid_range'), format: z.string().optional().describe('json (default) or csv; anything else is 400 invalid_format') }), response: 'file', example: { query: { categories: 'audit,ai_activity', format: 'json' } } },
  { method: 'get', path: '/core/data/backups', summary: 'Backups the operating system helper keeps on this box (D-377); 409 not_appliance on a container-only install', stories: ['S-CORE-1'], role: 'admin', response: BoxBackups },
  { method: 'post', path: '/core/data/restore', status: 202, summary: 'Restore a backup kept on this box (D-377): core first takes a copy of the current data, kept as a pre_restore backup, and the helper puts it back by itself when the restored data does not start. 409 confirm_required without confirm_data_loss: true; 404 backup_unknown; then the current password (400 wrong_password, counted like a failed sign-in, 429 rate_limited) and, when two-step sign-in is on, a fresh code (400 code_required / invalid_code), as for the purge; 409 busy, low_disk, schema_newer, not_appliance; 412 secrets_missing; 502 checksum_mismatch', stories: ['S-CORE-1'], role: 'admin', body: z.object({ backup_id: z.string(), confirm_data_loss: z.boolean().optional().describe('Required (true): everything written since the backup is replaced'), password: z.string(), code: z.string().optional() }), response: RestoreRun },
  { method: 'get', path: '/core/data/restore/run', summary: 'The current or latest restore run; null before the first one', stories: ['S-CORE-1'], role: 'admin', response: RestoreRun.nullable() },
  { method: 'get', path: '/core/data/export', summary: 'Export my data as JSON (every table except secrets; 409 busy while another export runs)', stories: ['S-CORE-1'], role: 'admin', response: 'file' },
  { method: 'post', path: '/core/data/purge', summary: 'Delete all data back to a fresh install and replace the decryption key (D-154). Needs the exact organization name (400 confirm_mismatch), the current password (400 wrong_password, counted like a failed sign-in, 429 rate_limited) and, when two-step sign-in is on, a fresh code (400 code_required / invalid_code). 409 busy while a host run, an update or another purge runs; 502 host_unreachable when the configured helper does not answer, its socket missing included (nothing is deleted); 412 transition_pending; 500 backups_already_deleted when the purge fails after the helper deleted its backups (the data on the box is still there). kept lists what was not done or not touched (host_backups: this box is configured without a helper, so there were no helper backups to delete; honeypot_log: the raw log of the honeypot belongs to its container and stays; key_not_replaced: the new key could not be written, replace vedette.key by hand)', stories: ['S-CORE-1'], role: 'admin', body: z.object({ confirm: z.string(), password: z.string(), code: z.string().optional() }), response: z.object({ ok: z.literal(true), removed: z.record(z.string(), z.number()), kept: z.array(z.enum(['host_backups', 'key_not_replaced', 'honeypot_log'])) }) },
  { method: 'get', path: '/core/network', summary: 'Network interfaces, management address, SPAN capture settings and live status, NTP, decoy IPs', stories: ['S-CORE-8', 'S-INV-1'], role: 'viewer', response: NetworkState },
  { method: 'put', path: '/core/network/interfaces', summary: 'Set the role of every interface (management / SPAN capture / unused). Exactly one management interface, at most one SPAN interface; the management interface cannot be changed here (409)', stories: ['S-CORE-8'], role: 'admin', body: z.object({ roles: z.record(z.string(), IfaceRole) }), response: NetworkState },
  { method: 'put', path: '/core/network/management', summary: 'Management interface: DHCP or static. An address change applies for 5 minutes and reverts unless confirmed from the new address (you sign in again there)', stories: ['S-CORE-8'], role: 'admin', body: ManagementBody, response: NetworkState },
  { method: 'post', path: '/core/network/management/confirm', summary: 'Confirm the pending management change from the new address (409 when none is pending or it expired)', stories: ['S-CORE-8'], role: 'admin', response: NetworkState },
  { method: 'post', path: '/core/network/management/revert', summary: 'Cancel the pending management change now and go back to the old settings', stories: ['S-CORE-8'], role: 'admin', response: NetworkState },
  { method: 'put', path: '/core/network/span', summary: 'SPAN capture: port, what is extracted, exclusion filters, CPU and memory cap. The management interface cannot be the SPAN port (409); turning it on needs a port and at least one extraction', stories: ['S-CORE-8', 'S-INV-1', 'S-LOG-4'], role: 'admin', body: SpanConfig, response: NetworkState },
  { method: 'get', path: '/core/network/span/status', summary: 'Live mirrored-traffic status: packets/s, other MACs, last packet, health verdict', stories: ['S-CORE-8', 'S-INV-1'], role: 'viewer', response: SpanStatus },
  { method: 'put', path: '/core/network/ntp', summary: 'NTP servers: default pool or your own (1 to 4)', stories: ['S-CORE-8'], role: 'admin', body: NtpConfig, response: NetworkState },
])
