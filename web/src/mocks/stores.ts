// Bảng dùng chung giữa module trong mock: phiên, người dùng, module, tài sản, kiểm toán.
// Bảng riêng của từng module nằm trong features/<m>/mocks.ts.
import { collection, dataMode, newId, nowIso, peek } from './db'
import { canonHash, GENESIS } from '@/lib/chain'
import type { Role } from '@/lib/session'
import type { ModuleId, ModuleState } from '@/lib/modules'
import type { Asset, Finding } from '@/lib/types'
import { realSessionOn, realUser } from './realSession'
import { seedAssets } from './seed/assets'
import { seedFindings } from './seed/findings'

export interface User { id: string; name: string; email: string; role: Role; password: string; twofa: boolean; /** Kiểu hai bước (D-35); thiếu = 'app' khi twofa bật */ twofa_method?: 'app' | 'email' | null; created_at: string; last_login: string | null; disabled?: boolean }

export const DEMO_PASSWORD = 'vedette-demo'

export const usersStore = collection<User[]>('core_users', () => [
  { id: 'u-admin', name: 'Admin', email: 'admin@acme.example', role: 'admin', password: DEMO_PASSWORD, twofa: false, created_at: '2026-10-01T02:00:00Z', last_login: null },
  { id: 'u-op', name: 'IT Operator', email: 'it@acme.example', role: 'operator', password: DEMO_PASSWORD, twofa: false, created_at: '2026-10-01T02:00:00Z', last_login: null },
  { id: 'u-view', name: 'Director', email: 'director@acme.example', role: 'viewer', password: DEMO_PASSWORD, twofa: false, created_at: '2026-10-02T02:00:00Z', last_login: null },
], () => [])

export const sessionStore = collection<{ userId: string | null }>('core_session', () => ({ userId: null }))
export const orgStore = collection<{ name: string; setup_complete: boolean; timezone: string }>('core_org', () => ({ name: 'Sample Company', setup_complete: false, timezone: 'Asia/Ho_Chi_Minh' }), () => ({ name: '', setup_complete: false, timezone: 'Asia/Ho_Chi_Minh' }))

const MODULES: Array<Omit<ModuleState, 'enabled_at'>> = [
  { id: 'core', enabled: true, tier: 'core', depends: [] },
  { id: 'feeds', enabled: true, tier: 'standard', depends: ['core'] },
  { id: 'inventory', enabled: true, tier: 'standard', depends: ['core', 'feeds'] },
  { id: 'notify', enabled: true, tier: 'standard', depends: ['core'] },
  { id: 'sensor-passive', enabled: true, tier: 'standard', depends: ['inventory'] },
  { id: 'sensor-active', enabled: true, tier: 'standard', depends: ['inventory'] },
  // D-57 (6): findings is its own module (fnd_*, on by default); mitigation only adds the "What to do" packs and needs findings.
  { id: 'findings', enabled: true, tier: 'standard', depends: ['feeds', 'inventory'] },
  { id: 'mitigation', enabled: true, tier: 'standard', depends: ['findings'] },
  { id: 'exposure', enabled: true, tier: 'optional', depends: ['inventory'] },
  { id: 'scan', enabled: true, tier: 'optional', depends: ['inventory', 'feeds'] },
  { id: 'scan-credentialed', enabled: false, tier: 'optional', depends: ['inventory', 'scan'] },
  { id: 'honeypot', enabled: true, tier: 'optional', depends: ['inventory'] },
  { id: 'logs', enabled: true, tier: 'optional', depends: ['feeds', 'inventory'] },
  { id: 'agent-intake', enabled: false, tier: 'optional', depends: ['inventory'] },
  { id: 'ai', enabled: true, tier: 'optional', depends: ['core'] },
  { id: 'reports', enabled: true, tier: 'optional', depends: ['inventory', 'feeds', 'notify'] },
  { id: 'mcp-server', enabled: false, tier: 'optional', depends: ['core'] },
  { id: 'auth-oidc', enabled: false, tier: 'optional', depends: ['core'] },
  // D-40: AI đề xuất phản ứng (bật). D-41: thực thi đã duyệt là công tắc riêng bên trong module, TẮT mặc định.
  { id: 'response', enabled: true, tier: 'optional', depends: ['ai', 'notify', 'inventory'] },
]
export const modulesStore = collection<ModuleState[]>('core_modules', () => MODULES.map((m) => ({ ...m, enabled_at: m.enabled ? '2026-10-01T02:00:00Z' : null })))
export const isOn = (id: ModuleId) => modulesStore.get().find((m) => m.id === id)?.enabled ?? false

export const assetsStore = collection<Asset[]>('inv_assets', seedAssets, () => [])
export const findingsStore = collection<Finding[]>('fnd_finding', seedFindings, () => [])

// core_audit is a hash chain (DATA_MODEL §5.3, D-57 (14)). Newest first here; each entry's prev_hash is the hash of the one before it in time.
export interface AuditEntry { id: string; ts: string; user: string; action: string; target: string; detail: string | null; prev_hash: string; hash: string }
export const auditStore = collection<AuditEntry[]>('core_audit', () => [])

/** SYS-3: mọi mutation ghi kiểm toán. */
export function audit(action: string, target: string, detail?: string) {
  const u = realSessionOn() ? realUser() : usersStore.get().find((x) => x.id === sessionStore.get().userId)
  auditStore.update((l) => {
    const core = { id: newId('au'), ts: nowIso(), user: u?.email ?? 'system', action, target, detail: detail ?? null, prev_hash: l[0]?.hash ?? GENESIS }
    return [{ ...core, hash: canonHash(core) }, ...l].slice(0, 1000)
  })
}

// AI BYOK (S-AI-1/4): cấu hình và đồng hồ token dùng chung — module ai sở hữu UI/endpoint; module khác đọc để biết "Hỏi AI của tôi" dùng được không.
export interface AiConfig { configured: boolean; provider: 'anthropic' | 'openai' | 'gemini' | 'openai-compatible'; base_url: string; model: string; key_last4: string | null; tier: 'min' | 'med' | 'max'; daily_cap: number; redact_pii: boolean }
export const aiConfigStore = collection<AiConfig>('ai_config', () => ({ configured: true, provider: 'anthropic', base_url: 'https://api.anthropic.com', model: 'claude-haiku-5-5', key_last4: '7Qk2', tier: 'med', daily_cap: 60000, redact_pii: true }),
  () => ({ configured: false, provider: 'anthropic', base_url: 'https://api.anthropic.com', model: '', key_last4: null, tier: 'min', daily_cap: 10000, redact_pii: true }))
export interface AiRun { id: string; ts: string; skill: string; model: string; tokens_in: number; tokens_out: number; status: 'ok' | 'schema_error' | 'capped'; target?: string; /** Tên hồ sơ AI đã trả lời (thêm sau, tuỳ chọn) */ profile?: string; /** true khi hồ sơ chính lỗi, quá trần hoặc không được phép nên chạy bằng hồ sơ dự phòng */ fallback?: boolean }
export const aiRunsStore = collection<AiRun[]>('ai_runs', () => [], () => [])
// ---- Nhiều hồ sơ AI + phân việc (owner 2026-11-06). Thêm vào cuối, các trường cũ của aiConfigStore vẫn dùng được:
// `configured` = có ít nhất một hồ sơ dùng được (module ai cập nhật mỗi khi đổi hồ sơ); provider/model/key_last4 phản chiếu hồ sơ dùng được đầu tiên.
export type AiJob = 'explain-finding' | 'mitigation-config' | 'cve-news' | 'log-digest' | 'log-investigate' | 'ask-my-data' | 'weekly-report' | 'pdpl-assessment' | 'translate-advisory' | 'response-plan'
/** `data`: internal = gửi log/thiết bị của khách; public = chỉ dữ liệu công khai (CVE, khuyến cáo). */
export const AI_JOBS: { id: AiJob; data: 'internal' | 'public' }[] = [
  { id: 'explain-finding', data: 'internal' }, { id: 'mitigation-config', data: 'internal' }, { id: 'cve-news', data: 'public' },
  { id: 'log-digest', data: 'internal' }, { id: 'log-investigate', data: 'internal' }, { id: 'ask-my-data', data: 'internal' },
  { id: 'weekly-report', data: 'internal' }, { id: 'pdpl-assessment', data: 'internal' }, { id: 'translate-advisory', data: 'public' },
  { id: 'response-plan', data: 'internal' },
]
const JOB_ALIAS: Record<string, AiJob> = { explain: 'explain-finding' }
export const aiJobOf = (skill: string): AiJob | null => (AI_JOBS.some((j) => j.id === skill) ? (skill as AiJob) : JOB_ALIAS[skill] ?? null)
export interface AiProfile {
  id: string; name: string
  kind: 'anthropic' | 'openai' | 'gemini' | 'openai-compatible' | 'custom'
  /** Kiểu API: Chat Completions (OpenAI), Messages (Anthropic) hoặc Gemini. Hồ sơ dựng sẵn suy ra từ `kind`. */
  api_style: 'openai' | 'anthropic' | 'gemini'
  base_url: string; model: string; key_last4: string | null
  /** internal = chạy trong mạng công ty, dữ liệu không rời mạng; cloud = nhà cung cấp đám mây */
  location: 'internal' | 'cloud'
  daily_cap: number
}
export const aiProfileUsable = (p: AiProfile) => p.key_last4 !== null || p.location === 'internal'
const P = (id: string, name: string, kind: AiProfile['kind'], api_style: AiProfile['api_style'], base_url: string, model: string, key_last4: string | null, location: AiProfile['location'], daily_cap: number): AiProfile => ({ id, name, kind, api_style, base_url, model, key_last4, location, daily_cap })
export const aiProfilesStore = collection<AiProfile[]>('ai_profiles', () => [
  P('p-haiku', 'Claude Haiku', 'anthropic', 'anthropic', 'https://api.anthropic.com', 'claude-haiku-5-5', '7Qk2', 'cloud', 60000),
  P('p-sonnet', 'Claude Sonnet', 'anthropic', 'anthropic', 'https://api.anthropic.com', 'claude-sonnet-5-5', '7Qk2', 'cloud', 30000),
  P('p-ollama', 'Company Ollama server', 'openai-compatible', 'openai', 'http://localhost:11434/v1', 'qwen3:8b', null, 'internal', 300000),
], () => [])
export type AiAssign = Record<AiJob, { primary: string | null; fallback: string | null }>
const noAssign = (): AiAssign => Object.fromEntries(AI_JOBS.map((j) => [j.id, { primary: null, fallback: null }])) as AiAssign
export const aiAssignStore = collection<{ internal_only: boolean; jobs: AiAssign }>('ai_assign', () => ({
  internal_only: false,
  jobs: { ...noAssign(),
    'explain-finding': { primary: 'p-sonnet', fallback: 'p-haiku' }, 'mitigation-config': { primary: 'p-sonnet', fallback: 'p-haiku' },
    'cve-news': { primary: 'p-haiku', fallback: 'p-ollama' }, 'log-digest': { primary: 'p-ollama', fallback: 'p-haiku' },
    'log-investigate': { primary: 'p-ollama', fallback: 'p-sonnet' }, 'ask-my-data': { primary: 'p-sonnet', fallback: 'p-ollama' },
    'weekly-report': { primary: 'p-haiku', fallback: null }, 'pdpl-assessment': { primary: 'p-sonnet', fallback: null }, 'translate-advisory': { primary: 'p-haiku', fallback: null },
    'response-plan': { primary: 'p-sonnet', fallback: 'p-ollama' },
  },
}), () => ({ internal_only: false, jobs: noAssign() }))
/** Hồ sơ dùng được cho một việc, theo thứ tự chính rồi dự phòng; bỏ hồ sơ không dùng được và hồ sơ đám mây khi luật riêng tư bắt buộc nội bộ. */
export function aiCandidates(job: AiJob): AiProfile[] {
  const a = aiAssignStore.get()
  const profiles = aiProfilesStore.get()
  const internalData = AI_JOBS.find((j) => j.id === job)?.data === 'internal'
  return [a.jobs[job]?.primary, a.jobs[job]?.fallback]
    .map((id) => profiles.find((p) => p.id === id))
    .filter((p): p is AiProfile => !!p && aiProfileUsable(p) && !(a.internal_only && internalData && p.location !== 'internal'))
}
/** Ghi một lần gọi AI (đồng hồ token, S-AI-4). Hồ sơ trả lời = hồ sơ chính của việc (module ai tự ghi khi có chuyển dự phòng). */
export function recordAiRun(skill: string, tokens_in: number, tokens_out: number, target?: string, profile?: AiProfile, fallback?: boolean): AiRun {
  const job = aiJobOf(skill)
  const p = profile ?? (job ? aiCandidates(job)[0] : undefined)
  const run: AiRun = { id: newId('ai'), ts: nowIso(), skill, model: p?.model ?? aiConfigStore.get().model, tokens_in, tokens_out, status: 'ok', target, profile: p?.name, fallback }
  aiRunsStore.update((l) => [run, ...l].slice(0, 500))
  return run
}
/** "Hỏi AI của tôi" chỉ hiện khi module ai bật, có hồ sơ dùng được, và (nếu nêu việc) việc đó có hồ sơ được phép. */
export const aiAvailable = (job?: AiJob) => {
  if (!isOn('ai') || !aiConfigStore.get().configured) return false
  return job ? aiCandidates(job).length > 0 : AI_JOBS.some((j) => aiCandidates(j.id).length > 0)
}

/**
 * Mạng của chính hộp Vedette (mock thay cho thông tin card mạng thật).
 * Dữ liệu mẫu: 192.168.10.250 trong 192.168.10.0/24. Cài sạch: suy ra từ dải LAN đầu tiên người dùng khai
 * (Thiết bị → Phạm vi), lấy địa chỉ .250 của dải /24 (hoặc địa chỉ gần cuối dải nhỏ hơn); chưa khai thì null.
 */
export interface BoxInfo { hostname: string; ip: string | null; lan: string | null; iface: string }
export function boxInfo(): BoxInfo {
  if (dataMode() === 'sample') return { hostname: 'vedette-hq', ip: '192.168.10.250', lan: '192.168.10.0/24', iface: 'eth0' }
  const lan = peek<{ lan_ranges?: string[] }>('inv_settings')?.lan_ranges?.[0] ?? null
  if (!lan) return { hostname: 'vedette', ip: null, lan: null, iface: 'eth0' }
  const [base = '0.0.0.0', bits = '24'] = lan.split('/')
  const n = base.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0
  const size = 2 ** (32 - Number(bits))
  const host = size >= 256 ? 250 : Math.max(1, size - 2)
  const ip = (n + host) >>> 0
  return { hostname: 'vedette', ip: [24, 16, 8, 0].map((s) => (ip >>> s) & 255).join('.'), lan, iface: 'eth0' }
}

// ---- Đăng nhập hai bước bằng mã email (D-35). Module core sở hữu; module notify đọc số người dùng để cảnh báo khi tắt kênh. ----
export type TwofaMethod = 'app' | 'email'
export const twofaMethodOf = (u: Pick<User, 'twofa' | 'twofa_method'>): TwofaMethod | null => (u.twofa ? (u.twofa_method ?? 'app') : null)

/** Kênh email của module notify đã cấu hình, đang bật và module đang bật? Đọc chéo bằng peek (không import mock của notify). */
export function emailChannelReady(): boolean {
  if (!isOn('notify')) return false
  const list = peek<{ type: string; configured: boolean; enabled: boolean }[]>('notify_channels')
  // Chưa ai mở module notify thì bảng chưa được gieo: dữ liệu mẫu có kênh email, cài sạch thì không.
  if (!list) return dataMode() === 'sample'
  return list.some((c) => c.type === 'email' && c.configured && c.enabled)
}

/** Số người dùng (chưa bị vô hiệu) đăng nhập bằng mã email: họ không vào được khi kênh email không gửi được. */
export const emailCodeUserCount = () => usersStore.get().filter((u) => !u.disabled && twofaMethodOf(u) === 'email').length
