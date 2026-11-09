// Gói chẩn đoán báo lỗi (D-42, S-CORE-5). Hộp không gửi gì: người dùng tải tệp và tự mở GitHub issue trong trình duyệt của mình.
import { getClientErrors, redact, type ClientError } from '@/lib/clientErrors'
import type { ModuleState } from '@/lib/modules'

export const ISSUE_URL = 'https://github.com/kiennt048/vedette/issues/new'

export interface BugText { what: string; steps: string; expected: string }
export interface DiagnosticBundle {
  app_version: string
  user_agent: string
  route: string
  data_mode: 'mock' | 'live'
  modules: Record<string, 'on' | 'off'>
  recent_errors: ClientError[]
}

/** Chỉ các trường này, không thiết bị, log, phát hiện, khoá, email hay IP. */
export function buildBundle(modules: ModuleState[] | undefined): DiagnosticBundle {
  return {
    app_version: String(import.meta.env.VITE_APP_VERSION ?? '0.0.0-preview'),
    user_agent: navigator.userAgent,
    route: location.pathname.replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '[ip]'),
    data_mode: import.meta.env.VITE_API_MOCK === 'off' ? 'live' : 'mock',
    modules: Object.fromEntries((modules ?? []).map((m) => [m.id, m.enabled ? 'on' : 'off'] as const)),
    recent_errors: getClientErrors(),
  }
}

export function issueUrl(text: BugText, b: DiagnosticBundle): string {
  const clean = (s: string) => redact(s.trim())
  const title = `[bug] ${clean(text.what).split('\n')[0]!.slice(0, 80) || 'Problem report'}`
  const body = [
    '## What happened', clean(text.what) || '_not given_',
    '## Steps to reproduce', clean(text.steps) || '_not given_',
    '## What I expected', clean(text.expected) || '_not given_',
    '## Summary', `Version ${b.app_version}, page ${b.route}, data ${b.data_mode}, ${b.recent_errors.length} recent client error(s).`,
    '_I will attach the downloaded diagnostic file to this issue._',
  ].join('\n\n').slice(0, 4000)
  return `${ISSUE_URL}?${new URLSearchParams({ title, body }).toString()}`
}

export function downloadBundle(text: BugText, b: DiagnosticBundle) {
  const json = JSON.stringify({ report: { what: redact(text.what), steps: redact(text.steps), expected: redact(text.expected) }, diagnostics: b }, null, 2)
  const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `vedette-report-${new Date().toISOString().slice(0, 10)}.json`
  document.body.append(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
