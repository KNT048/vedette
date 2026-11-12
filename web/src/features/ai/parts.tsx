import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ApiError } from '@/lib/api'
import { useCan } from '@/lib/session'
import { useModuleEnabled } from '@/lib/modules'
import { useAiConfig } from './api'
import type { AiJob } from './types'

/** Lỗi của một thao tác (không phải lỗi tải trang): nói cái gì sai, kèm cách sửa từ máy chủ. */
export function ActionError({ error }: { error: unknown }) {
  if (!error) return null
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error)
  return <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{msg}</p>
}

/** Việc AI chỉ chạy được khi module bật, có hồ sơ AI dùng được và việc đó được gán hồ sơ (kể cả luật riêng tư). `reason` giải thích nút bị khoá. */
export function useAiGate(minRole: 'operator' | 'viewer' = 'operator', job?: AiJob) {
  const { t } = useTranslation('ai')
  const on = useModuleEnabled('ai')
  const cfg = useAiConfig(on === true) // with the module off the route is 404: not asked (S-CORE-9, 2026-11-12 walk)
  const can = useCan(minRole)
  const unassigned = !!job && !!cfg.data?.configured && cfg.data.jobs_ready[job] === false
  const state: 'loading' | 'off' | 'unconfigured' | 'unassigned' | 'ready' = on === undefined || (on && cfg.isPending) ? 'loading' : !on ? 'off' : !cfg.data?.configured ? 'unconfigured' : unassigned ? 'unassigned' : 'ready'
  const reason = state !== 'ready' ? t(`gate.${state}`) : !can ? t('common:needRole', { role: t(`common:role.${minRole}`) }) : undefined
  return { state, canRun: state === 'ready' && can, reason, cfg: cfg.data }
}

export function ToSettings({ className }: { className?: string }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  return admin
    ? <Link to="/settings/ai" className={className ?? 'text-accent underline underline-offset-4'}>{t('gate.toSettings')}</Link>
    : <span className="text-muted">{t('gate.askAdmin')}</span>
}
