import { lazy, Suspense, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { ApiError } from '@/lib/api'
import { useCan } from '@/lib/session'
import { useModuleEnabled } from '@/lib/modules'
import { useAiConfig, useProfiles } from './api'
import type { AiJob } from './types'

// The profile dialog lives with Settings, AI assistant; loaded only when a page opens it to add the first profile.
const ProfileDialog = lazy(() => import('./AiSettings').then((m) => ({ default: m.ProfileDialog })))

/** The error of an action (not a page-load error): say what is wrong, with the fix from the server. */
export function ActionError({ error }: { error: unknown }) {
  if (!error) return null
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error)
  return <Notice tone="danger" role="alert" className="mb-0" title={msg} />
}

/** An AI job can run only when the module is on, there is a usable AI profile and the job is assigned a profile (privacy rule included). `reason` explains the locked button. */
export function useAiGate(minRole: 'operator' | 'viewer' = 'operator', job?: AiJob) {
  const { t } = useTranslation('ai')
  const on = useModuleEnabled('ai')
  const cfg = useAiConfig(on === true) // with the module off the route is 404: not asked (S-CORE-9)
  const can = useCan(minRole)
  const unassigned = !!job && !!cfg.data?.configured && cfg.data.jobs_ready[job] === false
  // #847: after a restore without the key every profile is key_lost, so none is usable and the box reads "not configured". The
  // profiles are still there (and assigned): the way out is their key, never a second profile. Asked only in that case.
  const unconf = on === true && cfg.data?.configured === false
  const profiles = useProfiles(unconf)
  const items = profiles.data?.items ?? []
  const keyLost = unconf && items.length > 0 && !items.some((p) => p.usable) && items.some((p) => p.key_lost)
  const state: 'loading' | 'off' | 'unconfigured' | 'unassigned' | 'ready' = on === undefined || (on && cfg.isPending) || (unconf && profiles.isPending) ? 'loading' : !on ? 'off' : !cfg.data?.configured ? 'unconfigured' : unassigned ? 'unassigned' : 'ready'
  /** The words of the state: 'keyLost' for an unconfigured box whose profiles lost their key (gate.keyLost*, ToSettings). */
  const text = state === 'unconfigured' && keyLost ? 'keyLost' : state
  const reason = state !== 'ready' ? t(`gate.${text}`) : !can ? t('common:needRole', { role: t(`common:role.${minRole}`) }) : undefined
  return { state, text, canRun: state === 'ready' && can, reason, cfg: cfg.data }
}

/** Where a blocked AI task is unblocked (docs/UI.md §0): no profile yet → "Add an AI profile" right here (the profile dialog of Settings,
 *  AI assistant, which still edits it there), with the link to the profiles; a profile exists but this task has none → the task's
 *  primary-profile select in the routing table; else `to` (default: the profiles). A non-administrator is told to ask one. */
export function ToSettings({ className, state, job, to }: { className?: string; state?: string; job?: AiJob; to?: string }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  const [adding, setAdding] = useState(false)
  const profiles = useProfiles(admin && adding)
  const link = className ?? 'text-accent underline underline-offset-4'
  if (!admin) return <span className="text-muted">{t(state === 'keyLost' ? 'gate.askAdminKey' : 'gate.askAdmin')}</span>
  if (state === 'unassigned' && job) return <Link to={`/settings/ai#ai-job-${job}`} className={link}>{t('gate.toAssign')}</Link>
  // The lost profiles' notices (Enter the key) are at the top of the profiles; a new profile would only duplicate one.
  if (state === 'keyLost') return <Link to="/settings/ai#ai-profiles" className={link}>{t('gate.toKey')}</Link>
  if (state === 'unconfigured') {
    return (
      <span className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2">
        <Button variant="primary" size="sm" onClick={() => setAdding(true)}>{t('profiles.add')}</Button>
        <Link to="/settings/ai#ai-profiles" className={link}>{t('gate.toSettings')}</Link>
        {adding && !profiles.isPending ? <Suspense fallback={null}><ProfileDialog profile={null} existing={profiles.data?.items ?? []} onClose={() => setAdding(false)} /></Suspense> : null}
      </span>
    )
  }
  return <Link to={to ?? '/settings/ai#ai-profiles'} className={link}>{t('gate.toSettings')}</Link>
}
