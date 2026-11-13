import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { fmtDate } from '@/lib/format'
import { BUNDLE_IN_UI } from '@/lib/bundle'
import { useUpdatesBanner } from './api'
import type { UpdatesState } from './types'

const WARNS = new Set(['block_install_and_warn', 'rollback_if_possible'])
const warns = (s: UpdatesState | undefined) => !!s?.running_revoked && WARNS.has(s.running_revoked.action)
/** The signed reason is a short sentence that may end with its own period; the sentence around it adds one. */
const reasonOf = (r: string) => r.trim().replace(/\.$/, '')

/**
 * S-CORE-2 criterion D-386 (1a): the running release is withdrawn with a warning, on every page for every role. A failed read shows nothing.
 * Rendered outside the page's keyed <main> so it is not mounted (and announced) again on every navigation.
 */
export function RevokedBanner() {
  const { t } = useTranslation('core')
  const { data } = useUpdatesBanner()
  if (!warns(data)) return null
  const r = data!.running_revoked!
  return (
    <div className="mx-auto w-full max-w-[1280px] px-4 pt-6 sm:px-6 lg:px-10 lg:pt-8">
      <div role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-4 py-3 text-sm">
        <p className="font-medium text-danger">{t('updates.revoked.title', { version: r.version })}</p>
        <p className="mt-1">{t('updates.revoked.body', { reason: reasonOf(r.reason) })} <Link className="text-accent underline-offset-4 hover:underline" to="/settings/updates">{t('updates.revoked.open')}</Link></p>
      </div>
    </div>
  )
}

/**
 * S-CORE-2 criterion D-407: the running Vedette version under the account menu of every page (as Grafana and Home Assistant
 * show theirs), from the same read as the banner; links to Settings → Updates. Nothing while it loads or fails.
 */
export function RunningVersion({ onNavigate }: { onNavigate?: () => void }) {
  const { t } = useTranslation('core')
  const { data } = useUpdatesBanner()
  const version = data?.components.find((c) => c.id === 'software')?.version
  if (!version) return null
  return <Link to="/settings/updates" onClick={onNavigate} className="truncate px-2.5 text-[12px] text-muted underline-offset-4 hover:text-ink hover:underline">{t('updates.footerVersion', { version })}</Link>
}

/** D-386 (1b), (2): on the Updates page only, a withdrawn release with block_install and stale update information. `bundle`: the install can import an offline bundle (appliance, and only while BUNDLE_IN_UI, D-408). */
export function UpdateNotices({ s, bundle = BUNDLE_IN_UI }: { s: UpdatesState; bundle?: boolean }) {
  const { t } = useTranslation('core')
  const quiet = s.running_revoked && !warns(s) ? s.running_revoked : null
  const box = 'mb-6 rounded-md border border-warn/50 bg-warn-soft/60 px-4 py-3 text-sm'
  return (
    <>
      {quiet ? (
        <div role="status" className={box}>
          <p className="font-medium">{t('updates.revoked.quietTitle', { version: quiet.version })}</p>
          <p className="mt-1">{t('updates.revoked.quietBody', { reason: reasonOf(quiet.reason) })}</p>
        </div>
      ) : null}
      {s.stale_since ? (
        <div role="status" className={box}>
          <p className="font-medium">{t('updates.stale.title')}</p>
          <p className="mt-1">{t('updates.stale.body', { date: fmtDate(s.stale_since) })} {s.check_enabled ? t('updates.stale.checkOn') : bundle ? t('updates.stale.checkOff') : t('updates.stale.checkOffNoBundle')}</p>
        </div>
      ) : null}
    </>
  )
}
