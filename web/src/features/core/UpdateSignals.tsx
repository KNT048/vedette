import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { fmtDate } from '@/lib/format'
import { useUpdates } from './api'
import type { UpdatesState } from './types'

const WARNS = new Set(['block_install_and_warn', 'rollback_if_possible'])
const warns = (s: UpdatesState | undefined) => !!s?.running_revoked && WARNS.has(s.running_revoked.action)

/** S-CORE-2 criterion D-386 (1a): the running release is withdrawn with a warning, on every page for every role. A failed read shows nothing. */
export function RevokedBanner() {
  const { t } = useTranslation('core')
  const { data } = useUpdates()
  if (!warns(data)) return null
  const r = data!.running_revoked!
  return (
    <div role="alert" className="mb-6 rounded-md border border-danger/40 bg-danger-soft px-4 py-3 text-sm">
      <p className="font-medium text-danger">{t('updates.revoked.title', { version: r.version })}</p>
      <p className="mt-1">{t('updates.revoked.body', { reason: r.reason })} <Link className="text-accent underline-offset-4 hover:underline" to="/settings/updates">{t('updates.revoked.open')}</Link></p>
    </div>
  )
}

/** D-386 (1b), (2): on the Updates page only, a withdrawn release with block_install and stale update information. */
export function UpdateNotices({ s }: { s: UpdatesState }) {
  const { t } = useTranslation('core')
  const quiet = s.running_revoked && !warns(s) ? s.running_revoked : null
  const box = 'mb-6 rounded-md border border-warn/50 bg-warn-soft/60 px-4 py-3 text-sm'
  return (
    <>
      {quiet ? (
        <div role="status" className={box}>
          <p className="font-medium">{t('updates.revoked.quietTitle', { version: quiet.version })}</p>
          <p className="mt-1">{t('updates.revoked.quietBody', { reason: quiet.reason })}</p>
        </div>
      ) : null}
      {s.stale_since ? (
        <div role="status" className={box}>
          <p className="font-medium">{t('updates.stale.title')}</p>
          <p className="mt-1">{t('updates.stale.body', { date: fmtDate(s.stale_since) })} {s.check_enabled ? t('updates.stale.checkOn') : t('updates.stale.checkOff')}</p>
        </div>
      ) : null}
    </>
  )
}
