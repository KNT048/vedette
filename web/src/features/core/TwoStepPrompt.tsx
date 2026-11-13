import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { useMe } from '@/lib/session'
import { useAccount } from './api'

/** How long "Remind me later" hides the prompt in this browser (D-405: Google asks again, it does not stop asking). */
export const TWO_STEP_SNOOZE_DAYS = 30
const key = (id: string) => `vedette-two-step-later:${id}`

function snoozed(id: string): boolean {
  try {
    const until = Number(localStorage.getItem(key(id)))
    return Number.isFinite(until) && until > Date.now()
  } catch { return false }
}

/**
 * S-CORE-3 criterion D-405 (walk 4): Home asks an administrator whose password account has no two-step sign-in to turn it on,
 * until it is on. "Remind me later" hides it in this browser for TWO_STEP_SNOOZE_DAYS. Not shown to other roles, to SSO accounts
 * (their identity provider does it) or while the account is loading.
 */
export function TwoStepPrompt() {
  const { t } = useTranslation('core')
  const { data: me } = useMe()
  const ask = !!me && me.role === 'admin' && !me.twofa
  const account = useAccount(ask)
  const [laterFor, setLaterFor] = useState<string | null>(null) // the user who pressed Remind in this tab
  if (!ask || laterFor === me.id || snoozed(me.id) || !account.data || account.data.user.sso) return null
  const remind = () => {
    try { localStorage.setItem(key(me.id), String(Date.now() + TWO_STEP_SNOOZE_DAYS * 86_400_000)) } catch { /* the prompt comes back next visit */ }
    setLaterFor(me.id)
  }
  return (
    <div role="status" className="mb-6 rounded-md border border-warn/50 bg-warn-soft/60 px-4 py-3 text-sm">
      <p className="font-medium">{t('twoStepPrompt.title')}</p>
      <p className="mt-1 max-w-prose">{t('twoStepPrompt.body')}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <Button asChild size="sm" variant="primary"><Link to="/account#two-step">{t('twoStepPrompt.go')}</Link></Button>
        <Button size="sm" variant="ghost" onClick={remind}>{t('twoStepPrompt.later', { count: TWO_STEP_SNOOZE_DAYS })}</Button>
      </div>
    </div>
  )
}
