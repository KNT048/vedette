import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { Button } from '@/components/ui/button'
import { fmtWhen } from '@/lib/format'
import { useCan, useMe } from '@/lib/session'
import type { FirstRunSummary, Overview } from '@/features/findings/types'
import { OPEN_FINDING_STATUSES, type OpenFindingStatus } from '@/lib/statusCodes'

// Hidden per user in this browser, for that summary only (a convenience, docs/UI.md §2): the summary of a later load shows again.
// Storage errors: shown, never remembered.
const HIDE_KEY = (user: string) => `vedette.home.firstRun.${user}`
function readHidden(user: string): string | null {
  try { return localStorage.getItem(HIDE_KEY(user)) } catch { return null }
}
function writeHidden(user: string, id: string) {
  try { localStorage.setItem(HIDE_KEY(user), id) } catch { /* the card comes back next visit */ }
}

/** The statuses the summary's list opens on (`status=` of its link); every open status when it names none. */
function statusesOf(link: string): OpenFindingStatus[] {
  const q = new URLSearchParams(link.split('?')[1] ?? '').get('status')
  if (!q) return [...OPEN_FINDING_STATUSES]
  return q.split(',').filter((s): s is OpenFindingStatus => (OPEN_FINDING_STATUSES as readonly string[]).includes(s))
}

/** One line of where the summary is: delivered (when, through which channels), waiting in the queue (until when), or why it was not sent. */
function StateLine({ f }: { f: FirstRunSummary }) {
  const { t } = useTranslation(['feeds', 'notify'])
  const admin = useCan('admin')
  const link = 'text-accent underline-offset-4 hover:underline'
  if (f.state === 'sent') {
    const by = new Intl.ListFormat('en', { type: 'conjunction' }).format(f.channels.map((c) => t(`notify:ch.${c}`, { defaultValue: c })))
    return <p className="text-meta text-muted">{by ? t('firstRun.sentBy', { when: fmtWhen(f.sent_at), by }) : t('firstRun.sent', { when: fmtWhen(f.sent_at) })}</p>
  }
  if (f.state === 'waiting') {
    const now = f.due_at ? Date.parse(f.due_at) <= Date.now() : true
    return (
      <p className="text-meta text-muted">
        {f.quiet && f.due_at ? t('firstRun.quiet', { when: fmtWhen(f.due_at) }) : now ? t('firstRun.goingNow') : t('firstRun.waiting', { when: fmtWhen(f.due_at) })}
      </p>
    )
  }
  // Not sent: it is still the box's own finding, so the card shows it, says why, and offers the fix to an administrator.
  const fix = f.reason === 'no_channel' || f.reason === 'channels_off' || f.reason === 'below_min_severity' ? 'setUp'
    : f.reason === 'failed' ? 'history' : null
  return (
    <p className="text-meta text-warn">
      {f.not_sent ?? t('firstRun.notSent')}{' '}
      {admin && fix === 'setUp' ? <Link to="/settings/channels#channels" className={link}>{t('firstRun.setUp')}</Link> : null}
      {admin && fix === 'history' ? <Link to="/settings/channels#history" className={link}>{t('firstRun.history')}</Link> : null}
    </p>
  )
}

/**
 * The first-run summary on Home: when a load (the box's own first look above all) first rates findings urgent, Vedette sends one
 * summary instead of one alert each. Mail or chat is not where everyone looks first, so Home shows it too, for 7 days after it was
 * made (the overview stops carrying it), until Hide: its title, where the message is, and the list it names. A summary no channel
 * took is shown all the same, with why.
 */
export function FirstRunCard({ o }: { o: Overview }) {
  const { t } = useTranslation('feeds')
  const { data: me } = useMe()
  const [hidden, setHidden] = useState<string | null>(null)
  const f = o.first_run_summary
  if (!f || !me) return null
  if (hidden === f.id || readHidden(me.id) === f.id) return null
  const open = statusesOf(f.link).reduce((n, s) => n + o.open.by_status[s], 0)
  const hide = () => { writeHidden(me.id, f.id); setHidden(f.id) }
  return (
    <Card id="first-run-summary" className="mb-8" title={t(`firstRun.title.${f.load}`)} info={t('firstRun.info')}
      actions={<Button size="sm" variant="ghost" onClick={hide}>{t('firstRun.hide')}</Button>}>
      <div className="grid gap-2">
        <p className="text-sm font-medium [overflow-wrap:anywhere]">{f.title}</p>
        <StateLine f={f} />
        {f.later_title ? <p className="text-meta text-muted [overflow-wrap:anywhere]">{t('firstRun.later', { count: f.later, title: f.later_title })}</p> : null}
        {open === 0 ? <p className="text-meta text-ok">{t('firstRun.allHandled')}</p> : null}
        <div className="mt-1 flex flex-wrap gap-2">
          <Button asChild size="sm" variant={open ? 'primary' : 'secondary'}><Link to={f.link}>{t('firstRun.open')}</Link></Button>
        </div>
      </div>
    </Card>
  )
}
