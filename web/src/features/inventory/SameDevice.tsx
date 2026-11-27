import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useSameDevice } from './api'
import { errMsg } from './kinds'
import { MergeFlow } from './MergeDialog'
import type { PossibleSame } from './types'

/** The id the device page section has, so the To review hint and a link can open it (useDeepLinkTarget focuses it). */
export const SAME_SECTION = 'possible-same'
type Me = { id: string; name: string; approved: boolean; ignored?: boolean }
/** After a merge from the notice: the device kept and the ones that went (the page moves to the kept one when it was not this one). */
type OnMerged = (kept: string, gone: string[]) => void

/** "nas is not added yet, last seen 2 days ago": what tells the two apart at a glance. It names the other device, so it is never read as
 *  this page's own state, and a device added by hand that nothing has seen says so, never "seen" at the time it was added. */
function StateLine({ p }: { p: PossibleSame }) {
  const { t } = useTranslation('inventory')
  const key = p.never_seen ? 'same.stateNeverSeen' : p.approved ? 'same.stateApproved' : 'same.statePending'
  return <span className="text-meta text-muted">{t(key, { name: p.name, when: fmtRelative(p.last_seen) })}</span>
}

/**
 * #829 gap 3: "Possibly the same device as X". The box could not be sure two rows are one machine (a phone with a new private
 * Wi-Fi address and a generic name, a MAC two rows share), so a person decides: Merge or Keep separate (admin). Fing and runZero leave such
 * twins to a delete or a support ticket; asking in place, with the reason, is the choice here. Shown above the approval notice: merging a
 * new row into the known device answers its approval too.
 */
export function PossibleSameNotice({ me, list, onMerged }: { me: Me; list: PossibleSame[]; onMerged?: OnMerged }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const [asking, setAsking] = useState<{ what: 'merge' | 'keep'; other: PossibleSame } | null>(null)
  const one = list.length === 1 ? list[0]! : null
  const other = (p: PossibleSame) => <Link to={`/devices/${encodeURIComponent(p.id)}`} className="text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{p.name}</Link>
  // #876: a deep link (#possible-same) focuses Merge when there is one pair, not the link to the other device in the title.
  const buttons = (p: PossibleSame, id?: string) => (admin ? (
    <span id={id} className="flex flex-wrap gap-2">
      <Button size="sm" variant="primary" onClick={() => setAsking({ what: 'merge', other: p })} aria-label={one ? undefined : t('same.mergeWith', { name: p.name })}>{t('same.merge')}</Button>
      <Button size="sm" onClick={() => setAsking({ what: 'keep', other: p })} aria-label={one ? undefined : t('same.keepSeparateWith', { name: p.name })}>{t('same.keepSeparate')}</Button>
    </span>
  ) : null)
  const focusButtons = !!one && admin
  // The dialogs live outside the notice: when the pair goes (merged, kept apart, refused and read again) the notice does, and the
  // dialog must stay to show the answer.
  return (
    <>
      {list.length ? (
        <Notice id={focusButtons ? undefined : SAME_SECTION} tone="accent" role="note" data-testid="possible-same" info={t('same.info')}
          title={one ? <>{t('same.title')} {other(one)}</> : t('same.titleMany', { count: list.length })}
          actions={one ? buttons(one, focusButtons ? SAME_SECTION : undefined) : undefined}>
          {one ? (
            <div className="grid gap-1">
              <p className="text-ink [overflow-wrap:anywhere]">{one.why}</p>
              <p className="flex flex-wrap gap-x-3"><StateLine p={one} />{admin ? null : <span className="text-meta">{t('same.adminOnly')}</span>}</p>
            </div>
          ) : (
            <>
              <ul className="grid gap-3" aria-label={t('same.titleMany', { count: list.length })}>
                {list.map((p) => (
                  <li key={p.id} className="grid gap-1.5 border-t border-rule pt-3 first:border-t-0 first:pt-0">
                    <span className="flex flex-wrap items-baseline gap-x-3">{other(p)}<StateLine p={p} /></span>
                    <p className="text-ink [overflow-wrap:anywhere]">{p.why}</p>
                    {buttons(p)}
                  </li>
                ))}
              </ul>
              {admin ? null : <p className="mt-2 text-meta">{t('same.adminOnly')}</p>}
            </>
          )}
        </Notice>
      ) : null}
      {/* the one merge dialog, prefilled with the pair; it keeps the approved one, the agent's or the named one unless the person picks */}
      {asking?.what === 'merge' ? <MergeFlow key={asking.other.id} start={{ ids: [me.id, asking.other.id], keep: asking.other.approved && !me.approved ? asking.other.id : me.id }} onClose={() => setAsking(null)} onMerged={onMerged} /> : null}
      {asking?.what === 'keep' ? <KeepDialog key={asking.other.id} me={me} other={asking.other} onClose={() => setAsking(null)} /> : null}
    </>
  )
}

/** Twins often share the name ("iPhone"): then the words say "this iPhone" and "the other iPhone", never "Merge iPhone into iPhone?".
 *  Only that wording is capitalised at the start of a sentence, never a device's own name ("nas-01" stays "nas-01"). */
function useSaid(me: Me, other: PossibleSame) {
  const { t } = useTranslation('inventory')
  return (d: { id: string; name: string }, start = false) => {
    if (me.name !== other.name) return d.name
    const s = t(d.id === me.id ? 'same.thisOne' : 'same.otherOne', { name: d.name })
    return start ? s.charAt(0).toUpperCase() + s.slice(1) : s
  }
}

/** #876: Keep separate also stops the automatic joins for the pair and no screen undoes it, so it asks first, naming both devices. */
function KeepDialog({ me, other, onClose }: { me: Me; other: PossibleSame; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const { keepSeparate } = useSameDevice()
  const said = useSaid(me, other)
  const [error, setError] = useState('')
  const confirm = () => {
    setError('')
    void keepSeparate.mutateAsync({ id: me.id, other: other.id }).then(() => {
      toast.success(t('same.keptSeparate', { name: other.name }))
      onClose()
    }, (e: unknown) => setError(errMsg(e)))
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !keepSeparate.isPending) onClose() }}>
      <DialogContent title={t('same.keepTitle', { a: said(me), b: said(other) })} description={t('same.keepBody')}>
        {error ? <p role="alert" className="text-meta text-danger [overflow-wrap:anywhere]">{error}</p> : null}
        <DialogFooter>
          <DialogClose asChild><Button disabled={keepSeparate.isPending}>{t('common:cancel')}</Button></DialogClose>
          <Button variant="primary" busy={keepSeparate.isPending} busyLabel={t('common:busy.saving')} onClick={confirm}>{t('same.keepConfirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The To review hint (#829): "Possibly the same device as X", linking to the section of this row's page that asks. */
export function SameHint({ id, others }: { id: string; others: string[] }) {
  const { t } = useTranslation('inventory')
  if (!others.length) return null
  return (
    <p className="text-meta">
      <Link to={`/devices/${encodeURIComponent(id)}#${SAME_SECTION}`} className="text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">
        {others.length === 1 ? t('same.hint', { name: others[0] }) : t('same.hintMany', { name: others[0], count: others.length - 1 })}
      </Link>
    </p>
  )
}

/** #876: on the Devices (approved) list a row in a pair carries a short chip, one line at 1280 px, linking to the question on its
 *  page; its accessible name is the whole hint and starts with the visible words (WCAG 2.5.3). */
export function SameChip({ id, others }: { id: string; others: string[] }) {
  const { t } = useTranslation('inventory')
  if (!others.length) return null
  const hint = others.length === 1 ? t('same.hint', { name: others[0] }) : t('same.hintMany', { name: others[0], count: others.length - 1 })
  return (
    <Link to={`/devices/${encodeURIComponent(id)}#${SAME_SECTION}`} onClick={(e) => e.stopPropagation()} aria-label={hint} title={hint} className="rounded-sm">
      <Chip tone="accent">{t('search.chip.same')}</Chip>
    </Link>
  )
}
