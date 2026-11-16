import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Field, Select } from '@/components/ui/input'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useSameDevice } from './api'
import { errMsg } from './kinds'
import type { PossibleSame } from './types'

/** The id the device page section has, so the To review hint and a link can open it (useDeepLinkTarget focuses it). */
export const SAME_SECTION = 'possible-same'
type Me = { id: string; name: string; approved: boolean }

/** "Waiting for review, seen 2 days ago": what tells the two apart at a glance. */
function StateLine({ approved, lastSeen }: { approved: boolean; lastSeen: string }) {
  const { t } = useTranslation('inventory')
  return <span className="text-meta text-muted">{t(approved ? 'same.stateApproved' : 'same.statePending', { when: fmtRelative(lastSeen) })}</span>
}

/**
 * D-599 (#829 gap 3, J2): "Possibly the same device as X". The box could not be sure two rows are one machine (a phone with a new private
 * Wi-Fi address and a generic name, a MAC two rows share), so a person decides: Merge or Keep separate (admin). Fing and runZero leave such
 * twins to a delete or a support ticket; asking in place, with the reason, is the D-599 choice. Shown above the approval notice: merging a
 * new row into the known device answers its approval too.
 */
export function PossibleSameNotice({ me, list }: { me: Me; list: PossibleSame[] }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const act = useSameDevice()
  const [merging, setMerging] = useState<PossibleSame | null>(null)
  if (!list.length) return null
  const one = list.length === 1 ? list[0]! : null
  const other = (p: PossibleSame) => <Link to={`/devices/${encodeURIComponent(p.id)}`} className="font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{p.name}</Link>
  // mutateAsync: the pair leaves the page when the device is read again, which would drop a mutate() callback and its toast
  const keepSeparate = (p: PossibleSame) => void act.keepSeparate.mutateAsync({ id: me.id, other: p.id })
    .then(() => toast.success(t('same.keptSeparate', { name: p.name })), (e: unknown) => toast.error(errMsg(e)))
  const buttons = (p: PossibleSame) => (admin ? (
    <span className="flex flex-wrap gap-2">
      <Button size="sm" variant="primary" disabled={act.merge.isPending} onClick={() => setMerging(p)} aria-label={one ? undefined : t('same.mergeWith', { name: p.name })}>{t('same.merge')}</Button>
      <Button size="sm" disabled={act.keepSeparate.isPending} onClick={() => keepSeparate(p)} aria-label={one ? undefined : t('same.keepSeparateWith', { name: p.name })}>{t('same.keepSeparate')}</Button>
    </span>
  ) : null)
  return (
    <Notice id={SAME_SECTION} tone="accent" role="note" data-testid="possible-same" info={t('same.info')}
      title={one ? <>{t('same.title')} {other(one)}</> : t('same.titleMany', { count: list.length })}
      actions={one ? buttons(one) : undefined}>
      {one ? (
        <div className="grid gap-1">
          <p className="text-ink [overflow-wrap:anywhere]">{one.why}</p>
          <p className="flex flex-wrap gap-x-3"><StateLine approved={one.approved} lastSeen={one.last_seen} />{admin ? null : <span className="text-meta">{t('same.adminOnly')}</span>}</p>
        </div>
      ) : (
        <>
          <ul className="grid gap-3" aria-label={t('same.titleMany', { count: list.length })}>
            {list.map((p) => (
              <li key={p.id} className="grid gap-1.5 border-t border-rule pt-3 first:border-t-0 first:pt-0">
                <span className="flex flex-wrap items-baseline gap-x-3">{other(p)}<StateLine approved={p.approved} lastSeen={p.last_seen} /></span>
                <p className="text-ink [overflow-wrap:anywhere]">{p.why}</p>
                {buttons(p)}
              </li>
            ))}
          </ul>
          {admin ? null : <p className="mt-2 text-meta">{t('same.adminOnly')}</p>}
        </>
      )}
      {merging ? <MergeDialog key={merging.id} me={me} other={merging} onClose={() => setMerging(null)} /> : null}
    </Notice>
  )
}

/** The confirm names both devices, which one stays (the approved one by default, else this one; the admin may pick the other), what
 *  moves and that the other disappears. An answer the box refuses (two machines, a device gone) stays in the dialog, word for word. */
function MergeDialog({ me, other, onClose }: { me: Me; other: PossibleSame; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const navigate = useNavigate()
  const { merge } = useSameDevice()
  const [keep, setKeep] = useState(other.approved && !me.approved ? other.id : me.id)
  const [error, setError] = useState('')
  // Twins often share the name ("iPhone"): then the words say "this iPhone" and "the other iPhone", never "Merge iPhone into iPhone?"
  const said = (d: { id: string; name: string }) => (me.name !== other.name ? d.name : t(d.id === me.id ? 'same.thisOne' : 'same.otherOne', { name: d.name }))
  const kept = keep === me.id ? { id: me.id, name: said(me) } : { id: other.id, name: said(other) }
  const gone = keep === me.id ? { id: other.id, name: said(other) } : { id: me.id, name: said(me) }
  const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)
  const option = (d: { id: string; name: string; approved: boolean }) => (
    <option key={d.id} value={d.id}>{t(d.approved ? 'same.keepOptionApproved' : 'same.keepOptionPending', { name: cap(said(d)) })}</option>
  )
  const confirm = () => {
    setError('')
    // mutateAsync: once the lists are read again this dialog is gone (the pair is), and a mutate() callback with it
    void merge.mutateAsync({ into: kept.id, from: gone.id }).then((r) => {
      toast.success(t('same.merged', { name: keep === me.id ? me.name : other.name }))
      onClose()
      if (r.id !== me.id) void navigate(`/devices/${encodeURIComponent(r.id)}`)
    }, (e: unknown) => setError(errMsg(e)))
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('same.mergeTitle', { from: gone.name, into: kept.name })} description={cap(t('same.mergeBody', { from: gone.name, into: kept.name }))} info={t('same.mergeInfo')}>
        <Field label={t('same.keepLabel')} htmlFor="same-keep" hint={t('same.keepHint')}>
          <Select id="same-keep" value={keep} disabled={merge.isPending} onChange={(e) => { setKeep(e.target.value); setError('') }}>
            {option(me)}{option(other)}
          </Select>
        </Field>
        {error ? <p role="alert" className="text-meta text-danger [overflow-wrap:anywhere]">{error}</p> : null}
        <DialogFooter>
          <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
          <Button variant="primary" disabled={merge.isPending} onClick={confirm}>{t('same.mergeConfirm', { from: gone.name, into: kept.name })}</Button>
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
