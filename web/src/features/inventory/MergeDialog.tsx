import { useEffect, useId, useMemo, useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { Loading } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { StatusBadge } from '@/components/common/status/StatusBadge'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Input, Label } from '@/components/ui/input'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { kindLabel } from '@/lib/deviceTypes'
import { cn } from '@/lib/utils'
import { ADDRESSES_SECTION } from './AddressesSection'
import { useDevices, useMergePreview, useSameDevice } from './api'
import { errMsg } from './kinds'
import { declaredSoftwareOnly, nameOf } from './nameOf'
import {
  addressText, choiceFields, defaultKeep, matchesQuery, MERGE_MAX_FROM, movePieces, nameScore, rankCandidates, shownDiffers, watchAfterMergeAll,
  type Candidate, type MovePiece, type PickerMe, type ShownField, type Suggestion,
} from './mergeLogic'
import type { DeviceRow, MergeField, MergeSide } from './types'

/** How a merge starts: with the devices already chosen (a selection of the list, a suggested pair), or from one device whose
 *  twins the person picks first ("Merge with…"). `keep`: the device the caller expects to stay, so the first preview usually is
 *  the right one; the dialog still keeps the best one by its own rule. */
export type MergeStart =
  | { ids: string[]; keep?: string }
  | { pickFor: PickerMe & { label: string }; suggested: Suggestion[] }

/**
 * The one merge dialog (admin), over the page it is opened from: Devices (a selection or a row's "Merge with…"), the device page
 * ("Merge with…", a suggested pair). Picking the twins and reviewing the merge are two steps of one dialog, so Back keeps the
 * picks and focus stays inside. After the merge the person stays where they were; `onMerged` says which device stayed and which
 * went (the device page moves to the one kept when it was not this one). A toast offers Split, the way back.
 */
export function MergeFlow({ start, onClose, onMerged }: { start: MergeStart; onClose: () => void; onMerged?: (kept: string, gone: string[]) => void }) {
  const { t } = useTranslation('inventory')
  const navigate = useNavigate()
  const picking = 'pickFor' in start
  const [step, setStep] = useState<{ ids: string[]; keep?: string } | null>(picking ? null : start)
  const [picked, setPicked] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const done = (kept: string, keptName: string, gone: string[]) => {
    toast.success(t('merge.done', { count: gone.length + 1, name: keptName }), {
      description: t('merge.doneHint'),
      action: { label: t('merge.split'), onClick: () => void navigate(`/devices/${encodeURIComponent(kept)}#${ADDRESSES_SECTION}`) },
    })
    onClose()
    onMerged?.(kept, gone)
  }
  const title = step ? t('merge.title', { count: step.ids.length }) : picking ? t('merge.pick.title', { name: start.pickFor.label }) : ''
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !busy) onClose() }}>
      <DialogContent wide title={title} description={step ? t('merge.description') : t('merge.pick.description')} info={t('merge.info')}>
        {step ? (
          <MergeReview key={step.ids.join(',')} ids={step.ids} hint={step.keep} onBusy={setBusy} onDone={done}
            onBack={picking ? () => setStep(null) : undefined} />
        ) : picking ? (
          <MergePicker me={start.pickFor} suggested={start.suggested} picked={picked} setPicked={setPicked}
            onNext={() => setStep({ ids: [start.pickFor.id, ...picked], keep: start.pickFor.id })} />
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

/** A device of the list as every page names it. */
const rowName = (r: DeviceRow) => nameOf(r, kindLabel(r.kind))

/** Step 1 of "Merge with…": the devices that may be this machine, the box's suggestions first with their reason, then the similar
 *  and nearby ones; searchable by name, IP or MAC; up to 8 picked. The list is the Devices list's own cached read. */
function MergePicker({ me, suggested, picked, setPicked, onNext }: {
  me: PickerMe & { label: string }; suggested: Suggestion[]; picked: string[]; setPicked: (ids: string[]) => void; onNext: () => void
}) {
  const { t } = useTranslation('inventory')
  const id = useId()
  const list = useDevices()
  const [q, setQ] = useState('')
  const ranked = useMemo(() => {
    const rows = (list.data?.items ?? []).filter((r) => !declaredSoftwareOnly(r))
    return rankCandidates(me, rows, suggested, rowName)
  }, [list.data, me, suggested])
  const shown = ranked.filter((c) => matchesQuery(c.row, rowName(c.row), q))
  // the device itself is never a candidate; searching for it says so instead of "no device matches"
  const meRow = list.data?.items.find((r) => r.id === me.id)
  const self = !!q.trim() && !!meRow && matchesQuery(meRow, me.label, q)
  const full = picked.length >= MERGE_MAX_FROM
  const toggle = (rid: string, on: boolean) => setPicked(on ? [...picked, rid] : picked.filter((x) => x !== rid))
  const groups = (['suggested', 'similar', 'nearby', 'other'] as const).map((g) => ({ g, items: shown.filter((c) => c.group === g) })).filter((x) => x.items.length)
  const why = (c: Candidate) => {
    if (c.group === 'suggested') return c.reason ? t(`merge.reason.${c.reason}`) : ''
    if (c.similar) return t(`merge.pick.same${c.similar.what === 'model' ? 'Model' : c.similar.what === 'name' ? 'Name' : 'Maker'}`, { value: c.similar.value })
    return c.near ? t('merge.pick.near', { mac: c.near }) : ''
  }
  let body: React.ReactNode
  if (list.isPending) body = <Loading />
  else if (list.error) body = <p role="alert" className="text-meta text-danger">{t('merge.pick.loadFailed')} {errMsg(list.error)}</p>
  else if (!ranked.length) body = <p className="text-sm text-muted">{t('merge.pick.empty')}</p>
  else if (!shown.length) body = <p className="text-sm text-muted" role="status">{self ? t('merge.pick.self', { name: me.label }) : t('merge.pick.none', { q: q.trim() })}</p>
  else {
    body = (
      <div className="grid max-h-[46vh] gap-4 overflow-y-auto pr-1" data-testid="merge-candidates">
        {groups.map(({ g, items }) => (
          <section key={g} aria-labelledby={`${id}-${g}`} className="grid gap-1">
            <h3 id={`${id}-${g}`} className="text-meta font-medium text-muted">{t(`merge.pick.group.${g}`)}</h3>
            <ul className="grid">
              {items.map((c) => {
                const r = c.row
                const on = picked.includes(r.id)
                const hw = [r.vendor?.value, r.model?.value].filter(Boolean).join(' ')
                const cid = `${id}-c-${r.id}`
                return (
                  <li key={r.id} className={cn('flex items-start gap-3 rounded-md px-2 py-2', on && 'bg-accent-soft')}>
                    <Checkbox id={cid} className="mt-1" checked={on} disabled={!on && full} onCheckedChange={(v) => toggle(r.id, v === true)} aria-describedby={`${cid}-why`} />
                    <label htmlFor={cid} className="grid min-w-0 flex-1 cursor-pointer gap-0.5">
                      <span className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
                        <span className="font-medium [overflow-wrap:anywhere]">{rowName(r)}</span>
                        {r.ip && r.ip !== '—' ? <span className="text-meta tabular-nums text-muted">{r.ip}</span> : null}
                        {r.mac ? <span className="text-meta tabular-nums text-muted">{r.mac}</span> : null}
                        {r.approved ? null : <span className="text-meta text-warn">{t('merge.pending')}</span>}
                      </span>
                      {hw ? <span className="text-meta text-muted [overflow-wrap:anywhere]">{hw}</span> : null}
                      <span id={`${cid}-why`} className="text-meta [overflow-wrap:anywhere]">
                        {why(c)}{c.why ? <span className="text-muted">{`. ${c.why}`}</span> : null}
                      </span>
                    </label>
                  </li>
                )
              })}
            </ul>
          </section>
        ))}
      </div>
    )
  }
  return (
    <>
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-q`}>{t('merge.pick.search')}</Label>
        <Input id={`${id}-q`} type="search" value={q} autoComplete="off" onChange={(e) => setQ(e.target.value)} />
      </div>
      {self && shown.length ? <p className="text-meta text-muted" role="status">{t('merge.pick.self', { name: me.label })}</p> : null}
      {body}
      <DialogFooter className="items-center">
        <span role="status" aria-live="polite" className="mr-auto text-meta text-muted">
          {picked.length ? t('merge.pick.picked', { count: picked.length }) : ''}{full ? ` ${t('merge.pick.max', { count: MERGE_MAX_FROM })}` : ''}
        </span>
        <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
        <Button variant="primary" disabled={!picked.length} onClick={onNext}>{t('merge.pick.next')}</Button>
      </DialogFooter>
    </>
  )
}

type Field = MergeField['field']

/**
 * Step 2: which device stays, the fields they state differently (a choice where the merge takes one), what moves, and why the box
 * would refuse; one primary button. The preview is read for the device kept: on open for the caller's guess, then for the best
 * device by the default rule, and again each time the person picks another.
 */
function MergeReview({ ids, hint, onBack, onBusy, onDone }: {
  ids: string[]; hint?: string; onBack?: () => void; onBusy: (b: boolean) => void; onDone: (kept: string, keptName: string, gone: string[]) => void
}) {
  const { t } = useTranslation('inventory')
  const id = useId()
  const rows = useDevices().data?.items
  const { merge } = useSameDevice()
  const [keep, setKeep] = useState<string | null>(null)
  const into = keep ?? (hint && ids.includes(hint) ? hint : ids[0]!)
  const from = ids.filter((x) => x !== into)
  const preview = useMergePreview(into, from)
  const data = preview.data
  const named = useMemo(() => {
    const m = new Map((rows ?? []).map((r) => [r.id, nameScore(r)]))
    return (x: string) => m.get(x) ?? 0
  }, [rows])
  const sides = useMemo(() => (data ? [data.into, ...data.from] : []), [data])
  const best = sides.length ? defaultKeep(sides, named) : ''
  // the first answer settles the device kept by the default rule (set while rendering, React's pattern for state derived from a
  // new value); a different one reads the preview again for it
  if (keep === null && best) setKeep(best)
  const [picked, setPicked] = useState<{ into: string; v: Partial<Record<Field, string>> }>({ into: '', v: {} })
  const choices = picked.into === into ? picked.v : {}
  const [error, setError] = useState('')
  useEffect(() => { onBusy(merge.isPending) }, [merge.isPending, onBusy])

  const fresh = !!data && !preview.isPlaceholderData && data.into.id === into && keep !== null
  const fields = fresh ? shownDiffers(data.differs) : []
  const byId = new Map(sides.map((s) => [s.id, s]))
  const keptSide = byId.get(into)
  const goneSides = from.map((x) => byId.get(x)).filter((s): s is MergeSide => !!s)
  const sideName = (x: string) => byId.get(x)?.name ?? rows?.find((r) => r.id === x)?.ip ?? x
  const watch = keptSide ? watchAfterMergeAll(keptSide, goneSides) : ''
  const refusal = fresh ? data.refusal : null
  const confirm = () => {
    if (!fresh) return
    setError('')
    const fieldsSent = choiceFields(fields, choices)
    void merge.mutateAsync({ into, from, fields: fieldsSent }).then((r) => {
      onDone(r.id, fieldsSent?.name ?? keptSide?.name ?? sideName(into), from)
    }, (e: unknown) => setError(errMsg(e)))
  }

  if (!data) {
    if (preview.error) {
      return (
        <>
          <p role="alert" className="text-meta text-danger [overflow-wrap:anywhere]">{t('merge.previewFailed')} {errMsg(preview.error)}</p>
          <DialogFooter>
            {onBack ? <Button variant="ghost" className="mr-auto" onClick={onBack}>{t('merge.back')}</Button> : null}
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button busy={preview.isFetching} busyLabel={t('merge.loading')} onClick={() => void preview.refetch()}>{t('common:retry')}</Button>
          </DialogFooter>
        </>
      )
    }
    return <Loading label={t('merge.loading')} />
  }
  return (
    <>
      <fieldset className="grid gap-2" disabled={merge.isPending}>
        <legend id={`${id}-keep`} className="mb-1 text-sm font-medium">{t('merge.keep')}</legend>
        <p className="-mt-1 text-meta text-muted">{t('merge.keepHint')}</p>
        <RadioGroup value={into} aria-labelledby={`${id}-keep`} onValueChange={(v) => { setKeep(v); setError('') }}>
          {ids.map((x) => {
            const s = byId.get(x)
            return s ? <KeepOption key={x} id={`${id}-k-${x}`} side={s} checked={x === into} suggested={x === best && ids.length > 1} /> : null
          })}
        </RadioGroup>
      </fieldset>

      {!fresh ? <Loading label={t('merge.loading')} /> : (
        <>
          {fields.length ? (
            <section aria-labelledby={`${id}-differ`} className="grid gap-3">
              <div className="grid gap-0.5">
                <h3 id={`${id}-differ`} className="text-sm font-medium">{t('merge.differ')}</h3>
                <p className="text-meta text-muted">{t('merge.differHint')}</p>
              </div>
              <dl className="grid gap-3 sm:grid-cols-[minmax(120px,max-content)_1fr] sm:gap-x-6">
                {fields.map((f) => (
                  <DifferRow key={f.field} id={`${id}-f-${f.field}`} f={f} value={choices[f.field] ?? f.kept} disabled={merge.isPending} nameOf={sideName}
                    onPick={(v) => setPicked({ into, v: { ...choices, [f.field]: v } })} />
                ))}
              </dl>
            </section>
          ) : null}
          <section aria-labelledby={`${id}-moves`} className="grid gap-1.5 rounded-md border border-rule bg-sunken px-4 py-3">
            <h3 id={`${id}-moves`} className="text-sm font-medium [overflow-wrap:anywhere]">{t('merge.moves', { name: keptSide?.name ?? '' })}</h3>
            <MoveList pieces={movePieces(data)} />
            {watch ? <p className="text-meta">{t(`same.watch.${watch}`, { into: keptSide?.name ?? '', from: goneSides.map((s) => s.name).join(', ') })}</p> : null}
          </section>
        </>
      )}

      {refusal ? <Notice tone="danger" role="alert" title={t('merge.refused')} className="mb-0">{refusal.message}</Notice> : null}
      {error ? <p role="alert" className="text-meta text-danger [overflow-wrap:anywhere]">{error}</p> : null}
      <DialogFooter>
        {onBack ? <Button variant="ghost" className="mr-auto" disabled={merge.isPending} onClick={onBack}>{t('merge.back')}</Button> : null}
        <DialogClose asChild><Button disabled={merge.isPending}>{t('common:cancel')}</Button></DialogClose>
        <Button variant="primary" disabled={!fresh || !!refusal || ids.length < 2} busy={merge.isPending} busyLabel={t('merge.merging')} onClick={confirm}>{t('merge.confirm', { count: ids.length })}</Button>
      </DialogFooter>
    </>
  )
}

/** One device the person may keep: its name, state, addresses, badge and what it holds, so the rows tell apart at a glance. */
function KeepOption({ id, side: s, checked, suggested }: { id: string; side: MergeSide; checked: boolean; suggested: boolean }) {
  const { t } = useTranslation('inventory')
  const first = s.addresses[0]
  const facts = [
    s.findings ? t('merge.sideFindings', { count: s.findings }) : '',
    s.software ? t('merge.sideSoftware', { count: s.software }) : '',
    s.open_ports ? t('merge.sidePorts', { count: s.open_ports }) : '',
  ].filter(Boolean)
  return (
    <div className={cn('flex items-start gap-3 rounded-md border px-3 py-2.5', checked ? 'border-accent bg-accent-soft' : 'border-rule')}>
      <RadioItem id={id} value={s.id} className="mt-1" />
      <label htmlFor={id} className="grid min-w-0 flex-1 cursor-pointer gap-1">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-medium [overflow-wrap:anywhere]">{s.name}</span>
          {suggested ? <Chip tone="accent">{t('merge.suggested')}</Chip> : null}
          {s.ignored ? <Chip tone="off">{t('merge.ignored')}</Chip> : s.approved ? null : <Chip tone="warn">{t('merge.pending')}</Chip>}
          {s.agent ? <Chip tone="ok">{t('merge.agent')}</Chip> : null}
          {s.risk ? <StatusBadge code={s.risk.code} count={s.risk.count} /> : null}
        </span>
        <span className="text-meta tabular-nums text-muted [overflow-wrap:anywhere]">
          {first ? [addressText(first), first.ip && first.mac ? first.mac : ''].filter(Boolean).join(' / ') : t('merge.noAddress')}
          {s.addresses.length > 1 ? ` ${t('merge.addressMore', { count: s.addresses.length - 1 })}` : ''}
        </span>
        <span className="flex flex-wrap gap-x-3 text-meta text-muted">
          {facts.map((f) => <span key={f}>{f}</span>)}
          <time dateTime={s.last_seen} title={fmtDateTime(s.last_seen)}>{t('merge.seen', { when: fmtRelative(s.last_seen) })}</time>
        </span>
      </label>
    </div>
  )
}

/** A field the devices state differently: a choice of their values where the merge takes one (name, type, OS), else the value the
 *  sources give the kept device, with the others for comparison. A type the box only guesses says so; the devices with no value of the
 *  field are named under it. */
function DifferRow({ id, f, value, disabled, nameOf: nameOfDevice, onPick }: {
  id: string; f: ShownField; value: string; disabled: boolean; nameOf: (id: string) => string; onPick: (v: string) => void
}) {
  const { t } = useTranslation('inventory')
  const shown = (o: { value: string; guess?: boolean }) => {
    const v = f.field === 'kind' ? kindLabel(o.value) : o.value
    return o.guess ? t('merge.guessed', { value: v }) : v
  }
  // whose value it is, unless the value is the device's name itself
  const whose = (o: { devices: string[] }) => (f.field === 'name' || !o.devices.length ? '' : t('merge.onDevices', { list: o.devices.map(nameOfDevice).join(', ') }))
  const none = f.missing.length ? <p className="text-caption text-muted [overflow-wrap:anywhere]">{t('merge.noneOn', { list: f.missing.map(nameOfDevice).join(', ') })}</p> : null
  return (
    <div className="contents">
      <dt id={`${id}-label`} className="text-meta text-muted sm:pt-0.5">{t(`merge.field.${f.field}`)}</dt>
      <dd className="min-w-0">
        {f.choosable ? (
          <>
            <RadioGroup value={value} aria-labelledby={`${id}-label`} onValueChange={onPick} disabled={disabled} className="gap-1.5">
              {f.options.map((o, i) => (
                <div key={o.value} className="flex items-start gap-2.5">
                  <RadioItem id={`${id}-${i}`} value={o.value} className="mt-0.5" />
                  <label htmlFor={`${id}-${i}`} className="grid min-w-0 cursor-pointer text-sm">
                    <span className="[overflow-wrap:anywhere]">{shown(o)}</span>
                    {whose(o) ? <span className="text-caption text-muted [overflow-wrap:anywhere]">{whose(o)}</span> : null}
                  </label>
                </div>
              ))}
            </RadioGroup>
            {none}
          </>
        ) : (
          <div className="grid gap-0.5 text-sm">
            <span className="[overflow-wrap:anywhere]"><span className="font-medium">{t('merge.followsSources', { value: shown({ value: f.kept }) })}</span> <span className="text-caption text-muted">{t('merge.followsSourcesHint')}</span></span>
            <ul className="text-caption text-muted">
              {f.options.filter((o) => o.value !== f.kept).map((o) => <li key={o.value} className="[overflow-wrap:anywhere]">{`${shown(o)} ${whose(o)}`}</li>)}
            </ul>
            {none}
          </div>
        )}
      </dd>
    </div>
  )
}

/** "2 exploited CVEs, 3 findings, 14 software lines (9 new), 4 open ports, address 192.0.2.7": what the kept device gains. */
function MoveList({ pieces }: { pieces: MovePiece[] }) {
  const { t } = useTranslation('inventory')
  if (!pieces.length) return <p className="text-meta text-muted">{t('merge.move.nothing')}</p>
  const text = (p: MovePiece) => {
    switch (p.key) {
      case 'software': return p.fresh > 0 && p.fresh < p.count ? t('merge.move.softwareNew', { count: p.count, fresh: p.fresh }) : t('merge.move.software', { count: p.count })
      case 'addresses': return p.more ? t('merge.move.addressesMore', { list: p.list.join(', '), count: p.more }) : t('merge.move.addresses', { count: p.count, list: p.list.join(', ') })
      default: return t(`merge.move.${p.key}`, { count: p.count })
    }
  }
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-sm" data-testid="merge-moves">
      {pieces.map((p) => <li key={p.key} className={cn('[overflow-wrap:anywhere]', p.key === 'exploited' && 'font-medium text-danger')}>{text(p)}</li>)}
    </ul>
  )
}

