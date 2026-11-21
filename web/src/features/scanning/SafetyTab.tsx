import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ShieldCheck } from 'lucide-react'
import { Card } from '@/components/common/Card'
import { Notice, Section } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select, Textarea } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { BEHAVIOUR_KINDS, kindLabel } from '@/lib/deviceTypes'
import { fmtDate } from '@/lib/format'
import { useCan } from '@/lib/session'
import { ApiError } from '@/lib/api'
import { useSaveSafety, useScopeCost } from './api'
import type { Safety, SafetyInput } from './types'

const DAYS = [1, 2, 3, 4, 5, 6, 7]
const PPS = [10, 50, 100, 300, 1000]
const RPS = [1, 2, 5, 10, 20]
const lines = (v: string) => v.split('\n').map((l) => l.trim()).filter(Boolean)
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const withValue = (list: number[], v: number) => (list.includes(v) ? list : [...list, v].sort((a, b) => a - b))
type Kind = SafetyInput['fragile']['kinds'][number]

/** The form's values, by the part of the block each belongs to (#877 r1 M4: what the person typed survives a 409). */
type Vals = { ranges: string; confirmed: boolean; days: number[]; from: string; to: string; pps: number; rps: number; excl: string; kinds: Kind[]; regular: Kind[] }
const PARTS = ['scope', 'window', 'speed', 'exclusions', 'fragile'] as const
type Part = (typeof PARTS)[number]
const valsOf = (s: Safety): Vals => ({
  ranges: s.scope.lan_ranges.join('\n'), confirmed: !!s.scope.confirmed_at, days: s.window.days, from: s.window.from, to: s.window.to,
  pps: s.speed.packets_per_s, rps: s.speed.requests_per_s, excl: s.exclusions.join('\n'), kinds: s.fragile.kinds, regular: s.fragile.regular_scan_kinds,
})
const sorted = <T,>(l: T[]) => [...l].sort()
/** One part's values, compared as the server stores them (order of days and kinds, blank lines do not count). */
function partKey(v: Vals, p: Part): string {
  switch (p) {
    case 'scope': return JSON.stringify([lines(v.ranges), v.confirmed])
    case 'window': return JSON.stringify([sorted(v.days), v.from, v.to])
    case 'speed': return JSON.stringify([v.pps, v.rps])
    case 'exclusions': return JSON.stringify(lines(v.excl))
    case 'fragile': return JSON.stringify([sorted(v.kinds), sorted(v.regular.filter((k) => v.kinds.includes(k)))])
  }
}
const pick = (v: Vals, p: Part): Partial<Vals> => (p === 'scope' ? { ranges: v.ranges, confirmed: v.confirmed } : p === 'window' ? { days: v.days, from: v.from, to: v.to }
  : p === 'speed' ? { pps: v.pps, rps: v.rps } : p === 'exclusions' ? { excl: v.excl } : { kinds: v.kinds, regular: v.regular })
/** After a 409: the parts someone else changed, and the form's start values (the stored block, with the parts the person changed kept). */
type Merge = { theirs: Part[]; mine: Part[]; start: Vals }
function merge(read: Safety, typed: Vals, stored: Safety): Merge {
  const was = valsOf(read)
  const now = valsOf(stored)
  const mine = PARTS.filter((p) => partKey(typed, p) !== partKey(was, p))
  const theirs = PARTS.filter((p) => partKey(now, p) !== partKey(was, p))
  const start = { ...now }
  for (const p of mine) Object.assign(start, pick(typed, p))
  // The tick vouches for the ranges the person saw; ranges someone else changed are confirmed again by hand
  if (theirs.includes('scope') && mine.includes('scope') && lines(typed.ranges).join() === lines(was.ranges).join()) Object.assign(start, { ranges: now.ranges, confirmed: false })
  return { theirs, mine, start }
}

/**
 * The one shared safety block (PUT /scanning/safety; inventory stores it). What it covers is said as it is on the box:
 * network discovery, version scans, SNMP and the vulnerability checks on the LAN obey it; scans of public targets follow their own
 * testing terms and are not covered by it in this version (review r1 H4). The ranges and the commitment are edited here too (§0).
 */
function Form({ s, start, merged, devices, onSaved, onChanged }: {
  s: Safety; /** The values to start from: the block, or after a 409 the block with the person's own edits kept (#877 r1 M4). */ start: Vals
  merged: Merge | null; devices: number; onSaved: (r: Safety) => void
  /** 409 safety_changed: the block stored now (null: read it again) and what was typed, to build the form again on both (#860). */ onChanged: (current: Safety | null, typed: Vals) => void
}) {
  const { t } = useTranslation('scanning')
  const admin = useCan('admin')
  const save = useSaveSafety()
  const [ranges, setRanges] = useState(start.ranges)
  const [confirmed, setConfirmed] = useState(start.confirmed)
  const [days, setDays] = useState<number[]>(start.days)
  const [from, setFrom] = useState(start.from)
  const [to, setTo] = useState(start.to)
  const [pps, setPps] = useState(start.pps)
  const [rps, setRps] = useState(start.rps)
  const [excl, setExcl] = useState(start.excl)
  const [kinds, setKinds] = useState<Kind[]>(start.kinds)
  const [regular, setRegular] = useState<Kind[]>(start.regular)
  const [error, setError] = useState<string | null>(null)
  const dis = !admin
  const rangesChanged = lines(ranges).join() !== s.scope.lan_ranges.join()
  function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    save.mutate({
      scope: { lan_ranges: lines(ranges), confirmed }, window: { days, from, to }, speed: { packets_per_s: pps, requests_per_s: rps },
      exclusions: lines(excl), fragile: { kinds, regular_scan_kinds: regular.filter((k) => kinds.includes(k)) },
      version: s.version, // the block this form was built on: another one stored is refused, never overwritten (#860)
    }, { onSuccess: (r) => { onSaved(r); toast.success(r.adjusted.length ? t('safety.savedAdjusted', { list: r.adjusted.map((a) => `${a.from} → ${a.to}`).join(', ') }) : t('safety.saved')) }, onError: (err) => {
      if (err instanceof ApiError && err.code === 'safety_changed') {
        onChanged((err.details.safety as Safety | undefined) ?? null, { ranges, confirmed, days, from, to, pps, rps, excl, kinds, regular })
        return
      }
      setError(errMsg(err))
    } })
  }
  return (
    <form onSubmit={submit} className="grid max-w-3xl gap-8" noValidate>
      {dis ? <Notice tone="off" className="mb-0" title={t('safety.adminOnly')} /> : null}
      {merged ? <MergeNotice m={merged} now={s} /> : null}
      <p className="text-sm">{t('safety.appliesTo')}</p>

      <Section id="scope" title={t('safety.scopeTitle')} description={t('safety.scopeDescription')} info={t('safety.scopeInfo')} stories={['S-INV-1']}>
        <Card className="grid gap-4">
          <Field htmlFor="scope-ranges" label={t('scope.ranges')} hint={t('scope.rangesHint')}>
            <Textarea id="scope-ranges" rows={3} spellCheck={false} value={ranges} placeholder="192.168.10.0/24" disabled={dis} onChange={(e) => { setRanges(e.target.value); setConfirmed(false) }} />
          </Field>
          <div className="flex items-start gap-3">
            <Checkbox id="scope-confirm" className="mt-0.5" checked={confirmed} disabled={dis} onCheckedChange={(v) => setConfirmed(v === true)} aria-describedby="scope-status" />
            <Label htmlFor="scope-confirm" className="font-normal">{t('inventory:scope.confirm')}</Label>
          </div>
          <p id="scope-status" className={s.scope.confirmed_at && !rangesChanged ? 'text-meta text-muted' : 'text-meta text-warn'}>
            {s.scope.confirmed_at && !rangesChanged ? t('safety.confirmedBy', { date: fmtDate(s.scope.confirmed_at), by: s.scope.confirmed_by ?? '' }) : rangesChanged ? t('safety.confirmAgain') : t('safety.notConfirmed')}
          </p>
        </Card>
      </Section>

      <Section id="window" title={t('safety.windowTitle')} description={t('safety.windowDescription')} info={t('safety.windowInfo', { zone: s.window.time_zone })} stories={['S-SCAN-4']}>
        <div className="grid gap-4">
          <fieldset className="grid gap-2" disabled={dis}>
            <legend className="mb-1 text-sm font-medium">{t('safety.days')}</legend>
            <div className="flex flex-wrap gap-x-4 gap-y-2">
              {DAYS.map((d) => (
                <span key={d} className="inline-flex items-center gap-2 text-sm">
                  <Checkbox id={`day-${d}`} checked={days.includes(d)} onCheckedChange={(v) => setDays((l) => (v === true ? [...l, d] : l.filter((x) => x !== d)))} />
                  <label htmlFor={`day-${d}`}>{t(`scan:days.${d}`)}</label>
                </span>
              ))}
            </div>
          </fieldset>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field htmlFor="win-from" label={t('safety.from')}><Input id="win-from" type="time" value={from} onChange={(e) => setFrom(e.target.value)} disabled={dis} /></Field>
            <Field htmlFor="win-to" label={t('safety.to')}><Input id="win-to" type="time" value={to} onChange={(e) => setTo(e.target.value)} disabled={dis} /></Field>
          </div>
        </div>
      </Section>

      <Section id="speed" title={t('safety.speedTitle')} description={t('safety.speedDescription')}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field htmlFor="speed-pps" label={t('safety.pps')} hint={t('safety.ppsHint')}>
            <Select id="speed-pps" value={pps} onChange={(e) => setPps(Number(e.target.value))} disabled={dis}>
              {withValue(PPS, pps).map((n) => <option key={n} value={n}>{t('safety.ppsOption', { count: n })}</option>)}
            </Select>
          </Field>
          <Field htmlFor="speed-rps" label={t('safety.rps')} hint={t('safety.rpsHint')}>
            <Select id="speed-rps" value={rps} onChange={(e) => setRps(Number(e.target.value))} disabled={dis}>
              {withValue(RPS, rps).map((n) => <option key={n} value={n}>{t('safety.rpsOption', { count: n })}</option>)}
            </Select>
          </Field>
        </div>
      </Section>

      <SweepCost ranges={lines(ranges)} excl={lines(excl)} days={days} from={from} to={to} pps={pps} />

      <Section id="exclusions" title={t('safety.exclTitle')} description={t('safety.exclDescription')}>
        <Field htmlFor="excl" label={t('safety.exclLabel')} hint={t('safety.exclHint')} info={t('safety.exclInfo')}>
          <Textarea id="excl" value={excl} onChange={(e) => setExcl(e.target.value)} disabled={dis} spellCheck={false} rows={4} />
        </Field>
      </Section>

      <Section id="fragile" title={t('safety.fragileTitle')} description={t('safety.fragileDescription')} info={t('safety.fragileInfo')}>
        <Card className="grid gap-3">
          <fieldset disabled={dis}>
            <legend className="sr-only">{t('safety.fragileTitle')}</legend>
            <div className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3">
              {BEHAVIOUR_KINDS.map((k) => (
                <span key={k} className="grid gap-1">
                  <span className="inline-flex items-center gap-2">
                    <Checkbox id={`fragile-${k}`} checked={kinds.includes(k)} onCheckedChange={(v) => setKinds((l) => (v === true ? [...l, k] : l.filter((x) => x !== k)))} />
                    <Label htmlFor={`fragile-${k}`} className="font-normal">{kindLabel(k)}</Label>
                  </span>
                  {kinds.includes(k) ? (
                    <span className="ml-6 inline-flex items-center gap-2">
                      <Switch id={`regular-${k}`} aria-label={t('safety.regularFor', { kind: kindLabel(k) })} checked={regular.includes(k)}
                        onCheckedChange={(v) => setRegular((l) => (v ? [...l, k] : l.filter((x) => x !== k)))} />
                      <span className="text-meta text-muted" aria-hidden>{t('safety.regular')}</span>
                    </span>
                  ) : null}
                </span>
              ))}
            </div>
          </fieldset>
          {devices > 0 ? <Link to="/devices?show=fragile" className="w-fit text-meta text-accent underline-offset-4 hover:underline">{t('safety.fragileDevices', { count: devices })}</Link> : null}
        </Card>
      </Section>

      <Section id="never" title={t('scan:safety.neverTitle')} description={t('scan:safety.neverDescription')}
        info={(['exploit', 'write', 'tags'] as const).map((k) => <p key={k}>{t(`scan:safety.never.${k}Info`)}</p>)}>
        <Card className="grid gap-2">
          <p className="flex items-center gap-2 text-sm font-medium"><ShieldCheck className="size-4 text-ok" aria-hidden />{t('scan:safety.neverHeadline')}</p>
          <ul className="grid list-disc gap-1 pl-9 text-sm">
            {(['exploit', 'dos', 'brute', 'write', 'tags'] as const).map((k) => <li key={k}>{t(`scan:safety.never.${k}`)}</li>)}
          </ul>
          <p className="text-meta text-muted">{t('scan:safety.neverLocked')}</p>
        </Card>
      </Section>

      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      <div><Button type="submit" variant="primary" disabled={dis} busy={save.isPending} busyLabel={t('common:busy.saving')}>{t('safety.save')}</Button></div>
    </form>
  )
}

/** What one pass of discovery over the scope as typed costs, from the box (POST /scanning/safety/estimate): the addresses and the time
 *  of one pass, and whether it fits one window. A pass that needs several windows is one run over several nights; the choices to make
 *  it fit one are named. A scope that does not fit a week is refused on save, and the card says so before. */
function SweepCost({ ranges, excl, days, from, to, pps }: { ranges: string[]; excl: string[]; days: number[]; from: string; to: string; pps: number }) {
  const { t } = useTranslation('scanning')
  const q = useScopeCost({ lan_ranges: ranges.slice(0, 16), exclusions: excl.slice(0, 400), window: { days, from, to }, packets_per_s: pps }, ranges.length > 0)
  const c = q.data
  if (!c || c.addresses === 0) return null
  const pass = fmtDuration(c.pass_seconds)
  const win = fmtDuration(c.window_seconds)
  const line = t('safety.cost.line', { addresses: c.addresses.toLocaleString('en-US'), pass, pps })
  return (
    <Notice tone={!c.fits_week ? 'danger' : c.fits_window ? 'off' : 'warn'} className="mb-0" title={line} role="status">
      {!c.fits_week ? t('safety.cost.tooLarge', { windows: c.windows, week: c.week_windows, window: win })
        : c.fits_window ? t('safety.cost.fits', { window: win })
          : t('safety.cost.nights', { windows: c.windows, window: win })}
    </Notice>
  )
}

/** "6 h 12 min", "40 min", "less than a minute". */
function fmtDuration(seconds: number): string {
  const m = Math.round(seconds / 60)
  if (m < 1) return 'less than a minute'
  if (m < 60) return `${m} min`
  return m % 60 === 0 ? `${m / 60} h` : `${Math.floor(m / 60)} h ${m % 60} min`
}

/** #877 r1 M4: after a 409, what someone else changed (its value stored now) and that the person's own edits are kept, to save again. */
function MergeNotice({ m, now }: { m: Merge; now: Safety }) {
  const { t } = useTranslation('scanning')
  const days = [...now.window.days].sort().map((d) => t(`scan:days.${d}`)).join(', ')
  const value: Record<Part, string> = {
    scope: now.scope.lan_ranges.join(', ') || t('safety.merge.none'),
    window: `${days}, ${now.window.from}–${now.window.to}`,
    speed: `${t('safety.ppsOption', { count: now.speed.packets_per_s })}, ${t('safety.rpsOption', { count: now.speed.requests_per_s })}`,
    exclusions: now.exclusions.join(', ') || t('safety.merge.none'),
    fragile: now.fragile.kinds.map(kindLabel).join(', ') || t('safety.merge.none'),
  }
  const title: Record<Part, string> = { scope: t('safety.scopeTitle'), window: t('safety.windowTitle'), speed: t('safety.speedTitle'), exclusions: t('safety.exclTitle'), fragile: t('safety.fragileTitle') }
  return (
    <Notice tone="warn" role="alert" className="mb-0" title={t('safety.changedElsewhere')}>
      <ul className="grid gap-1 text-sm">
        {m.theirs.map((p) => <li key={p}>{t(m.mine.includes(p) ? 'safety.merge.bothChanged' : 'safety.merge.taken', { part: title[p], value: value[p] })}</li>)}
      </ul>
      <p className="mt-1 text-sm">{t('safety.merge.saveAgain')}</p>
    </Notice>
  )
}

export function SafetyTab({ s }: { s: Safety }) {
  // review r2 L-g: the form starts from the block once, and again only from the answer of its own save (the server may normalize
  // ranges); the page's regular reads (a new fragile device, a run) never wipe what is being typed
  const [base, setBase] = useState<{ v: number; s: Safety; start: Vals; merged: Merge | null }>({ v: 0, s, start: valsOf(s), merged: null })
  const reset = (n: Safety) => setBase((b) => ({ v: b.v + 1, s: n, start: valsOf(n), merged: null }))
  // another change came first (#860): the form is built again on the stored block, from the 409's own copy or from the next read,
  // keeping what the person typed in the parts they changed and saying what the other change was (#877 r1 M4)
  const [typed, setTyped] = useState<Vals | null>(null)
  const rebase = (n: Safety, mine: Vals) => setBase((b) => { const m = merge(b.s, mine, n); return { v: b.v + 1, s: n, start: m.start, merged: m } })
  if (typed && s.version !== base.s.version) { setTyped(null); rebase(s, typed) }
  return <Form key={base.v} s={base.s} start={base.start} merged={base.merged} devices={s.fragile.devices} onSaved={reset} onChanged={(cur, mine) => (cur ? rebase(cur, mine) : setTyped(mine))} />
}
