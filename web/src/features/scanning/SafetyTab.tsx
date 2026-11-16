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
import { useSaveSafety } from './api'
import type { Safety, SafetyInput } from './types'

const DAYS = [1, 2, 3, 4, 5, 6, 7]
const PPS = [10, 50, 100, 300, 1000]
const RPS = [1, 2, 5, 10, 20]
const lines = (v: string) => v.split('\n').map((l) => l.trim()).filter(Boolean)
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const withValue = (list: number[], v: number) => (list.includes(v) ? list : [...list, v].sort((a, b) => a - b))
type Kind = SafetyInput['fragile']['kinds'][number]

/**
 * #850, D-627: the one shared safety block (PUT /scanning/safety; inventory stores it). What it covers is said as it is on the box:
 * network discovery, version scans, SNMP and the vulnerability checks on the LAN obey it; scans of public targets follow their own
 * testing terms and are not covered by it in this version (review r1 H4). The ranges and the commitment are edited here too (§0).
 */
function Form({ s, devices, onSaved, onChanged }: { s: Safety; devices: number; onSaved: (r: Safety) => void; /** 409 safety_changed: the block stored now, to build the form again on it (#860). */ onChanged: (current: Safety | null) => void }) {
  const { t } = useTranslation('scanning')
  const admin = useCan('admin')
  const save = useSaveSafety()
  const [ranges, setRanges] = useState(s.scope.lan_ranges.join('\n'))
  const [confirmed, setConfirmed] = useState(!!s.scope.confirmed_at)
  const [days, setDays] = useState<number[]>(s.window.days)
  const [from, setFrom] = useState(s.window.from)
  const [to, setTo] = useState(s.window.to)
  const [pps, setPps] = useState(s.speed.packets_per_s)
  const [rps, setRps] = useState(s.speed.requests_per_s)
  const [excl, setExcl] = useState(s.exclusions.join('\n'))
  const [kinds, setKinds] = useState<Kind[]>(s.fragile.kinds)
  const [regular, setRegular] = useState<Kind[]>(s.fragile.regular_scan_kinds)
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
        toast.error(t('safety.changedElsewhere'))
        onChanged((err.details.safety as Safety | undefined) ?? null)
        return
      }
      setError(errMsg(err))
    } })
  }
  return (
    <form onSubmit={submit} className="grid max-w-3xl gap-8" noValidate>
      {dis ? <Notice tone="off" className="mb-0" title={t('safety.adminOnly')} /> : null}
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
          <Link to="/devices?show=fragile" className="w-fit text-meta text-accent underline-offset-4 hover:underline">{t('safety.fragileDevices', { count: devices })}</Link>
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
      <div><Button type="submit" variant="primary" disabled={dis || save.isPending}>{t('safety.save')}</Button></div>
    </form>
  )
}

export function SafetyTab({ s }: { s: Safety }) {
  // review r2 L-g: the form starts from the block once, and again only from the answer of its own save (the server may normalize
  // ranges); the page's regular reads (a new fragile device, a run) never wipe what is being typed
  const [base, setBase] = useState<{ v: number; s: Safety }>({ v: 0, s })
  const reset = (n: Safety) => setBase((b) => ({ v: b.v + 1, s: n }))
  // another change came first (#860): the form is built again on the stored block, from the 409's own copy or from the next read
  const [waiting, setWaiting] = useState(false)
  if (waiting && s.version !== base.s.version) { setWaiting(false); reset(s) }
  return <Form key={base.v} s={base.s} devices={s.fragile.devices} onSaved={reset} onChanged={(cur) => (cur ? reset(cur) : setWaiting(true))} />
}
