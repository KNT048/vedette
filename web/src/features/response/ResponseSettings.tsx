import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader, Panel } from '@/components/common/PageHeader'
import { ErrorState, Loading } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Plus, Trash2 } from 'lucide-react'
import { useMe } from '@/lib/session'
import { fmtDateTime } from '@/lib/format'
import { errText, useResetBreaker, useSaveSettings, useSetExecution, useSettings, useTriggers } from './api'
import { RISK_PHRASE } from './contract'
import { CatalogEditor } from './CatalogEditor'
import { EmergencyStop } from './parts'
import { NeverTouch } from './NeverTouch'
import type { SettingsView, Window } from './types'

function EnableDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const { t } = useTranslation('response')
  const me = useMe()
  const set = useSetExecution()
  const [phrase, setPhrase] = useState('')
  const [error, setError] = useState<string | undefined>()
  const twofa = me.data?.twofa === true
  const ok = twofa && phrase === RISK_PHRASE
  return (
    <Dialog open={open} onOpenChange={(v) => { onOpenChange(v); if (!v) { setPhrase(''); setError(undefined) } }}>
      <DialogContent title={t('enable.title')} description={t('enable.description')}>
        <p className="rounded-md border border-danger/50 bg-danger-soft px-3 py-2 text-sm font-medium">{t('risk.statement')}</p>
        <div className="grid gap-1 text-sm">
          <p className="flex flex-wrap items-center gap-2">{t('enable.twofa')} <Chip tone={twofa ? 'ok' : 'danger'}>{twofa ? t('enable.twofaOn') : t('enable.twofaOff')}</Chip></p>
          {!twofa ? <p className="text-[13px]"><Link to="/account" className="text-accent underline underline-offset-4" onClick={() => onOpenChange(false)}>{t('enable.toAccount')}</Link></p> : null}
        </div>
        <Field htmlFor="risk-phrase" label={t('enable.phraseLabel', { phrase: RISK_PHRASE })} error={error}>
          <Input id="risk-phrase" value={phrase} autoComplete="off" spellCheck={false} onChange={(e) => { setPhrase(e.target.value); setError(undefined) }} aria-invalid={!!error} aria-describedby={error ? 'risk-phrase-error' : undefined} />
        </Field>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
          <Button variant="danger" disabled={!ok || set.isPending}
            onClick={() => set.mutate({ enabled: true, phrase }, { onSuccess: () => { toast.success(t('enable.done')); onOpenChange(false); setPhrase('') }, onError: (e) => setError(errText(e)) })}>{t('enable.confirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Form({ s }: { s: SettingsView }) {
  const { t } = useTranslation('response')
  const save = useSaveSettings()
  const triggers = useTriggers()
  const [perHour, setPerHour] = useState(String(s.max_per_hour))
  const [expiry, setExpiry] = useState(String(s.expiry_min))
  const [chans, setChans] = useState(s.approval_channels)
  const [breaker, setBreaker] = useState(String(s.breaker_max_per_hour))
  const [multi, setMulti] = useState(String(s.multi_target_max))
  const [windows, setWindows] = useState<Window[]>(s.maintenance)
  const [aiTrig, setAiTrig] = useState(s.ai.triggers)
  const [bh, setBh] = useState(String(s.ai.budget_hour))
  const [bd, setBd] = useState(String(s.ai.budget_day))
  const [error, setError] = useState<string | undefined>()
  const toggle = (list: string[], v: string, on: boolean) => (on ? [...new Set([...list, v])] : list.filter((x) => x !== v))
  const ready = s.channels.filter((c) => c.ready)
  const local = (iso: string) => { const d = new Date(iso); return new Date(d.getTime() - d.getTimezoneOffset() * 60e3).toISOString().slice(0, 16) }
  const setWin = (i: number, p: Partial<Window>) => setWindows(windows.map((w, j) => (j === i ? { ...w, ...p } : w)))
  return (
    <form className="grid gap-6" onSubmit={(e) => { e.preventDefault(); setError(undefined)
      save.mutate({ max_per_hour: Number(perHour), expiry_min: Number(expiry), approval_channels: chans.filter((c) => ready.some((r) => r.type === c)), breaker_max_per_hour: Number(breaker), multi_target_max: Number(multi), maintenance: windows,
        ai: { triggers: aiTrig as SettingsView['ai']['triggers'], budget_hour: Number(bh), budget_day: Number(bd) } },
        { onSuccess: () => toast.success(t('common:saved')), onError: (er) => setError(errText(er)) }) }}>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field htmlFor="resp-hour" label={t('form.perHour')} hint={t('form.perHourHint')}><Input id="resp-hour" type="number" min={1} max={20} value={perHour} onChange={(e) => setPerHour(e.target.value)} /></Field>
        <Field htmlFor="resp-expiry" label={t('form.expiry')} hint={t('form.expiryHint')}><Input id="resp-expiry" type="number" min={15} max={30} value={expiry} onChange={(e) => setExpiry(e.target.value)} /></Field>
      </div>
      <fieldset className="grid gap-2">
        <legend className="text-sm font-medium">{t('form.channels')}</legend>
        <p className="text-[13px] text-muted">{t('form.channelsHint')}</p>
        {ready.length ? ready.map((c) => (
          <div key={c.type} className="flex items-center gap-2.5">
            <Checkbox id={`ch-${c.type}`} checked={chans.includes(c.type)} onCheckedChange={(v) => setChans(toggle(chans, c.type, v === true))} />
            <label htmlFor={`ch-${c.type}`} className="text-sm">{c.label} <span className="text-muted">({t('form.approverCount', { count: c.approvers })}{c.link ? `, ${t('form.byLink')}` : ''})</span></label>
          </div>
        )) : <p className="text-sm text-muted">{t('form.noChannels')} <Link className="text-accent underline underline-offset-4" to="/settings/channels">{t('form.toChannels')}</Link></p>}
        <p className="text-[13px] text-muted">{t('form.approversRule')}</p>
      </fieldset>

      <fieldset className="grid gap-3 rounded-md border border-rule p-4">
        <legend className="px-1 text-sm font-medium">{t('safety.title')}</legend>
        <p className="text-[13px] text-muted">{t('safety.description')}</p>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field htmlFor="resp-breaker" label={t('safety.breaker')} hint={t('safety.breakerHint')}><Input id="resp-breaker" type="number" min={1} max={200} value={breaker} onChange={(e) => setBreaker(e.target.value)} /></Field>
          <Field htmlFor="resp-multi" label={t('safety.multi')} hint={t('safety.multiHint')}><Input id="resp-multi" type="number" min={1} max={1000} value={multi} onChange={(e) => setMulti(e.target.value)} /></Field>
        </div>
        <div className="grid gap-2">
          <p className="text-sm font-medium">{t('safety.windows')}</p>
          <p className="text-[13px] text-muted">{t('safety.windowsHint')}</p>
          {windows.map((w, i) => (
            <div key={w.id} className="grid gap-2 sm:grid-cols-[1.2fr_1fr_1fr_auto]">
              <Input aria-label={t('safety.windowName')} value={w.name} maxLength={80} onChange={(e) => setWin(i, { name: e.target.value })} />
              <Input aria-label={t('safety.windowStart')} type="datetime-local" value={local(w.start)} onChange={(e) => e.target.value && setWin(i, { start: new Date(e.target.value).toISOString() })} />
              <Input aria-label={t('safety.windowEnd')} type="datetime-local" value={local(w.end)} onChange={(e) => e.target.value && setWin(i, { end: new Date(e.target.value).toISOString() })} />
              <Button size="icon" variant="ghost" aria-label={t('safety.windowRemove')} onClick={() => setWindows(windows.filter((_, j) => j !== i))}><Trash2 className="size-4" aria-hidden /></Button>
            </div>
          ))}
          <div><Button size="sm" onClick={() => { const a = new Date(Date.now() + 864e5); a.setMinutes(0, 0, 0); setWindows([...windows, { id: `mw-${Date.now().toString(36)}`, name: 'Maintenance', start: a.toISOString(), end: new Date(a.getTime() + 2 * 3600e3).toISOString() }]) }}><Plus className="size-4" aria-hidden />{t('safety.windowAdd')}</Button></div>
        </div>
      </fieldset>

      <fieldset className="grid gap-3 rounded-md border border-rule p-4">
        <legend className="px-1 text-sm font-medium">{t('aiGates.title')}</legend>
        <p className="text-[13px] text-muted">{t('aiGates.description')}</p>
        <div className="grid gap-2 sm:grid-cols-2">
          {(triggers.data?.items ?? []).map((tr) => (
            <div key={tr.id} className="flex items-start gap-2.5">
              <Checkbox id={`aitr-${tr.id}`} checked={aiTrig.includes(tr.id)} onCheckedChange={(v) => setAiTrig(toggle(aiTrig, tr.id, v === true) as typeof aiTrig)} />
              <label htmlFor={`aitr-${tr.id}`} className="text-sm">{tr.name}</label>
            </div>
          ))}
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field htmlFor="ai-bh" label={t('aiGates.perHour')}><Input id="ai-bh" type="number" min={1} max={20} value={bh} onChange={(e) => setBh(e.target.value)} /></Field>
          <Field htmlFor="ai-bd" label={t('aiGates.perDay')}><Input id="ai-bd" type="number" min={1} max={100} value={bd} onChange={(e) => setBd(e.target.value)} /></Field>
        </div>
        <ul className="ml-5 list-disc text-[13px] text-muted">{[1, 2, 3, 4, 5, 6].map((n) => <li key={n}>{t(`aiGates.fixed.${n}`)}</li>)}</ul>
      </fieldset>
      {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{error}</p> : null}
      <div><Button type="submit" variant="primary" disabled={save.isPending}>{t('common:save')}</Button></div>
    </form>
  )
}

export default function ResponseSettings() {
  const { t } = useTranslation('response')
  const q = useSettings()
  const set = useSetExecution()
  const reset = useResetBreaker()
  const [open, setOpen] = useState(false)
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const s = q.data
  return (
    <>
      <PageHeader title={t('settings.title')} meta={t('settings.description')} stories={['S-RESP-2', 'S-RESP-4']} />
      <section>
        <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
          <p className="rounded-md border border-danger/50 bg-danger-soft px-4 py-3 text-sm font-medium">{t('risk.statement')}</p>
          <Panel className="flex flex-wrap items-center justify-between gap-3 p-4">
            <div className="flex items-center gap-3">
              <Switch id="resp-exec" checked={s.execution} disabled={set.isPending}
                onCheckedChange={(v) => (v ? setOpen(true) : set.mutate({ enabled: false }, { onSuccess: () => toast.success(t('enable.off')), onError: (e) => toast.error(errText(e)) }))} />
              <label htmlFor="resp-exec" className="grid text-sm"><span className="font-medium">{t('settings.switch')}</span>
                <span className="text-[13px] text-muted">{s.execution ? t('settings.on', { who: s.accepted_by ?? '', time: fmtDateTime(s.accepted_at) }) : t('settings.off')}</span></label>
            </div>
            {s.execution ? <EmergencyStop /> : null}
          </Panel>
          {s.breaker_tripped_at ? (
            <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-danger/50 bg-danger-soft px-4 py-3 text-sm">
              <span><span className="font-medium">{t('safety.tripped')}</span> {t('safety.trippedBody', { max: s.breaker_max_per_hour, time: fmtDateTime(s.breaker_tripped_at), who: s.breaker_notified.join(', ') })}</span>
              <Button disabled={reset.isPending} onClick={() => reset.mutate(undefined, { onSuccess: () => toast.success(t('safety.resumed')), onError: (e) => toast.error(errText(e)) })}>{t('safety.resume')}</Button>
            </div>
          ) : null}
          <Form key={JSON.stringify([s.max_per_hour, s.expiry_min, s.approval_channels, s.channels.map((c) => [c.type, c.ready]), s.breaker_max_per_hour, s.multi_target_max, s.maintenance, s.ai])} s={s} />
          <NeverTouch />
          <CatalogEditor />
        </div>
      </section>
      <EnableDialog open={open} onOpenChange={setOpen} />
    </>
  )
}
