import { useRef, useState, type ReactNode, type RefObject } from 'react'
import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ArrowLeft, ScanSearch } from 'lucide-react'
import { PageHeader, Section, KeyValue, Panel, Notice } from '@/components/common/PageHeader'
import { QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { SourceBadge } from '@/components/common/SourceBadge'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Slot } from '@/components/common/Slot'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { fmtDate, fmtDateTime, fmtPercent } from '@/lib/format'
import { useCan } from '@/lib/session'
import { AcceptUntil, FindingStatusChip } from './AcceptRisk'
import { untilOk } from './accept'
import { useFinding, useSetStatus } from './api'
import { basisKey, deviceName, hasIp, isOpen, unverified } from './basis'
import { errMsg } from './errors'
import { AskAi, NoPack, PackView } from './Recommendation'
import { RiskChip } from './Risk'
import type { FindingDetail, StatusAction } from './types'
import { IUpdatedFinding } from './Updated'

const RESOLVE: StatusAction[] = ['patched', 'mitigated', 'false_positive', 'not_relevant', 'accept_risk']

function StatusDialog({ f, open, onOpenChange, opener }: { f: FindingDetail; open: boolean; onOpenChange: (v: boolean) => void; opener: RefObject<HTMLButtonElement | null> }) {
  const { t } = useTranslation('findings')
  const set = useSetStatus(f.id)
  const [action, setAction] = useState<StatusAction>('patched')
  const [note, setNote] = useState('')
  const [until, setUntil] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [untilError, setUntilError] = useState<string | undefined>()
  // Every opening starts clean: Cancel or Esc drops the draft, and a saved status is not offered again the next time.
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) { setWasOpen(open); if (open) { setAction('patched'); setNote(''); setUntil(''); setError(undefined); setUntilError(undefined) } }
  const accept = action === 'accept_risk'
  const needNote = action === 'false_positive' || action === 'not_relevant' || accept
  function submit() {
    const badUntil = accept && !untilOk(until)
    setUntilError(badUntil ? t('accept.untilRequired') : undefined)
    if (needNote && note.trim().length < 3) { setError(t(accept ? 'accept.noteRequired' : 'status.noteRequired')); return }
    if (badUntil) return
    setError(undefined)
    set.mutate({ action, note: note.trim(), ...(accept ? { until } : {}) }, {
      onSuccess: () => { toast.success(t('status.done')); onOpenChange(false); setNote('') },
      onError: (e) => setError(errMsg(e)),
    })
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('status.title')} description={t('status.description', { cve: f.cve })} onCloseAutoFocus={(e) => { e.preventDefault(); opener.current?.focus() }}>
        <RadioGroup value={action} onValueChange={(v) => { setAction(v as StatusAction); setError(undefined); setUntilError(undefined) }} aria-label={t('status.title')}>
          {RESOLVE.map((a) => (
            <div key={a} className="flex items-start gap-2.5">
              <RadioItem id={`st-${a}`} value={a} className="mt-1" />
              <label htmlFor={`st-${a}`} className="grid text-sm"><span className="font-medium">{t(`status.${a}`)}</span><span className="text-[13px] text-muted">{t(`status.${a}Hint`)}</span></label>
            </div>
          ))}
        </RadioGroup>
        {accept ? <AcceptUntil id="st-until" value={until} onChange={(v) => { setUntil(v); setUntilError(undefined) }} error={untilError} /> : null}
        <Field htmlFor="st-note" label={needNote ? t('status.noteLabelRequired') : t('status.noteLabel')} error={error}>
          <Textarea id="st-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} aria-invalid={!!error} aria-describedby={error ? 'st-note-error' : undefined} />
        </Field>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
          <Button variant="primary" disabled={set.isPending} onClick={submit}>{t('status.submit')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Evidence({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const ev = f.evidence
  return (
    <Section id="evidence" title={t('evidence.title')} description={t('evidence.description')} stories={['S-SCAN-3']}>
      <Panel className="grid gap-4 p-4">
        {ev ? (
          <>
            <p className="max-w-3xl text-sm">{ev.summary}</p>
            <KeyValue items={[
              { label: t('evidence.basis'), value: t(basisKey(f.basis)) },
              { label: t('evidence.confidence'), value: fmtPercent(f.confidence, 0) },
              { label: t('evidence.template'), value: ev.template ?? <span className="text-muted">{f.kev?.has_template ? t('evidence.noTemplateRun') : t('evidence.noTemplate')}</span> },
              { label: t('evidence.source'), value: <SourceBadge source={f.basis === 'scan' ? 'scan' : 'kev'} confidence={f.confidence} at={ev.checked_at} /> },
            ]} />
            {ev.request ? <CodeBlock code={ev.request} label={t('evidence.request')} /> : null}
            {ev.response ? <CodeBlock code={ev.response} label={t('evidence.response')} /> : null}
          </>
        ) : <p className="text-sm text-muted">{t('evidence.none')}</p>}
        <div className="grid gap-2 border-t border-rule pt-3">
          <h3 className="text-sm font-semibold">{t('evidence.recheck')}</h3>
          <ol className="grid list-decimal gap-1 pl-5 text-sm">{f.recheck.steps.map((s) => <li key={s}>{s}</li>)}</ol>
          {f.recheck.code ? <CodeBlock code={f.recheck.code} label={t('evidence.recheckCode')} wrapOnPhone /> : null}
          {f.asset && hasIp(f.asset) ? (
            <Button asChild className="w-fit"><Link to={`/scans?target=${f.asset.id}`}><ScanSearch />{t('evidence.rescan')}</Link></Button>
          ) : f.asset ? (
            <p className="text-[13px] text-muted">{t('evidence.noIpScan')} <Link to={`/devices/${f.asset.id}`} className="text-accent underline underline-offset-4">{t('evidence.openDevice')}</Link></p>
          ) : null}
        </div>
      </Panel>
    </Section>
  )
}

function Compromise({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const c = f.compromise
  return (
    <Section id="compromise" title={t('compromise.title')} description={t('compromise.description')} stories={['S-MIT-3']}>
      {c ? (
        <Panel className="grid gap-4 p-4">
          <p className="max-w-3xl text-sm">{c.summary}</p>
          <ul className="grid gap-4">
            {c.indicators.map((i) => (
              <li key={i.title} className="grid gap-2">
                <p className="text-sm font-medium">{i.title}</p>
                <p className="max-w-3xl text-[13px] text-muted">{i.detail}</p>
                {i.commands?.map((cmd) => <CodeBlock key={cmd.label} code={cmd.code} label={cmd.label} wrapOnPhone />)}
              </li>
            ))}
          </ul>
          <div className="grid gap-1.5 border-t border-rule pt-3">
            <h3 className="text-sm font-semibold">{t('compromise.ifFound')}</h3>
            <ol className="grid list-decimal gap-1 pl-5 text-sm">{c.if_found.map((s) => <li key={s}>{s}</li>)}</ol>
          </div>
        </Panel>
      ) : (
        <p className="max-w-3xl rounded-md border border-dashed border-rule bg-surface px-4 py-3 text-sm text-muted">{t('compromise.none')}</p>
      )}
    </Section>
  )
}

function Aside({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const label = (a: string) => (a.startsWith('applied:') ? t('history.applied', { item: t(`history.item.${a.slice(8)}`, { defaultValue: a.slice(8) }) }) : t(`history.${a}`, { defaultValue: a }))
  return (
    <div className="grid content-start gap-6">
      <section aria-labelledby="dev-title" className="grid gap-2">
        <h2 id="dev-title" className="text-base font-semibold">{t('aside.device')}</h2>
        {f.asset ? (
          <Panel className="grid gap-1 p-4 text-sm">
            <Link to={`/devices/${f.asset.id}`} title={deviceName(f.asset, t('removedDevice'))} className="w-fit font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{deviceName(f.asset, t('removedDevice'))}</Link>
            <span className="text-muted">{hasIp(f.asset) ? f.asset.ip : t('noIp')}</span>
            <span>{f.asset.display}</span>
          </Panel>
        ) : <p className="text-sm text-muted">{t('aside.noDevice')}</p>}
        {f.kev ? <p className="text-[13px] text-muted">{f.kev.name}</p> : null}
        <Link to={`/cve/${f.cve}`} className="w-fit text-[13px] text-accent underline-offset-4 hover:underline">{t('aside.cvePage', { cve: f.cve })}</Link>
      </section>
      <section aria-labelledby="hist-title" className="grid gap-2">
        <h2 id="hist-title" className="text-base font-semibold">{t('history.title')}</h2>
        <ol className="grid gap-3 border-l border-rule pl-4">
          {[...f.history].reverse().map((h, i) => (
            <li key={`${h.ts}-${i}`} className="grid text-sm">
              <span className="font-medium">{label(h.action)}</span>
              <span className="text-[12px] text-muted">{fmtDateTime(h.ts)}, {h.user === 'system' ? t('history.system') : h.user}</span>
              {h.note ? <span className="text-[13px]">{h.note}</span> : null}
            </li>
          ))}
        </ol>
      </section>
    </div>
  )
}

/** S-MIT-1 (W12-1): a closed finding opens with why it was closed (GitHub's dismissed-alert banner, Snyk's ignore reason): who or what closed it, when, the reason, and the one action that undoes it. */
function ClosedNotice({ f, reopen }: { f: FindingDetail; reopen: ReactNode }) {
  const { t } = useTranslation('findings')
  const system = f.resolved_by === 'system'
  const who = system ? t('closed.vedette') : f.resolved_by
  const when = f.resolved_at ? fmtDate(f.resolved_at) : ''
  const key = f.status === 'risk_accepted' ? 'risk_accepted' : system && f.status === 'not_relevant' ? 'systemNotRelevant' : f.status
  return (
    <Notice tone={f.status === 'risk_accepted' ? 'accent' : 'off'} role="status" data-testid="closed-notice" actions={reopen}
      title={t(`closed.${key}`, { date: fmtDate(f.accepted_until), who: who ? t('closed.by', { who }) : '', when: when ? t('closed.on', { when }) : '' })}>
      {f.resolution_note ? <p className="[overflow-wrap:anywhere]">{f.resolution_note}</p> : null}
    </Notice>
  )
}

function Detail({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const set = useSetStatus(f.id)
  const [open, setOpen] = useState(false)
  const opener = useRef<HTMLButtonElement>(null)
  const name = deviceName(f.asset, t('removedDevice'))
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const reopenButton = (
    <Button disabled={!can || set.isPending} title={needRole} onClick={() => set.mutate({ action: 'reopen', note: '' }, { onSuccess: () => toast.success(t('status.reopened')), onError: (e) => toast.error(errMsg(e)) })}>{t('status.reopen')}</Button>
  )
  const open_ = isOpen(f.status)
  const body = (
    <>
      <Evidence f={f} />
      <Section id="mitigation" title={t('rec.title')} description={t('rec.description')} stories={['S-MIT-1']}>
        <RequireModule module="mitigation">{f.pack ? <PackView finding={f} /> : <NoPack finding={f} />}</RequireModule>
      </Section>
      <Compromise f={f} />
    </>
  )
  return (
    <>
      <PageHeader
        title={<span className="[overflow-wrap:anywhere]">{t(`headline.${f.status}`, { device: name, cve: f.cve, date: fmtDate(f.accepted_until) })}</span>}
        stories={['S-MIT-1', 'S-MIT-3', 'S-SCAN-3', 'S-AI-2']}
        meta={
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1.5">
            <FindingStatusChip f={f} /><RiskChip f={f} />
            {unverified(f) ? <span className="text-muted">{t('risk.unverifiedLine')}</span> : null}
            {f.kev?.ransomware ? <Chip tone="danger">{t('meta.ransomware')}</Chip> : null}
            <span>{t('meta.seen', { first: fmtDate(f.first_seen), last: fmtDateTime(f.last_seen) })}</span>
            {f.kev?.due_date && isOpen(f.status) ? <span>{t('meta.due', { date: fmtDate(f.kev.due_date) })}</span> : null}
            {f.status === 'risk_accepted' ? (
              <span className="basis-full [overflow-wrap:anywhere]">{t('accept.line', { date: fmtDate(f.accepted_until), who: f.resolved_by ?? '' })}{f.resolution_note ? ` ${f.resolution_note}` : ''}</span>
            ) : null}
          </span>
        }
        actions={
          <>
            <SampleDataNote />
            <IUpdatedFinding f={f} />
            {open_ ? <Button ref={opener} variant="primary" disabled={!can} title={needRole} onClick={() => setOpen(true)}>{t('status.mark')}</Button> : null}
          </>
        }
      />
      {open_ ? null : <ClosedNotice f={f} reopen={reopenButton} />}
      <div className="grid gap-8 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div>
          {open_ ? body : (
            <details className="group" data-testid="before-closed">
              <summary className="mb-3 w-fit cursor-pointer text-base font-semibold">{t('closed.before')}</summary>
              {body}
            </details>
          )}
          <Slot name="finding.panels" props={{ findingId: f.id }} />
          <Section id="explain" title={t('explain.title')} description={t('explain.description')} stories={['S-AI-2']}>
            <AskAi finding={f} skill="explain" result={f.ai.explain} label={t('explain.button')} />
          </Section>
        </div>
        <Aside f={f} />
      </div>
      <StatusDialog f={f} open={open} onOpenChange={setOpen} opener={opener} />
    </>
  )
}

export default function FindingPage() {
  const { t } = useTranslation('findings')
  const { id = '' } = useParams()
  const q = useFinding(id)
  return (
    <RequireModule module="findings">
      <Link to="/findings" className="mb-3 inline-flex items-center gap-1 text-[13px] text-muted hover:text-ink"><ArrowLeft className="size-3.5" />{t('back')}</Link>
      <QueryState query={q}>{(f) => <Detail f={f} />}</QueryState>
    </RequireModule>
  )
}
