import { useRef, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ScanSearch } from 'lucide-react'
import { PageHeader, Section, KeyValue, Notice } from '@/components/common/PageHeader'
import { Breadcrumbs } from '@/components/common/Breadcrumbs'
import { Card } from '@/components/common/Card'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { SourceBadge } from '@/components/common/SourceBadge'
import { InfoTip } from '@/components/common/InfoTip'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Slot } from '@/components/common/Slot'
import { Button } from '@/components/ui/button'
import { fmtDate, fmtDateTime, fmtPercent } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useModuleEnabled } from '@/lib/modules'
import { FindingStatus, legacySeverity } from './legacyStatus'
import { overdue } from './accept'
import { useFinding, useReopen, useView } from './api'
import { useFindingAgentGone } from './agentNow'
import { basisLabel, deviceName, hasIp, isOpen, unverified } from './basis'
import { errMsg } from './errors'
import { canConfirm, canUndo, ConfirmButton, ConfirmDialog, ConfirmWays, UndoButton } from './Confirm'
import { AskAi, PackView } from './Recommendation'
import { FixGuide, FixLineOf } from './WhatToDo'
import { useCve } from '@/features/feeds/api'
import { GeneralChecks } from './Hardening'
import { FindingStatusLines, ReopenedLine, SeverityBadge } from '@/components/common/status'
import type { FindingDetail } from './types'
import { IUpdatedFinding } from './Updated'
import { NotAdded } from './NotAdded'
import { HandleDialog } from './HandleDialog'
import { CveBriefCard } from './CveBrief'

function Evidence({ f, confirm }: { f: FindingDetail; confirm?: ReactNode }) {
  // #850 r2 N4: with the vulnerability checks on, the device page re-runs them; off, it only identifies the device again (said so)
  const scanOn = useModuleEnabled('scan') === true
  const { t } = useTranslation('findings')
  const admin = useCan('admin') // only an admin can confirm: the sentence offers it to no one else
  const ev = f.evidence
  return (
    <Section id="evidence" title={t('evidence.title')} description={t('evidence.description')} stories={['S-SCAN-3']}>
      <Card className="grid gap-4">
        {f.suspected_why ? <p className="max-w-3xl text-sm text-muted" data-testid="suspected-why">{admin && canConfirm(f) ? `${f.suspected_why} ${t('evidence.confirmYourself')}` : f.suspected_why}</p> : null}
        {canConfirm(f) && f.asset ? (
          <ConfirmWays assetId={f.asset.id} deviceStated={f.known_version?.source === 'snmp' || f.known_version?.source === 'agent'} checkable={!!f.kev?.has_template && hasIp(f.asset)}>
            {confirm}
          </ConfirmWays>
        ) : null}
        {ev ? (
          <>
            <p className="max-w-3xl text-sm">{ev.summary}</p>
            <KeyValue items={[
              { label: t('evidence.basis'), value: t(basisLabel(f)) },
              { label: t('evidence.confidence'), value: fmtPercent(f.confidence, 0) },
              { label: t('evidence.template'), value: ev.template ?? <span className="text-muted">{f.kev?.has_template ? t('evidence.noTemplateRun') : t('evidence.noTemplate')}</span> },
              { label: t('evidence.source'), value: <SourceBadge source={f.basis === 'scan' ? 'scan' : f.kev?.source === 'vulncheck-kev' ? 'vulncheck-kev' : f.kev ? 'kev' : 'catalogue'} confidence={f.confidence} at={ev.checked_at} /> },
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
            <Button asChild className="w-fit"><Link to={`/devices/${encodeURIComponent(f.asset.id)}`}><ScanSearch />{t(scanOn ? 'evidence.rescan' : 'evidence.rescanIdentify')}</Link></Button>
          ) : f.asset ? (
            <div className="flex flex-wrap items-center gap-x-1 text-meta text-muted">
              <span className="inline-flex items-center gap-1">{t('evidence.noIpScan')}<InfoTip topic={t('evidence.recheck')}>{t('evidence.noIpScanInfo')}</InfoTip></span>
              <Link to={`/devices/${f.asset.id}`} className="text-accent underline underline-offset-4">{t('evidence.openDevice')}</Link>
            </div>
          ) : null}
        </div>
      </Card>
    </Section>
  )
}

/**
 * S-MIT-3 without a confirmed pack: Vedette holds no signs specific to the CVE, and says so. The reports of the attacks it does hold
 * (an exploitation source's write-up, a technical description the record lists) are where such signs are published, so they are linked.
 */
function AttackReports({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const feedsOn = useModuleEnabled('feeds') !== false
  const b = useCve(feedsOn ? f.cve : '').data
  if (!b) return null
  const urls = [...new Set([
    ...b.signals.filter((s) => s.kind === 'exploited' && s.qualifies && s.url && !/cisa\.gov|nvd\.nist\.gov/i.test(s.url)).map((s) => s.url!),
    ...b.references.filter((r) => r.group === 'technical-description' || r.group === 'mitigation').map((r) => r.url),
  ])].slice(0, 5)
  return (
    <div className="grid gap-1.5" data-testid="attack-reports">
      <p className="max-w-3xl text-sm">{t(urls.length ? 'compromise.reports' : 'compromise.noReports', { cve: f.cve })}</p>
      {urls.length ? (
        <ul className="grid gap-0.5 text-sm">
          {urls.map((u) => <li key={u}><a href={u} target="_blank" rel="noopener noreferrer" className="break-all text-accent underline-offset-4 hover:underline">{u}</a></li>)}
        </ul>
      ) : null}
    </div>
  )
}

function Compromise({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const c = f.compromise
  return (
    <Section id="compromise" title={t('compromise.title')} description={t('compromise.description')} stories={['S-MIT-3']}>
      {c ? (
        <Card className="grid gap-4">
          <p className="max-w-3xl text-sm">{c.summary}</p>
          <ul className="grid gap-4">
            {c.indicators.map((i) => (
              <li key={i.title} className="grid gap-2">
                <p className="text-sm font-medium">{i.title}</p>
                <p className="max-w-3xl text-meta text-muted">{i.detail}</p>
                {i.commands?.map((cmd) => <CodeBlock key={cmd.label} code={cmd.code} label={cmd.label} wrapOnPhone />)}
              </li>
            ))}
          </ul>
          <div className="grid gap-1.5 border-t border-rule pt-3">
            <h3 className="text-sm font-semibold">{t('compromise.ifFound')}</h3>
            <ol className="grid list-decimal gap-1 pl-5 text-sm">{c.if_found.map((s) => <li key={s}>{s}</li>)}</ol>
          </div>
        </Card>
      ) : f.hardening?.checks ? (
        <Card className="grid gap-4"><AttackReports f={f} /><GeneralChecks finding={f} /></Card>
      ) : (
        <EmptyState title={t('compromise.none')} info={t('compromise.noneInfo')} />
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
          <Card className="grid gap-1 text-sm">
            <Link to={`/devices/${f.asset.id}`} title={deviceName(f.asset, t('removedDevice'))} className="w-fit font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{deviceName(f.asset, t('removedDevice'))}</Link>
            <span className="text-muted">{hasIp(f.asset) ? f.asset.ip : t('noIp')}</span>
            <span>{f.asset.display}</span>
          </Card>
        ) : <p className="text-sm text-muted">{t('aside.noDevice')}</p>}
        {f.kev ? <p className="text-meta text-muted">{f.kev.name}</p> : null}
      </section>
      <section aria-labelledby="hist-title" className="grid gap-2">
        <h2 id="hist-title" className="text-base font-semibold">{t('history.title')}</h2>
        <ol className="grid gap-3 border-l border-rule pl-4">
          {[...f.history].reverse().map((h, i) => (
            <li key={`${h.ts}-${i}`} className="grid text-sm">
              <span className="font-medium">{label(h.action)}</span>
              <span className="text-caption text-muted">{fmtDateTime(h.ts)}, {h.user === 'system' ? t('history.system') : h.user}</span>
              {h.note ? <span className="text-meta">{h.note}</span> : null}
            </li>
          ))}
        </ol>
      </section>
    </div>
  )
}

/** S-MIT-1: a closed finding opens with why it was closed (GitHub's dismissed-alert banner, Snyk's ignore reason): who or what closed it, when, the reason, and the one action that undoes it. */
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

function Detail({ f, crumbs }: { f: FindingDetail; crumbs: { label: string; to: string }[] }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const reopen = useReopen()
  const view = useView(f.id)
  const [open, setOpen] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const opener = useRef<HTMLButtonElement>(null)
  const confirmOpener = useRef<HTMLButtonElement>(null)
  const name = deviceName(f.asset, t('removedDevice'))
  // the agent's build is a detection; once no agent reports the device it is the last list one sent
  const agentHeadline = (f.status === 'suspected' || f.status === 'confirmed') && f.basis === 'version' && !!f.evidence?.agent
  const agentGone = useFindingAgentGone(f)
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const reopenButton = (
    <Button disabled={!can} busy={reopen.isPending} busyLabel={t('status.reopening')} title={needRole} onClick={() => reopen.mutate({ id: f.id, note: '' }, { onSuccess: () => toast.success(t('status.reopened')), onError: (e) => toast.error(errMsg(e)) })}>{t('status.reopen')}</Button>
  )
  const open_ = isOpen(f.status)
  const body = (
    <>
      <Evidence f={f} confirm={<ConfirmButton f={f} buttonRef={confirmOpener} onClick={() => setConfirming(true)} />} />
      <Section id="mitigation" title={t('rec.title')} description={t('rec.description')} info={t('rec.descriptionInfo')} stories={['S-MIT-1']}>
        {f.pack ? <RequireModule module="mitigation"><PackView finding={f} fix={<FixLineOf f={f} />} /></RequireModule> : <FixGuide f={f} />}
      </Section>
      <Compromise f={f} />
    </>
  )
  return (
    <>
      <PageHeader
        breadcrumbs={crumbs}
        title={<span className="[overflow-wrap:anywhere]">{t(`headline.${agentHeadline ? (agentGone ? 'agentLast' : 'agent') : f.status === 'confirmed' ? `confirmed_${f.urgency}` : f.status === 'suspected' && f.urgency === 1 ? 'suspected_1' : f.status === 'suspected' && !canConfirm(f) ? 'suspected_update' : f.status}`, { device: name, cve: f.cve, date: fmtDate(f.accepted_until) })}</span>}
        stories={['S-MIT-1', 'S-MIT-3', 'S-SCAN-3', 'S-AI-2']}
        meta={
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1.5">
            {/* the status lines every list says for this finding (its View); the older row's badge only until the view has loaded */}
            {view.data ? <FindingStatusLines value={{ status: view.data.status, urgency: view.data.urgency, verification: view.data.verification }} /> : <FindingStatus f={f} />}
            {/* open again after a handling: why, and who when a person's version change did it */}
            {view.data?.reopened ? <ReopenedLine reopened={view.data.reopened} version={view.data.software?.version} /> : null}
            <SeverityBadge severity={legacySeverity(f)} detail />
            {unverified(f) ? <span className="inline-flex items-center gap-1 text-muted">{t('risk.unverifiedLine')}<InfoTip topic={t('risk.unverifiedLine')}>{t('risk.unverifiedLineInfo')}</InfoTip></span> : null}
            {f.kev?.ransomware ? <Chip tone="danger">{t('meta.ransomware')}</Chip> : null}
            <span className="inline-flex items-center gap-1">{t('meta.seen', { first: fmtDate(f.first_seen), last: fmtDateTime(f.last_seen) })}<InfoTip topic={t('col.lastSeen')}>{t('matchedInfo')}</InfoTip></span>
            {f.known_version?.seen_at ? <span>{t(`meta.version.${f.known_version.source === 'agent' && agentGone ? 'agentLast' : f.known_version.source}`, { software: f.known_version.software, version: f.known_version.version, date: fmtDateTime(f.known_version.seen_at) })}</span> : null}
            {/* the reasons line says "fix by"; a deadline that passed is said once more, as an alarm */}
            {f.kev?.due_date && isOpen(f.status) && (overdue(f.kev.due_date) || !view.data) ? <span>{t(overdue(f.kev.due_date) ? 'meta.duePassed' : 'meta.due', { date: fmtDate(f.kev.due_date) })}</span> : null}
            {/* an accepted risk: the notice under the title says until when, by whom and why (once) */}
          </span>
        }
        actions={
          <>
            <SampleDataNote />
            <IUpdatedFinding f={f} />
            {canConfirm(f) && !f.asset ? <ConfirmButton f={f} buttonRef={confirmOpener} onClick={() => setConfirming(true)} /> : null}
            {canUndo(f) ? <UndoButton f={f} /> : null}
            {open_ ? <Button ref={opener} variant="primary" disabled={!can} title={needRole} onClick={() => setOpen(true)}>{t('status.mark')}</Button> : null}
          </>
        }
      />
      {f.asset && !f.asset.approved && !f.asset.ignored ? (
        <Notice tone="warn" title={t('notAdded.mark')} actions={<NotAdded asset={f.asset} />}>{t('notAdded.body')}</Notice>
      ) : null}
      {open_ ? null : <ClosedNotice f={f} reopen={reopenButton} />}
      <div className="grid gap-8 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div>
          <CveBriefCard f={f} />
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
      {open ? (
        <HandleDialog onClose={() => { setOpen(false); opener.current?.focus() }} rows={[{ id: f.id, cve: f.cve }]}
          device={{ id: f.asset?.id ?? f.asset_id, name, ip: f.asset && hasIp(f.asset) ? f.asset.ip : null, kind: f.asset?.kind ?? 'unknown', added: f.asset?.approved ?? true, ignored: f.asset?.ignored ?? false }} />
      ) : null}
      {confirming ? <ConfirmDialog f={f} onClose={() => setConfirming(false)} opener={confirmOpener} /> : null}
    </>
  )
}

export default function FindingPage() {
  const { t } = useTranslation('findings')
  const { id = '' } = useParams()
  const q = useFinding(id)
  // docs/UI.md §3: the parent above the title, also while the finding loads or is missing, so the way back is always there.
  const crumbs = [{ label: t('common:shell.findings'), to: '/findings' }]
  return (
    <RequireModule module="findings" page>
      {q.data ? null : <Breadcrumbs items={crumbs} />}
      <QueryState query={q}>{(f) => <Detail f={f} crumbs={crumbs} />}</QueryState>
    </RequireModule>
  )
}
