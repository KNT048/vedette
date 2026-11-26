// Needs your input: one queue of what only a person can settle, each item with its one action in place (forms open as dialogs).
// Devices nobody added yet that have findings (Add device, Ignore); then one card per added device, collapsed, that opens to what it needs:
// that Vedette cannot check it (Add its firmware, SNMP, an agent), urgent findings not confirmed yet (Run the safe check first when one
// exists, then Confirm vulnerability or Not affected…), and its questions grouped by software line, one entry per line ("Thunderbird
// 115.9.0: 196 CVEs waiting") with its one action (the version, the platform, the package release), Not affected and Accept the risk; the CVEs of a line are
// behind a click; last, one card for the devices nobody added yet that have no open finding (Review: the Devices list's To review). An
// item leaves the queue the moment it is answered or stops being true (GET /findings/input).
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ChevronDown, X } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ListSearch } from '@/components/common/Pager'
import { useListParams } from '@/components/common/listParams'
import { EmptyState, QueryState } from '@/components/common/States'
import { SeverityBadge, StatusBadge, VerificationLine } from '@/components/common/status'
import { Button, buttonVariants } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { fmtDate } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useDeviceAction } from '@/features/inventory/api'
import { AddDeviceDialog } from '@/features/inventory/AddDeviceDialog'
import { useStartRun } from '@/features/scan/api'
import { useAnswer, useAnswered, useIgnoreQuestions, useInputList, useUnanswer, useVerify } from './api'
import { AcceptRiskDialog } from './AcceptRiskDialog'
import { AskDialog, type Ask } from './AskDialog'
import { PAGE_DEFAULT, PAGE_MAX } from './contract'
import { errMsg } from './errors'
import { HandleDialog } from './HandleDialog'
import { NotAdded } from './NotAdded'
import { asAsset, DeviceLine } from './parts'
import { linkLabels } from './links'
import type { AnsweredQuestion, InputGroupItem, InputItem, InputQuestionItem, InputUncheckedItem, InputUnconfirmedItem } from './types'

/** What PATCH …/software/{sid} accepts as a version (the inventory's versionRE). */
const VERSION_RE = /^[A-Za-z0-9_.\-+() ]{1,40}$/

type Item<K extends InputItem['kind']> = Extract<InputItem, { kind: K }>

function useRoles() {
  const { t } = useTranslation('findings')
  const operator = useCan('operator')
  const admin = useCan('admin')
  return {
    operator, admin,
    needOperator: operator ? undefined : t('common:needRole', { role: t('common:role.operator') }),
    needAdmin: admin ? undefined : t('common:needRole', { role: t('common:role.admin') }),
  }
}

function NotAddedItem({ i, link }: { i: Item<'device_not_added'>; link: boolean }) {
  const { t } = useTranslation('findings')
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="grid gap-0.5">
        <DeviceLine device={i.device} status={i.status} link={link} />
        <span className="text-meta text-muted">{t('queue.notAdded', { count: i.findings })}</span>
      </div>
      <NotAdded asset={asAsset(i.device)} findings={i.findings} />
    </div>
  )
}

/** Every device nobody added yet that has no open finding, as one card: how many, and Review opens the Devices list's To review, where
 *  each is added or ignored (one by one or several at once). */
function NotAddedGroupItem({ i }: { i: Item<'devices_not_added'> }) {
  const { t } = useTranslation('findings')
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <p className="text-sm">{t('queue.notAddedGroup', { count: i.count })}</p>
      <Link to="/devices?tab=review" className={cn(buttonVariants({ size: 'sm' }))}>{t('queue.review')}</Link>
    </div>
  )
}

/** A device a person added that Vedette cannot check (no software, firmware or OS it can match): its empty findings say nothing. The
 *  ways to say what runs there, the first in place: its firmware version (the software dialog), SNMP read access, an agent. */
function UncheckedItem({ i, link }: { i: InputUncheckedItem; link: boolean }) {
  const { t } = useTranslation('findings')
  const r = useRoles()
  const [adding, setAdding] = useState(false)
  const words = { device: i.device.name }
  return (
    <div className="grid gap-2">
      <p className="text-sm">{t('queue.unchecked', words)}</p>
      <DeviceLine device={i.device} badge={false} link={link} />
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Button size="sm" variant="primary" disabled={!r.operator} title={r.needOperator} aria-label={t('queue.uncheckedAddOf', words)} onClick={() => setAdding(true)}>
          {t('queue.uncheckedAdd')}
        </Button>
        <Link to={`/devices/${encodeURIComponent(i.device.id)}?tab=overview#sources`} className="text-meta text-accent underline-offset-4 hover:underline">{t('queue.uncheckedSnmp')}</Link>
        <Link to="/devices/setup?tab=agents" className="text-meta text-accent underline-offset-4 hover:underline">{t('queue.uncheckedAgent')}</Link>
      </div>
      <AddDeviceDialog open={adding} onOpenChange={setAdding} deviceId={i.device.id} />
    </div>
  )
}

function UnconfirmedItem({ i, link }: { i: InputUnconfirmedItem; link: boolean }) {
  const { t } = useTranslation('findings')
  const r = useRoles()
  const run = useStartRun()
  const verify = useVerify()
  const [open, setOpen] = useState<'confirm' | 'not' | null>(null)
  const on = { cve: i.cve, device: i.device.name }
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <Link to={`/findings/${encodeURIComponent(i.id)}`} className="font-medium text-accent underline-offset-4 hover:underline">{i.cve}</Link>
        <SeverityBadge severity={i.severity} compact />
        <StatusBadge code={i.status} />
      </div>
      <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
        <DeviceLine device={i.device} badge={false} link={link} />
        {i.software ? <span className="text-meta text-muted">{i.software.version ? `${i.software.name} ${i.software.version}` : i.software.name}</span> : null}
      </span>
      <VerificationLine verified="no" basis={i.basis} />
      <div className="flex flex-wrap items-center gap-2">
        {i.safe_check ? (
          <Button size="sm" variant="primary" disabled={!r.operator} title={r.needOperator} busy={run.isPending} busyLabel={t('common:busy.starting')}
            aria-label={t('queue.safeCheckOf', on)}
            onClick={() => run.mutate([i.device.id], { onSuccess: () => toast.success(t('queue.safeCheckStarted', { device: i.device.name })), onError: (e) => toast.error(errMsg(e)) })}>
            {t('queue.safeCheck')}
          </Button>
        ) : null}
        <Button size="sm" variant={i.safe_check ? 'secondary' : 'primary'} disabled={!r.admin} title={r.needAdmin} aria-label={t('queue.confirmOf', on)} onClick={() => setOpen('confirm')}>{t('confirm.button')}</Button>
        <Button size="sm" disabled={!r.operator} title={r.needOperator} aria-label={t('queue.notAffectedOf', on)} onClick={() => setOpen('not')}>{t('queue.notAffected')}</Button>
      </div>
      {open === 'confirm' ? (
        <AskDialog title={t('queue.confirmTitle', on)} description={t('queue.confirmBody')} submit={t('confirm.button')} busyLabel={t('common:busy.confirming')}
          done={t('queue.confirmed', on)} onClose={() => setOpen(null)}
          fields={[{ name: 'note', label: t('queue.confirmNote'), min: 3, max: 500, long: true }]}
          onSend={(v) => verify.mutateAsync({ id: i.id, note: v.note! })} />
      ) : null}
      {open === 'not' ? (
        <HandleDialog device={i.device} rows={[{ id: i.id, cve: i.cve, severity: i.severity, status: i.status }]} resolutions={['not_relevant', 'false_positive']}
          title={t('queue.notAffectedTitle', on)} onClose={() => setOpen(null)} />
      ) : null}
    </div>
  )
}

type Asking = { kind: 'version' } | { kind: 'choice'; label: string; ask: ('os' | 'pkg_version')[] } | { kind: 'answer'; answer: 'affected' | 'not_affected' }

/** The dialog of a question's answer: what it asks and where it sends it. */
function QuestionDialog({ i, asking, onClose }: { i: InputQuestionItem; asking: Asking; onClose: () => void }) {
  const { t } = useTranslation('findings')
  const act = useDeviceAction(i.device.id)
  const answer = useAnswer()
  const unanswer = useUnanswer()
  const sw = i.software
  const words = { software: sw?.name ?? t('queue.theSoftware'), version: sw?.version ?? '', device: i.device.name, count: i.cves, cve: i.cve ?? '' }
  const lineWords = { ...words, line: i.line ?? sw?.version ?? '' }
  if (asking.kind === 'version') {
    return (
      <AskDialog title={t('queue.versionTitle', words)} submit={t('queue.saveVersion')} done={t('queue.versionSaved', words)} onClose={onClose}
        fields={[{ name: 'version', label: t('queue.versionLabel', words), hint: t('queue.versionHint'), max: 40, check: (v) => (VERSION_RE.test(v) ? undefined : t('queue.badVersion')) }]}
        onSend={(v) => act.correct.mutateAsync({ sid: sw!.id, version: v.version! })} />
    )
  }
  if (asking.kind === 'choice') {
    const fields: Ask[] = [
      ...(asking.ask.includes('os') ? [{ name: 'os', label: t('queue.osLabel'), placeholder: t('queue.osPlaceholder'), max: 200 }] : []),
      ...(asking.ask.includes('pkg_version') && sw ? [{ name: 'pkg', label: t('queue.pkgLabel', words), hint: i.command ? t('queue.commandHint', { command: i.command }) : undefined, max: 100 }] : []),
    ]
    return (
      <AskDialog title={asking.label} submit={t('queue.saveAnswer')} done={t('queue.answerSaved', words)} fields={fields} onClose={onClose}
        onSend={async (v) => {
          if (v.os) await act.patch.mutateAsync({ os: v.os })
          if (v.pkg) await act.correct.mutateAsync({ sid: sw!.id, pkg_version: v.pkg })
        }} />
    )
  }
  const a = asking.answer
  // "not affected" leaves the queue and no finding records it: the toast can take it back (the answer is also listed below the queue)
  const undo = a === 'not_affected' ? { label: t('queue.undo'), done: t('queue.askedAgain', words), run: () => unanswer.mutateAsync({ id: i.id }) } : undefined
  const line = i.question === 'older_line' // one answer for every CVE of the line
  return (
    <AskDialog title={line ? t('queue.lineTitle', lineWords) : t(`queue.${a}Title`, words)} submit={t(`queue.${a}`)}
      done={line ? t('queue.lineSaved', words) : t(a === 'not_affected' ? 'queue.notAffectedSaved' : 'queue.answerSaved', words)} undo={undo} onClose={onClose}
      fields={[{ name: 'note', label: line ? t('queue.lineNote', lineWords) : t(a === 'affected' ? 'queue.confirmNote' : 'queue.notAffectedNote'), min: a === 'not_affected' ? 3 : undefined, required: a === 'not_affected', max: 500, long: true }]}
      onSend={(v) => answer.mutateAsync({ id: i.id, answer: a, note: v.note ?? '' })} />
  )
}

/** One question of a software line. `action` is the line's one action (the version, the platform, the package release), `row` is one
 *  CVE of the line behind the click: its link and, when only a person's word decides it, Affected / Not affected. */
function QuestionItem({ i, mode }: { i: InputQuestionItem; mode: 'action' | 'row' }) {
  const { t } = useTranslation('findings')
  const r = useRoles()
  const act = useDeviceAction(i.device.id)
  const [asking, setAsking] = useState<Asking | null>(null)
  const [accepting, setAccepting] = useState(false)
  const sw = i.software
  const words = { software: sw?.name ?? t('queue.theSoftware'), version: sw?.version ?? '', device: i.device.name, count: i.cves, cve: i.cve ?? '',
    line: i.line ?? sw?.version ?? '', fixes: i.fixes.join(', ') }
  // a build attribute NVD pins (edition, architecture, platform) is asked for by name: retyping the version would change nothing
  const attr = i.question === 'not_comparable' ? i.attribute : null
  const typed = i.question === 'version_needed' || i.question === 'not_comparable' && !attr
  // what the question says: the CVE lists versions, just none that decides this one; the vendor names fixes only on newer lines
  const text = attr ? `queue.q.attribute_${attr}` : i.question === 'no_range_data' && i.versions_listed ? 'queue.q.no_range_data_listed'
    : i.question === 'older_line' && !i.fixes.length ? 'queue.q.older_line_none' : `queue.q.${i.question}`
  const perCve = i.question === 'no_range_data' || i.question === 'older_line' || !!attr
  if (mode === 'row') {
    return (
      <div className="grid gap-1.5">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          {i.cve ? <Link to={`/cve/${encodeURIComponent(i.cve)}`} className="text-accent underline-offset-4 hover:underline">{i.cve}</Link> : null}
          {/* the link says what it is: NVD's entry is not the vendor's advisory */}
          {i.url ? <a href={i.url} target="_blank" rel="noopener noreferrer" className="text-meta text-accent underline-offset-4 hover:underline">{linkLabels(t, [i.url])[0]}</a> : null}
          {i.cve_list.map((c) => <Link key={c} to={`/cve/${encodeURIComponent(c)}`} className="text-accent underline-offset-4 hover:underline">{c}</Link>)}
        </span>
        {perCve ? <p className="text-meta text-muted">{t(text, words)}</p> : null}
        {perCve ? (
          <div className="flex flex-wrap items-center gap-2">
            {(i.question === 'no_range_data' || attr) && i.cve ? (
              <Button size="sm" disabled={!r.admin} title={r.needAdmin} onClick={() => setAsking({ kind: 'answer', answer: 'affected' })}>{t('queue.affected')}</Button>
            ) : null}
            <Button size="sm" disabled={!r.operator} title={r.needOperator} onClick={() => setAsking({ kind: 'answer', answer: 'not_affected' })}>{t('queue.not_affected')}</Button>
            <Button size="sm" disabled={!r.admin} title={r.needAdmin} aria-label={t('queue.acceptRowOf', { cve: i.cve ?? sw?.name ?? '', device: i.device.name })}
              onClick={() => setAccepting(true)}>{t('queue.accept')}</Button>
          </div>
        ) : null}
        {asking ? <QuestionDialog i={i} asking={asking} onClose={() => setAsking(null)} /> : null}
        {accepting ? <AcceptRiskDialog device={i.device} line={sw} question={i.id} what={i.cve ?? sw?.name ?? t('queue.theSoftware')} count={Math.max(i.cves, 1)} onClose={() => setAccepting(false)} /> : null}
      </div>
    )
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      {typed && sw ? <Button size="sm" variant="primary" disabled={!r.operator} title={r.needOperator} onClick={() => setAsking({ kind: 'version' })}>{t('queue.addVersion')}</Button> : null}
      {i.choices.map((c) => c.os ? (
        <Button key={c.label} size="sm" disabled={!r.operator || act.patch.isPending} title={r.needOperator} busy={act.patch.isPending && act.patch.variables?.os === c.os} busyLabel={t('common:busy.saving')}
          onClick={() => act.patch.mutate({ os: c.os! }, { onSuccess: () => toast.success(t('queue.answerSaved', words)), onError: (e) => toast.error(errMsg(e)) })}>{c.label}</Button>
      ) : (
        <Button key={c.label} size="sm" disabled={!r.operator} title={r.needOperator} onClick={() => setAsking({ kind: 'choice', label: c.label, ask: c.ask ?? [] })}>{c.label}</Button>
      ))}
      {i.command && !i.choices.some((c) => c.ask?.includes('pkg_version')) ? <span className="text-meta text-muted">{t('queue.command')} <code className="font-mono">{i.command}</code></span> : null}
      {asking ? <QuestionDialog i={i} asking={asking} onClose={() => setAsking(null)} /> : null}
    </div>
  )
}

/** Not affected for all (bypass): answers "not affected" to every open question of a software line, or of the whole device, in one step. */
function IgnoreDialog({ device, line, count, onClose }: { device: { id: string; name: string }; line: { id: string; name: string } | null; count: number; onClose: () => void }) {
  const { t } = useTranslation('findings')
  const ignore = useIgnoreQuestions()
  const words = { device: device.name, software: line?.name ?? '', count }
  return (
    <AskDialog title={line ? t('queue.ignoreLineTitle', words) : t('queue.ignoreDeviceTitle', words)} description={t('queue.ignoreBody', words)} submit={t('queue.ignoreSubmit')}
      done={line ? t('queue.ignoredLine', words) : t('queue.ignoredDevice', words)} onClose={onClose}
      fields={[{ name: 'note', label: t('queue.notAffectedNote'), min: 3, required: true, max: 500, long: true }]}
      onSend={(v) => ignore.mutateAsync({ device: device.id, software: line?.id, note: v.note! })} />
  )
}

const lineName = (g: InputGroupItem, fallback: string) => (g.software ? (g.software.version ? `${g.software.name} ${g.software.version}` : g.software.name) : fallback)

/** One software line of a device: "Thunderbird 115.9.0: 196 CVEs waiting", its one action, an Ignore for the line, the CVEs behind a click. */
function SoftwareEntry({ g, device }: { g: InputGroupItem; device: Item<'device_needs'>['device'] }) {
  const { t } = useTranslation('findings')
  const r = useRoles()
  const [open, setOpen] = useState(false)
  const [ignoring, setIgnoring] = useState(false)
  const [accepting, setAccepting] = useState(false)
  const primary = g.questions[0]!
  const name = lineName(g, t('queue.theSoftware'))
  const attr = primary.question === 'not_comparable' ? primary.attribute : null
  const typed = primary.question === 'version_needed' || primary.question === 'not_comparable' && !attr
  const sentence = attr ? t(`queue.group.attribute_${attr}`, { software: name, count: g.cves })
    : typed ? t(`queue.group.${primary.question}`, { software: name, count: g.cves })
    : primary.question === 'platform' || primary.question === 'package_release' ? t(`queue.group.${primary.question}`, { software: name, count: g.cves })
    : t('queue.group.waiting', { software: name, count: g.cves })
  const panel = `needs-${g.id.replace(/[^\w-]/g, '_')}`
  return (
    <li className="grid gap-2 py-3" data-testid="needs-line">
      <p className="text-sm font-medium">{sentence}</p>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <QuestionItem i={primary} mode="action" />
        {!typed && primary.software ? (
          <Link to={`/devices/${encodeURIComponent(device.id)}?tab=software`} className="text-meta text-accent underline underline-offset-4">{t('queue.openSoftware')}</Link>
        ) : null}
        {g.software ? (
          <Button size="sm" disabled={!r.operator} title={r.needOperator} aria-label={t('queue.ignoreLineOf', { software: name, device: device.name })} onClick={() => setIgnoring(true)}>{t('queue.ignore')}</Button>
        ) : null}
        {g.software ? (
          <Button size="sm" disabled={!r.admin} title={r.needAdmin} aria-label={t('queue.acceptLineOf', { software: name, device: device.name })} onClick={() => setAccepting(true)}>{t('queue.accept')}</Button>
        ) : null}
      </div>
      <details className="text-meta" onToggle={(e) => setOpen(e.currentTarget.open)}>
        <summary className="w-fit cursor-pointer text-accent">{t('queue.showCves', { count: g.cves })}</summary>
        {open ? (
          <ul id={panel} className="mt-2 grid divide-y divide-rule border-l border-rule pl-3">
            {g.questions.map((q) => <li key={q.id} className="py-1.5"><QuestionItem i={q} mode="row" /></li>)}
          </ul>
        ) : null}
      </details>
      {ignoring && g.software ? <IgnoreDialog device={device} line={{ id: g.software!.id, name }} count={g.cves} onClose={() => setIgnoring(false)} /> : null}
      {accepting && g.software ? <AcceptRiskDialog device={device} line={g.software} what={name} count={g.cves} onClose={() => setAccepting(false)} /> : null}
    </li>
  )
}

/** One card per added device: everything Vedette needs from a person about it, collapsed to a line by default (as Findings By fix).
 *  Opened: what runs there, urgent findings not confirmed yet, and its software lines with their questions. */
function DeviceNeeds({ i, link }: { i: Item<'device_needs'>; link: boolean }) {
  const { t } = useTranslation('findings')
  const r = useRoles()
  const [open, setOpen] = useState(false)
  const [ignoring, setIgnoring] = useState(false)
  const [accepting, setAccepting] = useState(false)
  const lines = i.entries.filter((e): e is InputGroupItem => e.kind === 'software_group')
  const cves = lines.reduce((n, g) => n + g.cves, 0)
  const others = i.entries.length - lines.length
  const panel = `needs-${i.id.replace(/[^\w-]/g, '_')}`
  return (
    <article aria-label={t('queue.deviceCard', { device: i.device.name })} className="grid gap-2 py-1">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Button variant="ghost" size="sm" aria-expanded={open} aria-controls={panel} onClick={() => setOpen((o) => !o)} className="-ml-2 h-auto min-h-8 justify-start gap-1.5 whitespace-normal py-1 text-left">
            <ChevronDown aria-hidden className={open ? 'rotate-180' : ''} />
            <span className="text-sm font-semibold [overflow-wrap:anywhere]">{i.device.name}</span>
            <span className="font-normal text-muted">{t('queue.deviceSummary', { lines: lines.length, cves, others })}</span>
          </Button>
          {link ? <Link to={`/devices/${encodeURIComponent(i.device.id)}`} className="text-meta text-accent underline-offset-4 hover:underline">{t('queue.openDevice')}</Link> : null}
        </div>
        {lines.length ? (
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" disabled={!r.operator} title={r.needOperator} aria-label={t('queue.ignoreDeviceOf', { device: i.device.name })} onClick={() => setIgnoring(true)}>{t('queue.ignoreAll')}</Button>
            <Button size="sm" disabled={!r.admin} title={r.needAdmin} aria-label={t('queue.acceptDeviceOf', { device: i.device.name })} onClick={() => setAccepting(true)}>{t('queue.acceptAll')}</Button>
          </div>
        ) : null}
      </div>
      {open ? (
        <ul id={panel} aria-label={t('queue.entriesOf', { device: i.device.name })} className="ml-6 grid divide-y divide-rule border-l border-rule pl-3">
          {i.entries.map((e) => e.kind === 'software_group' ? <SoftwareEntry key={e.id} g={e} device={i.device} />
            : <li key={e.id} className="py-3">{e.kind === 'unconfirmed' ? <UnconfirmedItem i={e} link={false} /> : <UncheckedItem i={e} link={false} />}</li>)}
        </ul>
      ) : null}
      {ignoring ? <IgnoreDialog device={i.device} line={null} count={cves} onClose={() => setIgnoring(false)} /> : null}
      {accepting ? <AcceptRiskDialog device={i.device} what={t('queue.everythingWaiting')} count={cves} onClose={() => setAccepting(false)} /> : null}
    </article>
  )
}

/** One item of the queue. linkDevice false names its device without a link: an earlier item of the page links to its page. */
export function QueueItem({ i, linkDevice = true }: { i: InputItem; linkDevice?: boolean }) {
  return i.kind === 'devices_not_added' ? <NotAddedGroupItem i={i} />
    : i.kind === 'device_not_added' ? <NotAddedItem i={i} link={linkDevice} /> : <DeviceNeeds i={i} link={linkDevice} />
}

/** The ids of the items that link to their device's page: the first item of each device on the page, so the page has one link per
 * device. */
function deviceLinks(items: InputItem[]): Set<string> {
  const seen = new Set<string>()
  const out = new Set<string>()
  for (const i of items) {
    if (i.kind === 'devices_not_added') continue
    if (!seen.has(i.device.id)) {
      seen.add(i.device.id)
      out.add(i.id)
    }
  }
  return out
}

/** One question answered "not affected": what it was, who answered, and Ask again (the answer is taken back, the question waits again). */
function AnsweredRow({ x }: { x: AnsweredQuestion }) {
  const { t } = useTranslation('findings')
  const r = useRoles()
  const unanswer = useUnanswer()
  const words = { software: x.software?.name ?? t('queue.theSoftware'), version: x.software?.version ?? '', device: x.device.name, count: x.cves, cve: x.cve ?? '' }
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 py-2">
      <span className="grid gap-0.5">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
          {x.cve ? <Link to={`/cve/${encodeURIComponent(x.cve)}`} className="text-accent underline-offset-4 hover:underline">{x.cve}</Link> : null}
          <DeviceLine device={x.device} badge={false} />
          {x.software ? <span className="text-meta text-muted">{x.software.version ? `${x.software.name} ${x.software.version}` : x.software.name}</span> : null}
        </span>
        <span className="text-meta text-muted">{t('queue.answeredBy', { by: x.by, date: fmtDate(x.at) })}</span>
      </span>
      <Button size="sm" disabled={!r.operator} title={r.needOperator} busy={unanswer.isPending && unanswer.variables?.id === x.id} busyLabel={t('common:busy.saving')}
        aria-label={t('queue.askAgainOf', words)}
        onClick={() => unanswer.mutate({ id: x.id }, { onSuccess: () => toast.success(t('queue.askedAgain', words)), onError: (e) => toast.error(errMsg(e)) })}>
        {t('queue.askAgain')}
      </Button>
    </li>
  )
}

/** The questions answered "not affected", behind one click under the queue: a wrong click is never final. */
function Answered({ device }: { device: string }) {
  const { t } = useTranslation('findings')
  const q = useAnswered({ device }, { offset: 0, limit: PAGE_MAX })
  const total = q.data?.total ?? 0
  if (!total) return null
  return (
    <details className="grid gap-2" data-testid="answered">
      <summary className="w-fit cursor-pointer text-sm text-accent">{t('queue.answered', { count: total })}</summary>
      <ul aria-label={t('queue.answeredCaption')} className="mt-2 grid divide-y divide-rule">
        {q.data!.items.map((x) => <AnsweredRow key={x.id} x={x} />)}
      </ul>
      {total > q.data!.items.length ? <p className="text-meta text-muted">{t('queue.answeredMore', { count: total - q.data!.items.length })}</p> : null}
    </details>
  )
}

export function InputTab({ device, onDevice }: { device: string; onDevice: (id: string) => void }) {
  const { t } = useTranslation('findings')
  const raw = useListParams('input')
  const list = useMemo(() => ({ ...raw, size: raw.size === undefined ? undefined : Math.min(raw.size, PAGE_MAX) }), [raw])
  const size = list.size ?? PAGE_DEFAULT
  const q = useInputList({ q: raw.q, device }, { offset: list.page * size, limit: size })
  const links = useMemo(() => deviceLinks(q.data?.items ?? []), [q.data])
  const columns: ColumnDef<InputItem>[] = [
    { id: 'item', header: t('queue.col'), cell: ({ row: { original: i } }) => <QueueItem i={i} linkDevice={links.has(i.id)} /> },
  ]
  const named = q.data?.items.flatMap((x) => x.kind !== 'devices_not_added' && x.device.id === device ? [x.device.name] : [])[0]
  const filtered = !!(device || raw.q)
  const clear = () => { raw.set({ q: '', page: 0 }); onDevice('') }
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <ListSearch value={raw.q} onChange={(v) => raw.set({ q: v, page: 0 })} label={t('queue.search')} />
        {device ? <Button size="sm" onClick={() => onDevice('')}><X />{t('byDevice.clearDevice', { device: named ?? t('byDevice.thisDevice') })}</Button> : null}
      </div>
      <QueryState query={q}>
        {(d) => d.total === 0 && !filtered ? <EmptyState title={t('queue.empty')}>{t('queue.emptyBody')}</EmptyState> : (
          <DataTable urlKey="input" caption={t('queue.caption')} data={d.items} columns={columns} pageSize={PAGE_DEFAULT}
            server={{ total: d.total, list, max: PAGE_MAX }} filtered={filtered} onClearFilters={clear} resetPageOn={device} mobileRow={(i) => <QueueItem i={i} linkDevice={links.has(i.id)} />} />
        )}
      </QueryState>
      <Answered device={device} />
    </div>
  )
}
