// Needs your input: one queue of what only a person can settle, each item with its one action in place (forms open as dialogs).
// Devices nobody added yet that have findings (Add device, Ignore); urgent findings not confirmed yet (Run the safe check first when
// one exists, then Confirm vulnerability or Not affected…); questions (the version, the platform, the package release, "possibly
// affected: check the version"). An item leaves the queue the moment it is answered or stops being true (GET /findings/input).
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { X } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { useListParams } from '@/components/common/listParams'
import { EmptyState, QueryState } from '@/components/common/States'
import { SeverityBadge, StatusBadge, VerificationLine } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { fmtDate } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useDeviceAction } from '@/features/inventory/api'
import { useStartRun } from '@/features/scan/api'
import { useAnswer, useAnswered, useInputList, useUnanswer, useVerify } from './api'
import { AskDialog, type Ask } from './AskDialog'
import { PAGE_DEFAULT, PAGE_MAX } from './contract'
import { errMsg } from './errors'
import { HandleDialog } from './HandleDialog'
import { NotAdded } from './NotAdded'
import { asAsset, DeviceLine } from './parts'
import { linkLabels } from './links'
import type { AnsweredQuestion, InputItem } from './types'

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

function UnconfirmedItem({ i, link }: { i: Item<'unconfirmed'>; link: boolean }) {
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
function QuestionDialog({ i, asking, onClose }: { i: Item<'question'>; asking: Asking; onClose: () => void }) {
  const { t } = useTranslation('findings')
  const act = useDeviceAction(i.device.id)
  const answer = useAnswer()
  const unanswer = useUnanswer()
  const sw = i.software
  const words = { software: sw?.name ?? t('queue.theSoftware'), version: sw?.version ?? '', device: i.device.name, count: i.cves, cve: i.cve ?? '' }
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
  return (
    <AskDialog title={t(`queue.${a}Title`, words)} submit={t(`queue.${a}`)} done={t(a === 'not_affected' ? 'queue.notAffectedSaved' : 'queue.answerSaved', words)} undo={undo} onClose={onClose}
      fields={[{ name: 'note', label: t(a === 'affected' ? 'queue.confirmNote' : 'queue.notAffectedNote'), min: a === 'not_affected' ? 3 : undefined, required: a === 'not_affected', max: 500, long: true }]}
      onSend={(v) => answer.mutateAsync({ id: i.id, answer: a, note: v.note ?? '' })} />
  )
}

function QuestionItem({ i, link }: { i: Item<'question'>; link: boolean }) {
  const { t } = useTranslation('findings')
  const r = useRoles()
  const act = useDeviceAction(i.device.id)
  const [asking, setAsking] = useState<Asking | null>(null)
  const sw = i.software
  const words = { software: sw?.name ?? t('queue.theSoftware'), version: sw?.version ?? '', device: i.device.name, count: i.cves, cve: i.cve ?? '' }
  const typed = i.question === 'version_needed' || i.question === 'not_comparable'
  return (
    <div className="grid gap-2">
      <p className="text-sm">{t(`queue.q.${i.question}`, words)}</p>
      <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <DeviceLine device={i.device} badge={false} link={link} />
        {i.cve ? <Link to={`/cve/${encodeURIComponent(i.cve)}`} className="text-meta text-accent underline-offset-4 hover:underline">{i.cve}</Link> : null}
        {/* the link says what it is: NVD's entry is not the vendor's advisory */}
        {i.url ? <a href={i.url} target="_blank" rel="noopener noreferrer" className="text-meta text-accent underline-offset-4 hover:underline">{linkLabels(t, [i.url])[0]}</a> : null}
      </span>
      {i.command && !i.choices.some((c) => c.ask?.includes('pkg_version')) ? <p className="text-meta text-muted">{t('queue.command')} <code className="font-mono">{i.command}</code></p> : null}
      <div className="flex flex-wrap items-center gap-2">
        {typed && sw ? <Button size="sm" variant="primary" disabled={!r.operator} title={r.needOperator} onClick={() => setAsking({ kind: 'version' })}>{t('queue.addVersion')}</Button> : null}
        {typed && !sw ? (
          <Link to={`/devices/${encodeURIComponent(i.device.id)}?tab=software`} className="text-meta text-accent underline underline-offset-4">{t('queue.openSoftware')}</Link>
        ) : null}
        {i.choices.map((c) => c.os ? (
          <Button key={c.label} size="sm" disabled={!r.operator || act.patch.isPending} title={r.needOperator} busy={act.patch.isPending && act.patch.variables?.os === c.os} busyLabel={t('common:busy.saving')}
            onClick={() => act.patch.mutate({ os: c.os! }, { onSuccess: () => toast.success(t('queue.answerSaved', words)), onError: (e) => toast.error(errMsg(e)) })}>{c.label}</Button>
        ) : (
          <Button key={c.label} size="sm" disabled={!r.operator} title={r.needOperator} onClick={() => setAsking({ kind: 'choice', label: c.label, ask: c.ask ?? [] })}>{c.label}</Button>
        ))}
        {i.question === 'no_range_data' && i.cve ? (
          <>
            <Button size="sm" disabled={!r.admin} title={r.needAdmin} onClick={() => setAsking({ kind: 'answer', answer: 'affected' })}>{t('queue.affected')}</Button>
            <Button size="sm" disabled={!r.operator} title={r.needOperator} onClick={() => setAsking({ kind: 'answer', answer: 'not_affected' })}>{t('queue.not_affected')}</Button>
          </>
        ) : null}
      </div>
      {asking ? <QuestionDialog i={i} asking={asking} onClose={() => setAsking(null)} /> : null}
    </div>
  )
}

/** One item of the queue. linkDevice false names its device without a link: an earlier item of the page links to its page. */
export function QueueItem({ i, linkDevice = true }: { i: InputItem; linkDevice?: boolean }) {
  return i.kind === 'device_not_added' ? <NotAddedItem i={i} link={linkDevice} />
    : i.kind === 'unconfirmed' ? <UnconfirmedItem i={i} link={linkDevice} /> : <QuestionItem i={i} link={linkDevice} />
}

/** The ids of the items that link to their device's page: the first item of each device on the page, so the page has one link per
 * device. */
function deviceLinks(items: InputItem[]): Set<string> {
  const seen = new Set<string>()
  const out = new Set<string>()
  for (const i of items) {
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
  const q = useInputList({ device }, { offset: list.page * size, limit: size })
  const links = useMemo(() => deviceLinks(q.data?.items ?? []), [q.data])
  const columns: ColumnDef<InputItem>[] = [
    { id: 'item', header: t('queue.col'), cell: ({ row: { original: i } }) => <QueueItem i={i} linkDevice={links.has(i.id)} /> },
  ]
  const named = q.data?.items.find((x) => x.device.id === device)?.device.name
  return (
    <div className="grid gap-3">
      {device ? <Button size="sm" className="w-fit" onClick={() => onDevice('')}><X />{t('byDevice.clearDevice', { device: named ?? t('byDevice.thisDevice') })}</Button> : null}
      <QueryState query={q}>
        {(d) => d.total === 0 && !device ? <EmptyState title={t('queue.empty')}>{t('queue.emptyBody')}</EmptyState> : (
          <DataTable urlKey="input" caption={t('queue.caption')} data={d.items} columns={columns} pageSize={PAGE_DEFAULT}
            server={{ total: d.total, list, max: PAGE_MAX }} filtered={!!device} onClearFilters={() => onDevice('')} resetPageOn={device} mobileRow={(i) => <QueueItem i={i} linkDevice={links.has(i.id)} />} />
        )}
      </QueryState>
      <Answered device={device} />
    </div>
  )
}
