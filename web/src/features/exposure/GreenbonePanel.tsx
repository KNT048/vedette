import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { KeyValue, Panel, Section } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { dateText, dateTimeText } from './dates'
import { InfoLine } from './InfoLine'
import { useGreenbone, useSetGreenbone } from './api'
import type { Greenbone, GreenboneResult, GreenboneRun, Snapshot } from './types'

/** D-569: under 8 GB (decimal) the first feed load uses swap, so the box then needs 2 GB of swap; it passes from 6 GB. */
const SWAP_BELOW = 8e9

const STATE_TONE: Record<Greenbone['state'], Tone> = { unavailable: 'off', off: 'off', starting: 'accent', loading: 'accent', ready: 'ok', error: 'danger' }
/** Decimal GB with one decimal, as the box measures it (8 GB = 8e9 bytes, D-563). */
/** Greenbone's own classes: Low is 0.1 to 3.9 (D-564 G3: a hardening note). */
const LOW_BELOW = 4
const gb = (n: number | null) => (n === null ? null : `${(Math.floor(n / 1e8) / 10).toFixed(1)} GB`) // rounded down, as the box says it

/**
 * S-EXP-2 (INV-25, D-563): the optional deep scan with Greenbone (OpenVAS), off by default, admin only. The box measures its memory and
 * free disk first and refuses with the numbers; the first start loads Greenbone's feed for about 2 hours, shown as a phase.
 */
export function GreenboneSetting() {
  const { t } = useTranslation('exposure')
  const q = useGreenbone()
  return (
    <Section id="greenbone" title={t('greenbone.title')} description={t('greenbone.description')} info={<>
      <p>{t('greenbone.descriptionInfo')}</p><p>{t('greenbone.what')}</p><p>{t('greenbone.apart')}</p><p>{t('greenbone.weekly')}</p><p>{t('greenbone.offKeeps')}</p>
    </>}>
      <QueryState query={q}>{(g) => <GreenboneBody g={g} />}</QueryState>
    </Section>
  )
}

function GreenboneBody({ g }: { g: Greenbone }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const set = useSetGreenbone()
  const locked = !can ? t('common:needRole', { role: t('common:role.admin') }) : undefined
  const on = g.state !== 'off' && g.state !== 'unavailable'
  // D-564: held back after it was turned on, its containers may still run: Turn off stays offered (review r1 M1)
  const heldOn = g.state === 'unavailable' && g.enabled
  const change = (enabled: boolean) => set.mutate(enabled, {
    onSuccess: () => toast.success(enabled ? t('greenbone.toastOn') : t('greenbone.toastOff')),
    onError: (e) => toast.error(e instanceof Error ? e.message : String(e)),
  })
  const p = g.preflight
  const f = g.feed_sync
  return (
    <Panel className="grid max-w-3xl gap-4 p-4">
      <p className="flex flex-wrap items-center gap-2 text-sm font-medium" role="status">
        <Chip tone={STATE_TONE[g.state]}>{t(`greenbone.state.${g.state}`)}</Chip>
        {g.state === 'loading' ? g.reason ?? t('greenbone.loading') : g.state === 'error' || g.state === 'unavailable' ? g.reason : t(`greenbone.stateText.${g.state}`)}
      </p>
      {heldOn ? (
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={() => change(false)} disabled={!can || set.isPending} title={locked}>{t('greenbone.disable')}</Button>
          <span className="text-[12px] text-muted">{t('greenbone.heldOn')}</span>
        </div>
      ) : g.state === 'unavailable' ? null : (
        <>
          <KeyValue items={[
            { label: t('greenbone.memory'), value: gb(p.memory_bytes) ?? t('common:unknown') },
            { label: t('greenbone.disk'), value: gb(p.disk_free_bytes) ?? t('common:unknown') },
            // T10: the date of the tests OpenVAS itself reports (get_feeds), there from the first load at Enable on.
            // N45-4: a ready scanner whose feed was not read yet has its feed all the same (never "not yet"); before the first read
            // after a start the line is left out (review L2).
            ...(on && (g.feed?.nvt_version || g.state === 'ready') ? [{ label: t('greenbone.feedTests'), value: <FeedTests g={g} /> }] : []),
            // D-564 G6: the weekly feed update, its last outcome (only once one ran) and when the next one is due
            ...(f.last_at ? [{ label: t('greenbone.feedLast'), value: `${dateTimeText(f.last_at)}. ${f.note ?? ''}` }] : []),
            ...(f.next_at ? [{ label: t('greenbone.feedNext'), value: dateTimeText(f.next_at) }] : []),
          ]} />
          {!on ? <InfoLine className="text-[13px]" topic={t('greenbone.needsTopic')} info={t('greenbone.needsInfo')}>{t('greenbone.needs')}</InfoLine> : null}
          {(!on || (g.state === 'loading' && !f.last_at)) && p.ok && p.memory_bytes != null && p.memory_bytes < SWAP_BELOW ? <InfoLine className="text-[13px] text-muted" topic={t('greenbone.memory')} info={t('greenbone.swapNoteInfo')}>{t('greenbone.swapNote')}</InfoLine> : null}
          {!on && !p.ok ? <p role="alert" className="text-sm text-warn">{p.reason}</p> : null}
          <div className="flex flex-wrap items-center gap-3">
            {on ? (
              <Button onClick={() => change(false)} disabled={!can || set.isPending} title={locked}>{t('greenbone.disable')}</Button>
            ) : (
              <Button variant="primary" onClick={() => change(true)} disabled={!can || !p.ok || set.isPending} title={locked ?? (p.ok ? undefined : p.reason ?? undefined)}>{t('greenbone.enable')}</Button>
            )}
            {g.changed_by && g.changed_at ? <span className="text-[12px] text-muted">{t(on ? 'greenbone.changedOn' : 'greenbone.changedOff', { by: g.changed_by, time: dateTimeText(g.changed_at) })}</span> : null}
          </div>
          {locked ? <p className="text-[13px] text-muted">{locked}</p> : null}
        </>
      )}
    </Panel>
  )
}

/** T10 (#824): the feed's date on one line; its version and what it is behind ⓘ. */
function FeedTests({ g }: { g: Greenbone }) {
  const { t } = useTranslation('exposure')
  const feed = g.feed
  if (feed?.nvt_version) {
    return <InfoLine topic={t('greenbone.feedTests')} info={t('greenbone.feedTestsInfo', { version: feed.nvt_version })}>{feed.nvt_date ? dateText(feed.nvt_date) : feed.nvt_version}</InfoLine>
  }
  return <>{g.changed_at ? t('greenbone.feedFirstDoneAt', { time: dateTimeText(g.changed_at) }) : t('greenbone.feedFirstDone')}</>
}

/** A snapshot read from a box older than greenbone_run (or the mock's stored days) has none: the lines say what happened. */
function runOf(s: Snapshot): GreenboneRun {
  const run = (s as Partial<Snapshot>).greenbone_run
  if (run) return run
  return { state: s.checks.some((c) => c.kind === 'greenbone') ? 'done' : 'not_run', started_at: null, addresses: [] }
}

/** N49-3 (D-595): the heading of a state that has no table to show. */
const EMPTY_TITLE: Record<GreenboneRun['state'], string> = {
  running: 'greenbone.results.runningTitle', done: 'greenbone.results.noneTitle', partial: 'greenbone.results.partialNoneTitle',
  not_run: 'greenbone.results.notRunTitle', failed: 'greenbone.results.failedTitle', stopped: 'greenbone.results.stoppedTitle',
  ended: 'greenbone.results.endedTitle',
}

/** D-595 review M1, M3: the line above the table when its rows are not those of a finished scan. A domain's state is that of one of
 *  its addresses, so its line speaks of the addresses (review round 2 N2: another address may have finished with full rows). */
const ROWS_LINE: Partial<Record<GreenboneRun['state'], string>> = {
  partial: 'greenbone.results.partialLine', ended: 'greenbone.results.endedLine',
}
const rowsLine = (run: GreenboneRun) => (run.addresses ?? []).length > 0
  ? (run.state === 'partial' || run.state === 'stopped' || run.state === 'ended' ? 'greenbone.results.domainLine' : undefined)
  : ROWS_LINE[run.state]

/**
 * S-EXP-2 (INV-25): what Greenbone reported on this IP. Apart from the exploited CVEs, and never "nothing found = not affected". D-564 G3:
 * High and Medium results are its findings; Low results are hardening notes in their own group, not alerts and not counted anywhere.
 * N49-3 (D-595): the heading follows the step's one state (greenbone_run): scanning, finished, stopped at the 90-minute cap with what it
 * had found by then, not run, failed, stopped, ended by OpenVAS or the domain fence. The rows it stored are shown whatever the state, with
 * a line when they are not those of a finished scan (review M1). N49-2: its start is shown in the viewer's time zone, like every other
 * time of the page. Every OpenVAS line is also in the "Not checked" list below.
 */
export function GreenboneSection({ s }: { s: Snapshot }) {
  const { t } = useTranslation('exposure')
  const rows = s.greenbone ?? [] // a snapshot read from an older box has no list
  const run = runOf(s)
  const findings = rows.filter((r) => r.severity >= LOW_BELOW)
  const notes = rows.filter((r) => r.severity < LOW_BELOW)
  // D-595 review L2: a domain's lines carry the address in front; the body is the line of an address in the run's state
  const lines = s.not_checked.filter((n) => n.kind === 'greenbone')
  const addr = (run.addresses ?? []).find((a) => a.state === run.state)
  const why = (addr ? lines.find((n) => n.text.startsWith(`${addr.ip} `) || n.text.startsWith(`${addr.ip}:`)) : undefined) ?? lines[0]
  // D-595 review M1: rows OpenVAS stored are shown whatever the state (a domain stopped on its second address keeps the first's)
  const shown = run.state !== 'running' && findings.length > 0
  // rows were read: the table, or "found none"; review round 2 N3: stored Low rows (hardening notes) show in any state too
  const read = rows.length > 0 || run.state === 'done' || run.state === 'partial'
  const line = shown ? rowsLine(run) : undefined
  const started = run.started_at ? dateTimeText(run.started_at) : null
  const cols: ColumnDef<GreenboneResult>[] = [
    { id: 'severity', header: t('greenbone.col.severity'), accessorFn: (r) => r.severity, cell: ({ row }) => {
      const v = row.original.severity
      return <Chip tone={v >= 7 ? 'danger' : v >= 4 ? 'warn' : 'off'}>{t(v >= 7 ? 'greenbone.sev.high' : v >= 4 ? 'greenbone.sev.medium' : 'greenbone.sev.low', { score: v.toFixed(1) })}</Chip>
    } },
    { id: 'name', header: t('greenbone.col.name'), accessorFn: (r) => r.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: 'port', header: t('greenbone.col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="tabular-nums">{row.original.port || t('common:unknown')}</span> },
    { id: 'qod', header: t('greenbone.col.qod'), accessorFn: (r) => r.qod, cell: ({ row }) => <span className="tabular-nums">{row.original.qod}%</span> },
    { id: 'cves', header: t('greenbone.col.cves'), enableSorting: false, accessorFn: (r) => r.cves.join(' '), cell: ({ row }) => (
      row.original.cves.length > 0 ? <span className="grid gap-0.5 text-[12px]">{row.original.cves.map((c) => <span key={c}>{c}</span>)}</span> : <span className="text-[12px] text-muted">{t('greenbone.noCve')}</span>
    ) },
    { id: 'solution', header: t('greenbone.col.solution'), enableSorting: false, accessorFn: (r) => r.solution, cell: ({ row }) => <span className="text-[13px]">{row.original.solution}</span> },
  ]
  const emptyBody = run.state === 'running' ? (started ? t('greenbone.results.runningBody', { time: started }) : t('greenbone.results.runningBodyNoTime'))
    : run.state === 'done' ? t('greenbone.results.noneBody')
    : run.state === 'partial' ? t('greenbone.results.partialNoneBody')
    : why?.text ?? t(run.state === 'not_run' ? 'greenbone.results.notRunBody' : run.state === 'failed' ? 'greenbone.results.failedBody' : run.state === 'ended' ? 'greenbone.results.endedBody' : 'greenbone.results.stoppedBody')
  const emptyInfo = run.state === 'done' ? t('greenbone.results.noneBodyInfo') : run.state === 'partial' ? t('greenbone.results.partialNoneBodyInfo') : undefined
  return (
    <>
      <Section id="greenbone-results" title={t('greenbone.results.title')} description={t('greenbone.results.header')} info={t('greenbone.results.headerInfo')}>
        {line ? <p role="status" className="mb-3 text-sm text-warn">{t(line)}</p> : null}
        {shown ? (
          <DataTable caption={t('greenbone.results.caption')} data={findings} columns={cols} pageSize={20} initialSort={[{ id: 'severity', desc: true }]} rowTone={(r) => (r.severity >= 7 ? 'warn' : undefined)} />
        ) : (
          <EmptyState title={t(EMPTY_TITLE[run.state])} info={emptyInfo}>{emptyBody}</EmptyState>
        )}
        {started && run.state !== 'running' ? <p className="mt-2 text-[12px] text-muted">{t('greenbone.results.startedAt', { time: started })}</p> : null}
      </Section>
      {read && notes.length > 0 ? (
        <Section id="greenbone-notes" title={t('greenbone.results.notesTitle')} description={t('greenbone.results.notesHeader')} info={t('greenbone.results.notesHeaderInfo')}>
          <DataTable caption={t('greenbone.results.notesCaption')} data={notes} columns={cols} pageSize={20} initialSort={[{ id: 'severity', desc: true }]} />
        </Section>
      ) : null}
    </>
  )
}
