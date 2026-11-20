import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { KeyValue, Panel, Section } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { CveList, SeverityBadge, bandOf } from '@/components/common/status'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Button } from '@/components/ui/button'
import { BusyNote } from '@/components/common/BusyNote'
import { useCan } from '@/lib/session'
import { DependencyLink } from '@/components/common/DependencyLink'
import { InfoLine } from './InfoLine'
import { useGreenbone, useOpenVasAgain, useScanRun, useSetGreenbone } from './api'
import type { Greenbone, GreenboneResult, GreenboneRun, Snapshot, Target } from './types'
import { blockedKey } from './types'
import { fmtDate, fmtDateTime, fmtEnd } from '@/lib/format'

/** Under 8 GB (decimal) the first feed load uses swap, so the box then needs 2 GB of swap; it passes from 6 GB. */
const SWAP_BELOW = 8e9

const STATE_TONE: Record<Greenbone['state'], Tone> = { unavailable: 'off', off: 'off', starting: 'accent', loading: 'accent', ready: 'ok', error: 'danger' }
/** Decimal GB with one decimal, as the box measures it (8 GB = 8e9 bytes). */
/** Greenbone's own classes: Low is 0.1 to 3.9 (a hardening note). */
const LOW_BELOW = 4
const gb = (n: number | null) => (n === null ? null : `${(Math.floor(n / 1e8) / 10).toFixed(1)} GB`) // rounded down, as the box says it

/**
 * S-EXP-2 (INV-25): the optional deep scan with Greenbone (OpenVAS), off by default, admin only. The box measures its memory and
 * free disk first and refuses with the numbers; the first start loads Greenbone's feed for about 2 hours, shown as a phase.
 */
export function GreenboneSetting({ embedded = false }: { embedded?: boolean }) {
  const { t } = useTranslation('exposure')
  const q = useGreenbone()
  // #850: on the OpenVAS engine card of Settings › Scanning the card's switch turns it on or off; this shows its state and needs only
  if (embedded) return <QueryState query={q}>{(g) => <GreenboneBody g={g} embedded />}</QueryState>
  return (
    <Section id="greenbone" title={t('greenbone.title')} description={t('greenbone.description')} info={<>
      <p>{t('greenbone.descriptionInfo')}</p><p>{t('greenbone.what')}</p><p>{t('greenbone.apart')}</p><p>{t('greenbone.weekly')}</p><p>{t('greenbone.offKeeps')}</p>
    </>}>
      <QueryState query={q}>{(g) => <GreenboneBody g={g} />}</QueryState>
    </Section>
  )
}

function GreenboneBody({ g, embedded = false }: { g: Greenbone; embedded?: boolean }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const set = useSetGreenbone()
  const locked = !can ? t('common:needRole', { role: t('common:role.admin') }) : undefined
  const on = g.state !== 'off' && g.state !== 'unavailable'
  // held back after it was turned on, its containers may still run: Turn off stays offered
  const heldOn = g.state === 'unavailable' && g.enabled
  const change = (enabled: boolean) => set.mutate(enabled, {
    onSuccess: () => toast.success(enabled ? t('greenbone.toastOn') : t('greenbone.toastOff')),
    onError: (e) => toast.error(e instanceof Error ? e.message : String(e)),
  })
  const p = g.preflight
  const f = g.feed_sync
  const Box = embedded ? 'div' : Panel
  return (
    <Box className={embedded ? 'grid max-w-3xl gap-4' : 'grid max-w-3xl gap-4 p-4'}>
      <p className="flex flex-wrap items-center gap-2 text-sm font-medium" role="status">
        <Chip tone={STATE_TONE[g.state]}>{t(`greenbone.state.${g.state}`)}</Chip>
        {g.state === 'loading' ? g.reason ?? t('greenbone.loading') : g.state === 'error' || g.state === 'unavailable' ? g.reason : t(`greenbone.stateText.${g.state}`)}
      </p>
      {heldOn ? (embedded ? null : (
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={() => change(false)} disabled={!can} busy={set.isPending} busyLabel={t('common:busy.turningOff')} title={locked}>{t('greenbone.disable')}</Button>
          <span className="text-caption text-muted">{t('greenbone.heldOn')}</span>
          <BusyNote busy={set.isPending} className="basis-full">{t('greenbone.offWaiting')}</BusyNote>
        </div>
      )) : g.state === 'unavailable' ? null : (
        <>
          <KeyValue items={[
            { label: t('greenbone.memory'), value: gb(p.memory_bytes) ?? t('common:unknown') },
            { label: t('greenbone.disk'), value: gb(p.disk_free_bytes) ?? t('common:unknown') },
            // T10: the date of the tests OpenVAS itself reports (get_feeds), there from the first load at Enable on.
            // A ready scanner whose feed was not read yet has its feed all the same (never "not yet"); before the first read
            // after a start the line is left out.
            ...(on && (g.feed?.nvt_version || g.state === 'ready') ? [{ label: t('greenbone.feedTests'), value: <FeedTests g={g} /> }] : []),
            // The weekly feed update, its last outcome (only once one ran) and when the next one is due
            ...(f.last_at ? [{ label: t('greenbone.feedLast'), value: `${fmtDateTime(f.last_at)}. ${f.note ?? ''}` }] : []),
            ...(f.next_at ? [{ label: t('greenbone.feedNext'), value: fmtDateTime(f.next_at) }] : []),
          ]} />
          {!on ? <InfoLine className="text-meta" topic={t('greenbone.needsTopic')} info={t('greenbone.needsInfo')}>{t('greenbone.needs')}</InfoLine> : null}
          {(!on || (g.state === 'loading' && !f.last_at)) && p.ok && p.memory_bytes != null && p.memory_bytes < SWAP_BELOW ? <InfoLine className="text-meta text-muted" topic={t('greenbone.memory')} info={t('greenbone.swapNoteInfo')}>{t('greenbone.swapNote')}</InfoLine> : null}
          {!on && !p.ok ? <p role="alert" className="text-sm text-warn">{p.reason}</p> : null}
          {embedded ? null : <div className="flex flex-wrap items-center gap-3">
            {on ? (
              <Button onClick={() => change(false)} disabled={!can} busy={set.isPending} busyLabel={t('common:busy.turningOff')} title={locked}>{t('greenbone.disable')}</Button>
            ) : (
              <Button variant="primary" onClick={() => change(true)} disabled={!can || !p.ok} busy={set.isPending} busyLabel={t('common:busy.turningOn')} title={locked ?? (p.ok ? undefined : p.reason ?? undefined)}>{t('greenbone.enable')}</Button>
            )}
            {g.changed_by && g.changed_at ? <span className="text-caption text-muted">{t(on ? 'greenbone.changedOn' : 'greenbone.changedOff', { by: g.changed_by, time: fmtDateTime(g.changed_at) })}</span> : null}
            {/* Turn off stops the OpenVAS containers and waits for them (up to 5 minutes); Enable only starts them in the background */}
            <BusyNote busy={set.isPending && set.variables === false} className="basis-full">{t('greenbone.offWaiting')}</BusyNote>
          </div>}
          {locked && !embedded ? <p className="text-meta text-muted">{locked}</p> : null}
        </>
      )}
    </Box>
  )
}

/** T10 (#824): the feed's date on one line; its version and what it is behind ⓘ. */
function FeedTests({ g }: { g: Greenbone }) {
  const { t } = useTranslation('exposure')
  const feed = g.feed
  if (feed?.nvt_version) {
    return <InfoLine topic={t('greenbone.feedTests')} info={t('greenbone.feedTestsInfo', { version: feed.nvt_version })}>{feed.nvt_date ? fmtDate(feed.nvt_date) : feed.nvt_version}</InfoLine>
  }
  return <>{g.changed_at ? t('greenbone.feedFirstDoneAt', { time: fmtDateTime(g.changed_at) }) : t('greenbone.feedFirstDone')}</>
}

/** docs/UI.md §0: OpenVAS did not run because it is off: the place to turn it on, on the External exposure page. */
function OpenVasOffLink() {
  const { t } = useTranslation('exposure')
  const q = useGreenbone()
  if (q.data?.state !== 'off') return null
  return <DependencyLink className="mt-2" reason={t('greenbone.offReason')} to="/exposure?tab=settings#greenbone" label={t('greenbone.offLink')} />
}

/** A snapshot read from a box older than greenbone_run (or the mock's stored days) has none: the lines say what happened. */
function runOf(s: Snapshot): GreenboneRun {
  const run = (s as Partial<Snapshot>).greenbone_run
  if (run) return run
  return { state: s.checks.some((c) => c.kind === 'greenbone') ? 'done' : 'not_run', started_at: null, addresses: [] }
}

/** The heading of a state that has no table to show. */
const EMPTY_TITLE: Record<GreenboneRun['state'], string> = {
  running: 'greenbone.results.runningTitle', done: 'greenbone.results.noneTitle', partial: 'greenbone.results.partialNoneTitle',
  not_run: 'greenbone.results.notRunTitle', failed: 'greenbone.results.failedTitle', stopped: 'greenbone.results.stoppedTitle',
  ended: 'greenbone.results.endedTitle',
}

/** The line above the table when its rows are not those of a finished scan. A domain's state is that of one of
 *  its addresses, so its line speaks of the addresses (review round 2 N2: another address may have finished with full rows). */
const ROWS_LINE: Partial<Record<GreenboneRun['state'], string>> = {
  partial: 'greenbone.results.partialLine', ended: 'greenbone.results.endedLine',
}
const rowsLine = (run: GreenboneRun) => (run.addresses ?? []).length > 0
  ? (run.state === 'partial' || run.state === 'stopped' || run.state === 'ended' ? 'greenbone.results.domainLine' : undefined)
  : ROWS_LINE[run.state]

/**
 * S-EXP-2 (INV-25): what Greenbone reported on this IP. Apart from the exploited CVEs, and never "nothing found = not affected".
 * High and Medium results are its findings; Low results are hardening notes in their own group, not alerts and not counted anywhere.
 * The heading follows the step's one state (greenbone_run): scanning, finished, stopped at the 90-minute cap with what it
 * had found by then, not run, failed, stopped, ended by OpenVAS or the domain fence. The rows it stored are shown whatever the state, with
 * a line when they are not those of a finished scan. Its start is shown in the viewer's time zone, like every other
 * time of the page. Every OpenVAS line is also in the "Not checked" list below.
 */
export function GreenboneSection({ s, again }: { s: Snapshot; again?: Target }) {
  const { t } = useTranslation('exposure')
  const rows = s.greenbone ?? [] // a snapshot read from an older box has no list
  const run = runOf(s)
  const findings = rows.filter((r) => r.severity >= LOW_BELOW)
  const notes = rows.filter((r) => r.severity < LOW_BELOW)
  // A domain's lines carry the address in front; the body is the line of an address in the run's state
  const lines = s.not_checked.filter((n) => n.kind === 'greenbone')
  const addr = (run.addresses ?? []).find((a) => a.state === run.state)
  const why = (addr ? lines.find((n) => n.text.startsWith(`${addr.ip} `) || n.text.startsWith(`${addr.ip}:`)) : undefined) ?? lines[0]
  // rows OpenVAS stored are shown whatever the state (a domain stopped on its second address keeps the first's)
  const shown = run.state !== 'running' && findings.length > 0
  // rows were read: the table, or "found none"; review round 2 N3: stored Low rows (hardening notes) show in any state too
  const read = rows.length > 0 || run.state === 'done' || run.state === 'partial'
  const line = shown ? rowsLine(run) : undefined
  const started = run.started_at ? fmtDateTime(run.started_at) : null
  const stopped = stopText(t, run)
  const cols: ColumnDef<GreenboneResult>[] = [
    { id: 'severity', header: t('greenbone.col.severity'), accessorFn: (r) => r.severity, cell: ({ row }) => {
      const v = row.original.severity // OpenVAS's severity is a CVSS base score
      return <SeverityBadge severity={{ band: bandOf(v), score: v }} />
    } },
    { id: 'name', header: t('greenbone.col.name'), accessorFn: (r) => r.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: 'port', header: t('greenbone.col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="tabular-nums">{row.original.port || t('common:unknown')}</span> },
    { id: 'qod', header: t('greenbone.col.qod'), accessorFn: (r) => r.qod, cell: ({ row }) => <span className="tabular-nums">{row.original.qod}%</span> },
    { id: 'cves', header: t('greenbone.col.cves'), enableSorting: false, accessorFn: (r) => r.cves.join(' '), cell: ({ row }) => (
      row.original.cves.length > 0 ? <CveList rows items={row.original.cves.map((cve) => ({ cve }))} label={t('greenbone.col.cves')} /> : <span className="text-caption text-muted">{t('greenbone.noCve')}</span>
    ) },
    { id: 'solution', header: t('greenbone.col.solution'), enableSorting: false, accessorFn: (r) => r.solution, cell: ({ row }) => <span className="text-meta">{row.original.solution}</span> },
  ]
  const emptyBody = run.state === 'running' ? (started ? t('greenbone.results.runningBody', { time: started }) : t('greenbone.results.runningBodyNoTime'))
    : run.state === 'done' ? t('greenbone.results.noneBody')
    : run.state === 'partial' ? t('greenbone.results.partialNoneBody')
    : stopped ? `${stopped} ${t('greenbone.results.stoppedNotShown')}`
    : why?.text ?? t(run.state === 'not_run' ? 'greenbone.results.notRunBody' : run.state === 'failed' ? 'greenbone.results.failedBody' : run.state === 'ended' ? 'greenbone.results.endedBody' : 'greenbone.results.stoppedBody')
  const emptyInfo = run.state === 'done' ? t('greenbone.results.noneBodyInfo') : run.state === 'partial' ? t('greenbone.results.partialNoneBodyInfo') : undefined
  return (
    <>
      <Section id="greenbone-results" title={t('greenbone.results.title')} description={t('greenbone.results.header')} info={t('greenbone.results.headerInfo')}>
        {line ? <p role="status" className="mb-3 text-sm text-warn">{t(line)}</p> : null}
        {shown && stopped ? <p className="mb-3 text-sm text-warn">{stopped}</p> : null}
        {shown ? (
          <DataTable urlKey="greenbone-results" caption={t('greenbone.results.caption')} data={findings} columns={cols} pageSize={20} initialSort={[{ id: 'severity', desc: true }]} rowTone={(r) => (r.severity >= 7 ? 'warn' : undefined)} />
        ) : (
          <EmptyState title={t(EMPTY_TITLE[run.state])} info={emptyInfo}>{emptyBody}{run.state === 'not_run' ? <OpenVasOffLink /> : null}</EmptyState>
        )}
        {again && againShown(s, run) ? <OpenVasAgain target={again} s={s} /> : null}
        {run.again && run.state !== 'running' ? <p className="mt-2 text-caption text-muted">{t('greenbone.results.again')}</p> : null}
        {started && run.state !== 'running' ? <p className="mt-2 text-caption text-muted">{run.ended_at && run.state !== 'stopped'
          ? t('greenbone.results.startedEnded', { time: started, end: fmtEnd(run.started_at, run.ended_at) }) : t('greenbone.results.startedAt', { time: started })}</p> : null}
      </Section>
      {read && notes.length > 0 ? (
        <Section id="greenbone-notes" title={t('greenbone.results.notesTitle')} description={t('greenbone.results.notesHeader')} info={t('greenbone.results.notesHeaderInfo')}>
          <DataTable urlKey="greenbone-results-notes" caption={t('greenbone.results.notesCaption')} data={notes} columns={cols} pageSize={20} initialSort={[{ id: 'severity', desc: true }]} />
        </Section>
      ) : null}
    </>
  )
}

/** Why and when a stopped OpenVAS step was stopped, in the viewer's time zone. A scan stored before the box kept the reason, for which
 *  the audit log proves none (the box reads it at start-up), was stopped by a Stop or a shutdown, which leave no record; without a
 *  stop time on record the box could not check, and every cause is named. */
function stopText(t: (k: string, o?: Record<string, unknown>) => string, run: GreenboneRun): string | null {
  if (run.state !== 'stopped') return null
  const time = run.ended_at ? fmtDateTime(run.ended_at) : null
  if (!run.stop) return t(time ? 'greenbone.results.stop.unknown' : 'greenbone.results.stop.unknownNoTime', { time })
  const key = run.stop.reason === 'restart' && !time ? 'restartNoTime' : run.stop.reason
  return t(`greenbone.results.stop.${key}`, { time, by: run.stop.by ?? t('greenbone.results.stop.someone') })
}

/** The OpenVAS states after which it may run again on its own: it started and did not finish. */
const AGAIN_STATES: GreenboneRun['state'][] = ['stopped', 'failed', 'ended']
/** How old a scan may be for OpenVAS to run again on the ports it found (the server's AgainWithin). */
const AGAIN_WITHIN_MS = 24 * 3_600_000
/** At most one scan of a target every 10 minutes (the server's ScanEvery); OpenVAS again counts as one. */
const SCAN_EVERY_MS = 10 * 60_000

/** The server's rule: the step started and did not finish, found nothing it would lose, and the scan is less than 24 hours old. */
function againShown(s: Snapshot, run: GreenboneRun) {
  const start = Date.parse((s as Partial<Snapshot>).started_at ?? s.scanned_at)
  return AGAIN_STATES.includes(run.state) && (s.greenbone ?? []).length === 0 && Date.now() - start <= AGAIN_WITHIN_MS
}

/** Run only OpenVAS again for the newest scan of this IP, on the open TCP ports that scan found, instead of the whole deep scan.
 *  The server checks the same things as Scan now (ownership, the IP still the box's, the box's one scan slot) and says why when it refuses. */
function OpenVasAgain({ target, s }: { target: Target; s: Snapshot }) {
  const { t } = useTranslation('exposure')
  const operator = useCan('operator')
  const last = useScanRun().data
  const openvas = useGreenbone().data?.state
  const go = useOpenVasAgain()
  // the ports the server sends: this IP's, seen open by this scan
  const ports = [...new Set(s.ports.filter((p) => p.ip === target.value && !p.last_seen && !p.unchecked).map((p) => p.port))].sort((a, b) => a - b)
  // the 10 minutes count from the target's newest start: its scan, or a run of OpenVAS again since
  const since = Math.max(target.last_scan_at ? Date.parse(target.last_scan_at) : 0, last?.target_id === target.id && last.status !== 'queued' ? Date.parse(last.started_at) : 0) // a queued entry has not started
  // Why the server would refuse now, first the one the person can act on here; each with the place to fix it (docs/UI.md §0)
  const why: { text: string; link?: { to: string; label: string } } | null = !operator ? { text: t('common:needRole', { role: t('common:role.operator') }) }
    : last?.status === 'running' ? { text: t('greenbone.again.busy') }
    : target.blocked_reason ? { text: t(`blocked.reasonLong.${blockedKey(target)}`, { value: target.value }), link: { to: '?tab=ownership#step-verify', label: t('greenbone.again.ownershipLink') } }
    : !target.full_scan ? { text: t('greenbone.again.terms'), link: { to: '?tab=ownership#step-terms', label: t('greenbone.again.termsLink') } }
    : openvas === 'off' ? { text: t('greenbone.offReason'), link: { to: '/exposure?tab=settings#greenbone', label: t('greenbone.offLink') } }
    : openvas !== undefined && openvas !== 'ready' ? { text: t('greenbone.again.notReady'), link: { to: '/exposure?tab=settings#greenbone', label: t('greenbone.again.notReadyLink') } }
    : Date.now() - since < SCAN_EVERY_MS ? { text: t('greenbone.again.wait', { time: fmtDateTime(new Date(since + SCAN_EVERY_MS).toISOString()) }) }
    : null
  return (
    <div className="mt-3 grid max-w-3xl gap-2">
      <p className="text-meta text-muted">{t('greenbone.again.note', { ports: ports.join(', ') })}</p>
      <div>
        <Button onClick={() => go.mutate(target.id, { onSuccess: () => toast.success(t('greenbone.again.started', { value: target.value })), onError: (e) => toast.error(e instanceof Error ? e.message : String(e)) })}
          disabled={!!why} title={why?.text} busy={go.isPending} busyLabel={t('common:busy.starting')}>{t('greenbone.again.button')}</Button>
      </div>
      {why?.link ? <DependencyLink reason={why.text} to={why.link.to} label={why.link.label} /> : why ? <p className="text-caption text-muted">{why.text}</p> : null}
    </div>
  )
}
