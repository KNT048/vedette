import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { KeyValue, Panel, Section } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { BusyNote } from '@/components/common/BusyNote'
import { useCan } from '@/lib/session'
import { InfoLine } from './InfoLine'
import { useGreenbone, useSetGreenbone } from './api'
import type { Greenbone } from './types'
import { fmtDate, fmtDateTime } from '@/lib/format'

/** Under 8 GB (decimal) the first feed load uses swap, so the box then needs 2 GB of swap; it passes from 6 GB. */
const SWAP_BELOW = 8e9

const STATE_TONE: Record<Greenbone['state'], Tone> = { unavailable: 'off', off: 'off', starting: 'accent', loading: 'accent', ready: 'ok', error: 'danger' }
/** Decimal GB with one decimal, as the box measures it (8 GB = 8e9 bytes). */
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
