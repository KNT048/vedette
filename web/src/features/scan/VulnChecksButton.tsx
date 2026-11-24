import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ShieldCheck } from 'lucide-react'
import { Card } from '@/components/common/Card'
import { JobProgress } from '@/components/progress/JobProgress'
import { Button } from '@/components/ui/button'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { isLive, useRuns, useScanConfig, useStartRun, useTargets } from './api'
import { errMsg } from './errors'
import { vulnCount, vulnLabel, vulnNothing } from './vulnCount'
import { runHref } from '@/features/scanning/places'

/** The most devices of one run (contract.ts POST /scans/runs, scan errTooMany). */
const MAX = 200

/**
 * #850 review r2 N4 (director's decision): the button that starts vulnerability checks (operator, POST /scans/runs), only while the
 * vulnerability checks (scan module, Preview) are on. `targets` = these devices (a device page, a selection: a person's own pick) or
 * 'lan' = every device the box may check without a person's own pick (never the box, never a fragile, unclassified or hand-added one).
 * Every such button follows the box's one rule (vulnCount): it says what the run will check ("Check 5 suspected findings on 3 devices"),
 * sends only the devices that have something to check, and with nothing to check says so and offers no run. More than 200 is said, never
 * cut. Its progress shows under the button and the run opens in Settings › Scanning › History.
 */
export function VulnChecksButton({ targets, size = 'sm', here = false, showProgress = true, describedBy }: { targets: string[] | 'lan'; size?: 'sm' | 'md'; /** One device's own page: the words leave out "on 1 device". */ here?: boolean; /** Show the progress card under the button (default true); off where the page already shows the run (#877 r1 L12). */ showProgress?: boolean; /** The id of a line that says what the button does. */ describedBy?: string }) {
  const { t } = useTranslation('scan')
  const on = useModuleEnabled('scan') === true
  const can = useCan('operator')
  const runs = useRuns(on)
  const cfg = useScanConfig(on)
  const all = useTargets(on)
  const start = useStartRun()
  const [mine, setMine] = useState<string | null>(null)
  if (!on) return null
  const live = runs.data?.items.find(isLive)
  const ours = live && live.id === mine ? live : null
  const of = targets === 'lan' ? (all.data?.items ?? []).filter((x) => x.kind === 'internal' && x.selectable && !x.pick_only && !x.box).map((x) => x.id) : targets
  // the box's rule: only the devices with something to check are sent (a failed read sends the pick; the box leaves them out itself)
  const c = vulnCount(all.data?.items, of)
  const ids = c.ids
  const reading = !all.data && !all.isError
  const nothing = c.counted && of.length > 0 && c.none ? vulnNothing(t, c) : null
  const blocked = !can ? t('common:needRole', { role: t('common:role.operator') })
    : cfg.data && !cfg.data.can_scan ? cfg.data.block_reason
    : live && !ours ? t('checks.otherRunning')
    : runs.data?.engine_busy ? t('start.engineBusy')
    : targets === 'lan' && all.data && of.length === 0 ? t('checks.none')
    : targets !== 'lan' && of.length === 0 ? t('start.none')
    : ids.length > MAX ? t('start.tooMany', { max: MAX, count: ids.length }) : null
  // with nothing to check there is no button: only why (#83)
  if (nothing && !ours) return <p role="status" className="text-meta text-muted">{nothing}</p>
  const leftOut = c.counted && !c.none && ids.length < of.length ? t('checks.leftOut', { count: of.length - ids.length }) : null
  return (
    <div className="grid min-w-0 gap-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button size={size} disabled={!!blocked || reading} busy={start.isPending || !!ours} busyLabel={t('checks.running')} aria-describedby={describedBy}
          onClick={() => start.mutate(ids, { onSuccess: (r) => { setMine(r.id); toast.success(t('start.started')) }, onError: (e) => toast.error(errMsg(e)) })}>
          <ShieldCheck />{vulnLabel(t, c, here)}
        </Button>
        {blocked && !ours ? <span className="text-meta text-muted">{blocked}{live && !ours ? <> <Link to={runHref(live.id)} className="text-accent underline-offset-4 hover:underline">{t('checks.openRun')}</Link></> : null}</span>
          : leftOut && !ours ? <span className="text-meta text-muted">{leftOut}</span> : null}
      </div>
      {ours && showProgress ? (
        <Card className="grid gap-2">
          <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span className="font-medium">{t('progress.device', { n: Math.min(ours.done + 1, ours.total), total: ours.total })}</span>
            <Link to={runHref(ours.id)} className="text-meta text-accent underline-offset-4 hover:underline">{t('checks.openRun')}</Link>
          </div>
          {ours.status === 'stopping' ? null : <JobProgress progress={ours.progress} />}
        </Card>
      ) : ours ? null : mine && live === undefined && runs.data ? <p role="status" className="text-meta text-muted">{t('checks.finished')} <Link to={runHref(mine)} className="text-accent underline-offset-4 hover:underline">{t('checks.openRun')}</Link></p> : null}
    </div>
  )
}
