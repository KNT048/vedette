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
import { runHref } from './links'

/** The most devices of one run (contract.ts POST /scans/runs, scan errTooMany). */
const MAX = 200

/**
 * #850 review r2 N4 (director's decision): "Run vulnerability checks now" (operator, POST /scans/runs), only while the vulnerability
 * checks (scan module, Preview) are on. `targets` = these devices (a device page: a person's own pick) or 'lan' = every
 * device the box may check without a person's own pick (never the box, never a fragile, unclassified or hand-added one); more than
 * 200 is said, never cut. Its progress shows under the button and the run opens in Settings › Scanning › History.
 */
export function VulnChecksButton({ targets, size = 'sm', label, showProgress = true, describedBy }: { targets: string[] | 'lan'; size?: 'sm' | 'md'; label?: string; /** Show the progress card under the button (default true); off where the page already shows the run (#877 r1 L12). */ showProgress?: boolean; /** The id of a line that says what the button does. */ describedBy?: string }) {
  const { t } = useTranslation('scan')
  const on = useModuleEnabled('scan') === true
  const can = useCan('operator')
  const runs = useRuns(on)
  const cfg = useScanConfig(on)
  const all = useTargets(on && targets === 'lan')
  const start = useStartRun()
  const [mine, setMine] = useState<string | null>(null)
  if (!on) return null
  const live = runs.data?.items.find(isLive)
  const ours = live && live.id === mine ? live : null
  const ids = targets === 'lan' ? (all.data?.items ?? []).filter((x) => x.kind === 'internal' && x.selectable && !x.pick_only && !x.box).map((x) => x.id) : targets
  const blocked = !can ? t('common:needRole', { role: t('common:role.operator') })
    : cfg.data && !cfg.data.can_scan ? cfg.data.block_reason
    : live && !ours ? t('checks.otherRunning')
    : runs.data?.engine_busy ? t('start.engineBusy')
    : targets === 'lan' && all.data && ids.length === 0 ? t('checks.none')
    : targets !== 'lan' && ids.length === 0 ? t('start.none')
    : ids.length > MAX ? t('start.tooMany', { max: MAX, count: ids.length }) : null
  return (
    <div className="grid min-w-0 gap-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button size={size} disabled={!!blocked || (targets === 'lan' && !all.data)} busy={start.isPending || !!ours} busyLabel={t('checks.running')} aria-describedby={describedBy}
          onClick={() => start.mutate(ids, { onSuccess: (r) => { setMine(r.id); toast.success(t('start.started')) }, onError: (e) => toast.error(errMsg(e)) })}>
          <ShieldCheck />{label ?? t('checks.button')}
        </Button>
        {blocked && !ours ? <span className="text-meta text-muted">{blocked}{live && !ours ? <> <Link to={runHref(live.id)} className="text-accent underline-offset-4 hover:underline">{t('checks.openRun')}</Link></> : null}</span> : null}
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
