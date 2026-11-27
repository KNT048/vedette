import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useReportWindow, useSetReportWindow } from './api'

/** Settings → Feeds (S-FEED-4): which CVEs the box reports. The last 12 months and older ones exploited in the wild (the default), or
 * every age. Either change asks first: every age costs downloads and disk, back to the default closes the findings it brought. */
export function ReportWindowSection() {
  const { t } = useTranslation('feeds')
  const admin = useCan('admin')
  const win = useReportWindow()
  const set = useSetReportWindow()
  const [ask, setAsk] = useState<boolean | null>(null) // the value an administrator is about to set
  const reason = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  return (
    <Section id="feeds-window" title={t('window.title')} description={t('window.description')} info={t('window.descriptionInfo')} stories={['S-FEED-4']}>
      <QueryState query={win}>
        {(w) => (
          <div className="grid max-w-3xl gap-1.5">
            <label className="flex flex-wrap items-center gap-3 text-sm font-medium" htmlFor="feeds-every-age">
              <Switch id="feeds-every-age" checked={w.every_age} disabled={!admin || set.isPending} title={reason} onCheckedChange={(v) => setAsk(v)} />
              {t('window.everyAge')}
            </label>
            <p className="text-meta text-muted">{t(w.every_age ? 'window.onHelp' : 'window.offHelp')}</p>
            {w.changed_at ? <p className="text-caption text-muted">{t('window.changed', { who: w.changed_by ?? '', when: fmtRelative(w.changed_at) })}</p> : null}
          </div>
        )}
      </QueryState>
      {ask !== null ? (
        <Dialog open onOpenChange={(o) => { if (!o) setAsk(null) }}>
          <DialogContent title={t(ask ? 'window.onTitle' : 'window.offTitle')} description={t(ask ? 'window.onBody' : 'window.offBody')}>
            {set.error ? <p role="alert" className="text-sm text-danger">{(set.error as Error).message}</p> : null}
            <DialogFooter>
              <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
              <Button type="button" variant="primary" busy={set.isPending} onClick={() => set.mutate(ask, { onSuccess: () => { toast.success(t(ask ? 'window.nowOn' : 'window.nowOff')); setAsk(null) } })}>
                {t(ask ? 'window.onConfirm' : 'window.offConfirm')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </Section>
  )
}
