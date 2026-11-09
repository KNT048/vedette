import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RefreshCw } from 'lucide-react'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Panel, Section } from '@/components/common/PageHeader'
import { ErrorState, Loading } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { fmtDateTime } from '@/lib/format'
import { errText, useBlocklist, useNewToken } from './api'
import { guides } from './guides'

export function BlocklistTab() {
  const { t } = useTranslation('response')
  const q = useBlocklist()
  const renew = useNewToken()
  const [ask, setAsk] = useState(false)
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const b = q.data
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
      <Section title={t('blocklist.title')} description={t('blocklist.description')} stories={['S-RESP-3']}>
        <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
          <p className="rounded-md border border-rule bg-surface px-4 py-3 text-sm">{t('blocklist.pull')}</p>
          <CodeBlock code={b.url} label={t('blocklist.url')} />
          <div className="flex flex-wrap items-center gap-3 text-[13px] text-muted">
            <span>{t('blocklist.token', { last4: b.token_last4 })}</span>
            <span>{b.last_fetch ? t('blocklist.fetched', { time: fmtDateTime(b.last_fetch.at), from: b.last_fetch.from }) : t('blocklist.neverFetched')}</span>
            <Button size="sm" onClick={() => setAsk(true)}><RefreshCw className="size-4" aria-hidden />{t('blocklist.regenerate')}</Button>
          </div>
          <Panel>
            {b.entries.length ? (
              <div className="overflow-x-auto"><table className="w-full text-sm">
                <caption className="sr-only">{t('blocklist.entries')}</caption>
                <thead><tr className="border-b border-rule text-left text-[12px] text-muted"><th scope="col" className="px-3 py-2 font-medium">{t('blocklist.address')}</th><th scope="col" className="px-3 py-2 font-medium">{t('blocklist.source')}</th><th scope="col" className="px-3 py-2 font-medium">{t('blocklist.reason')}</th><th scope="col" className="px-3 py-2 font-medium">{t('blocklist.expires')}</th></tr></thead>
                <tbody className="divide-y divide-rule">
                  {b.entries.map((e) => (
                    <tr key={e.value} className="align-top"><th scope="row" className="px-3 py-2 text-left font-medium">{e.value}</th><td className="px-3 py-2">{e.source}</td><td className="px-3 py-2">{e.reason}</td><td className="px-3 py-2">{e.expires_at ? fmtDateTime(e.expires_at) : t('blocklist.never')}</td></tr>
                  ))}
                </tbody>
              </table></div>
            ) : <p className="px-4 py-3 text-sm text-muted">{t('blocklist.empty')}</p>}
          </Panel>
          <p className="text-[13px] text-muted">{t('blocklist.ipOnly')}</p>
        </div>
      </Section>
      <Section title={t('blocklist.setupTitle')} description={t('blocklist.setupDescription')} stories={['S-RESP-3']}>
        <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
          {guides(b.url).map((g) => (
            <details key={g.id} className="rounded-md border border-rule bg-surface px-4 py-3">
              <summary className="cursor-pointer text-sm font-medium">{g.title}</summary>
              <ol className="ml-5 mt-3 grid grid-cols-[minmax(0,1fr)] list-decimal gap-2 text-sm">{g.steps.map((s) => <li key={s} className="[overflow-wrap:anywhere]">{s}</li>)}</ol>
              {g.code ? <div className="mt-3"><CodeBlock code={g.code.text} label={g.code.label} /></div> : null}
              {g.note ? <p className="mt-3 text-[13px] text-muted">{g.note}</p> : null}
            </details>
          ))}
        </div>
        <div className="mt-4 grid gap-1 rounded-md border border-dashed border-rule px-4 py-3 text-sm">
          <p className="font-medium">{t('blocklist.pushTitle')}</p>
          <p className="text-muted">{t('blocklist.pushBody')}</p>
        </div>
      </Section>
      <Dialog open={ask} onOpenChange={setAsk}>
        <DialogContent title={t('blocklist.regenerateTitle')} description={t('blocklist.regenerateBody')}>
          <DialogFooter>
            <Button onClick={() => setAsk(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={renew.isPending} onClick={() => renew.mutate(undefined, { onSuccess: () => { toast.success(t('blocklist.regenerated')); setAsk(false) }, onError: (e) => toast.error(errText(e)) })}>{t('blocklist.regenerate')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
