import { Card } from '@/components/common/Card'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import type { Blocklist } from './types'
import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RefreshCw } from 'lucide-react'
import { CodeBlock } from '@/components/common/CodeBlock'
import { InfoTip } from '@/components/common/InfoTip'
import { Notice, Section } from '@/components/common/PageHeader'
import { ErrorState, Loading } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { errText, useBlocklist, useNewToken } from './api'
import { guides } from './templates/guides'

export function BlocklistTab() {
  const { t } = useTranslation('response')
  const q = useBlocklist()
  const renew = useNewToken()
  const [ask, setAsk] = useState(false)
  const regenerate = (
    <Dialog open={ask} onOpenChange={setAsk}>
      <DialogContent title={t('blocklist.regenerateTitle')} description={t('blocklist.regenerateBody')}>
        <DialogFooter>
          <Button onClick={() => setAsk(false)}>{t('common:cancel')}</Button>
          <Button variant="danger" disabled={renew.isPending} onClick={() => renew.mutate(undefined, { onSuccess: () => { toast.success(t('blocklist.regenerated')); setAsk(false) }, onError: (e) => toast.error(errText(e)) })}>{t('blocklist.regenerate')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
  if (q.isPending) return <Loading />
  // #847: the token was not restored with the backup. The firewall keeps pulling its current address; the server's sentence says so,
  // and Regenerate (the administrator's choice) makes a new one.
  if (q.error instanceof ApiError && q.error.code === 'secret_lost') {
    return (
      <div className="grid grid-cols-[minmax(0,1fr)] gap-3">
        <ErrorState error={q.error} />
        <div><Button size="sm" onClick={() => setAsk(true)}><RefreshCw className="size-4" aria-hidden />{t('blocklist.regenerate')}</Button></div>
        {regenerate}
      </div>
    )
  }
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const b = q.data
  const entryColumns: ColumnDef<Blocklist['entries'][number]>[] = [
    { id: 'value', header: t('blocklist.address'), accessorFn: (e) => e.value, cell: ({ getValue }) => <span className="font-medium">{getValue() as string}</span> },
    { id: 'source', header: t('blocklist.source'), accessorFn: (e) => e.source },
    { id: 'reason', header: t('blocklist.reason'), accessorFn: (e) => e.reason },
    { id: 'expires', header: t('blocklist.expires'), accessorFn: (e) => e.expires_at ?? '', cell: ({ row }) => (row.original.expires_at ? fmtDateTime(row.original.expires_at) : t('blocklist.never')) },
  ]
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
      <Section title={t('blocklist.title')} description={t('blocklist.description')} info={<><p>{t('blocklist.descriptionInfo')}</p><p>{t('blocklist.pullInfo')}</p></>} stories={['S-RESP-3']}>
        <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
          <Card className="text-sm"><p>{t('blocklist.pull')}</p></Card>
          <CodeBlock code={b.url} label={t('blocklist.url')} />
          <div className="flex flex-wrap items-center gap-3 text-meta text-muted">
            <span>{t('blocklist.token', { last4: b.token_last4 })}</span>
            <span>{b.last_fetch ? t('blocklist.fetched', { time: fmtDateTime(b.last_fetch.at), from: b.last_fetch.from }) : t('blocklist.neverFetched')}</span>
            <Button size="sm" onClick={() => setAsk(true)}><RefreshCw className="size-4" aria-hidden />{t('blocklist.regenerate')}</Button>
          </div>
          {b.entries.length ? (
            <DataTable caption={t('blocklist.entries')} data={b.entries} columns={entryColumns} pageSize={b.entries.length}
              mobileRow={(e) => <div className="grid gap-0.5 text-sm"><span className="font-medium">{e.value}</span><span className="text-meta text-muted">{e.source}, {e.reason}</span><span className="text-meta text-muted">{t('blocklist.expires')}: {e.expires_at ? fmtDateTime(e.expires_at) : t('blocklist.never')}</span></div>} />
          ) : (
            // D-469: an empty list says what fills it, what it never holds, and where the rule that fills it is turned on
            <Card className="grid gap-2 text-sm">
              <div className="flex items-center gap-1"><p className="font-medium">{t('blocklist.empty')}</p><InfoTip topic={t('blocklist.title')}><p>{t('blocklist.emptyWhat')}</p><p>{t('blocklist.emptyPublic')}</p></InfoTip></div>
              <p className="text-muted">{t('blocklist.emptyTemplate')} <Link className="text-accent underline underline-offset-4" to="?tab=rules#templates">{t('blocklist.emptyLink')}</Link></p>
            </Card>
          )}
          <div className="flex items-center gap-1 text-meta text-muted"><p>{t('blocklist.ipOnly')}</p><InfoTip topic={t('blocklist.entries')}>{t('blocklist.ipOnlyInfo')}</InfoTip></div>
        </div>
      </Section>
      <Section title={t('blocklist.setupTitle')} description={t('blocklist.setupDescription')} stories={['S-RESP-3']}>
        <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
          {guides(b.url).map((g) => (
            <details key={g.id} className="rounded-md border border-rule bg-surface px-4 py-3">
              <summary className="cursor-pointer text-sm font-medium">{g.title}</summary>
              <ol className="ml-5 mt-3 grid grid-cols-[minmax(0,1fr)] list-decimal gap-2 text-sm">{g.steps.map((s) => <li key={s} className="[overflow-wrap:anywhere]">{s}</li>)}</ol>
              {g.code ? <div className="mt-3"><CodeBlock code={g.code.text} label={g.code.label} /></div> : null}
              {g.note ? <p className="mt-3 text-meta text-muted">{g.note}</p> : null}
            </details>
          ))}
        </div>
        <Notice tone="accent" className="mb-0 mt-4" title={t('blocklist.pushTitle')} info={t('blocklist.pushBodyInfo')}>{t('blocklist.pushBody')}</Notice>
      </Section>
      {regenerate}
    </div>
  )
}
