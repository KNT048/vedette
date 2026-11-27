import { useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Search } from 'lucide-react'
import { PageHeader, KeyValue } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { EmptyState, ErrorState, Loading } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ListRow, RowList } from '@/components/common/ListParts'
import { fmtDate, fmtPercent } from '@/lib/format'
import { useSearch } from './api'

export default function LookupPage() {
  const { t } = useTranslation('feeds')
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  const [draft, setDraft] = useState(q)
  useEffect(() => setDraft(q), [q])
  const res = useSearch(q)
  function submit(e: FormEvent) {
    e.preventDefault()
    setParams(draft.trim() ? { q: draft.trim() } : {})
  }
  return (
    <>
      <PageHeader title={t('common:shell.lookup')} meta={t('lookup.meta')} info={t('lookup.metaInfo')} stories={['S-FEED-3']} />
      <form role="search" onSubmit={submit} className="mb-6 flex max-w-xl flex-wrap gap-2">
        <Input autoFocus value={draft} maxLength={200} className="min-w-[17rem] flex-1" onChange={(e) => setDraft(e.target.value)} placeholder={t('search.placeholder')} aria-label={t('search.placeholder')} />
        <Button type="submit" variant="primary"><Search />{t('search.submit')}</Button>
      </form>
      <div className="[overflow-wrap:anywhere]"> {/* what was typed can be 200 characters without a space: break it, never widen the page */}
      {!q ? <EmptyState title={t('lookup.emptyTitle')}>{t('lookup.emptyBody')}</EmptyState>
        : res.isPending ? <Loading />
        : res.error ? <ErrorState error={res.error} onRetry={() => void res.refetch()} />
        : res.data.kind === 'cve' ? (
          res.data.found ? <Card><Link className="text-accent underline-offset-4 hover:underline" to={`/cve/${res.data.cve}`}>{t('lookup.cveFound', { cve: res.data.cve })}</Link></Card>
            : <EmptyState title={t('lookup.cveNotFound', { cve: res.data.cve })}>{t('lookup.cveNotFoundBody')}</EmptyState>
        ) : res.data.kind === 'ioc' ? (
          res.data.hit ? (
            <Card className="grid gap-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-medium">{res.data.hit.value}</span>
                <Chip tone={res.data.hit.verdict === 'block' ? 'danger' : 'warn'}>{t(`lookup.verdict.${res.data.hit.verdict}`)}</Chip>
              </div>
              <KeyValue items={[
                { label: t('lookup.category'), value: res.data.hit.category },
                { label: t('lookup.sources'), value: res.data.hit.sources.join(', ') },
                { label: t('lookup.score'), value: fmtPercent(res.data.hit.score, 0) },
                { label: t('lookup.seen'), value: t('lookup.seenRange', { first: fmtDate(res.data.hit.first_seen), last: fmtDate(res.data.hit.last_seen) }) },
              ]} />
              <p className="text-meta text-muted">{t('lookup.iocNote')}</p>
            </Card>
          ) : <EmptyState title={t('lookup.iocClean', { value: res.data.value })}>{t('lookup.iocCleanBody')}</EmptyState>
        ) : res.data.vulns.length ? (
          <Card flush><RowList flush label={t('lookup.results', { q })}>
            {res.data.vulns.map((v) => (
              <ListRow key={v.cve} title={v.cve} to={`/cve/${v.cve}`} sub={v.display} meta={[t('lookup.addedOn', { date: fmtDate(v.date_added) })]} />
            ))}
          </RowList></Card>
        ) : <EmptyState title={t('lookup.textNone', { q })}>{t('lookup.textNoneBody')}</EmptyState>}
      </div>
    </>
  )
}
