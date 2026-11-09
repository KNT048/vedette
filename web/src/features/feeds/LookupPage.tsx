import { useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Search } from 'lucide-react'
import { PageHeader, Panel, KeyValue } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { fmtPercent } from '@/lib/format'
import { fmtDay } from './dates'
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
      <PageHeader title={t('lookup.title')} meta={t('lookup.meta')} stories={['S-FEED-3']} />
      <form role="search" onSubmit={submit} className="mb-6 flex max-w-xl flex-wrap gap-2">
        <Input autoFocus value={draft} maxLength={200} className="min-w-[17rem] flex-1" onChange={(e) => setDraft(e.target.value)} placeholder={t('search.placeholder')} aria-label={t('search.placeholder')} />
        <Button type="submit" variant="primary"><Search />{t('search.submit')}</Button>
      </form>
      <div className="[overflow-wrap:anywhere]"> {/* what was typed can be 200 characters without a space: break it, never widen the page */}
      {!q ? <EmptyState title={t('lookup.emptyTitle')}>{t('lookup.emptyBody')}</EmptyState>
        : res.isPending ? <Loading />
        : res.error ? <ErrorState error={res.error} onRetry={() => void res.refetch()} />
        : res.data.kind === 'cve' ? (
          res.data.found ? <Panel className="p-4"><Link className="text-accent underline-offset-4 hover:underline" to={`/cve/${res.data.cve}`}>{t('lookup.cveFound', { cve: res.data.cve })}</Link></Panel>
            : <EmptyState title={t('lookup.cveNotFound', { cve: res.data.cve })}>{t('lookup.cveNotFoundBody')}</EmptyState>
        ) : res.data.kind === 'ioc' ? (
          res.data.hit ? (
            <Panel className="grid gap-4 p-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-medium">{res.data.hit.value}</span>
                <Chip tone={res.data.hit.verdict === 'block' ? 'danger' : 'warn'}>{t(`lookup.verdict.${res.data.hit.verdict}`)}</Chip>
              </div>
              <KeyValue items={[
                { label: t('lookup.category'), value: res.data.hit.category },
                { label: t('lookup.sources'), value: res.data.hit.sources.join(', ') },
                { label: t('lookup.score'), value: fmtPercent(res.data.hit.score, 0) },
                { label: t('lookup.seen'), value: t('lookup.seenRange', { first: fmtDay(res.data.hit.first_seen), last: fmtDay(res.data.hit.last_seen) }) },
              ]} />
              <p className="text-[13px] text-muted">{t('lookup.iocNote')}</p>
            </Panel>
          ) : <EmptyState title={t('lookup.iocClean', { value: res.data.value })}>{t('lookup.iocCleanBody')}</EmptyState>
        ) : res.data.vulns.length ? (
          <ul className="grid divide-y divide-rule rounded-md border border-rule bg-surface">
            {res.data.vulns.map((v) => (
              <li key={v.cve} className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-3">
                <span><Link to={`/cve/${v.cve}`} className="font-medium text-accent underline-offset-4 hover:underline">{v.cve}</Link> <span className="text-muted">{v.display}</span></span>
                <span className="text-[13px] text-muted">{t('lookup.addedOn', { date: fmtDay(v.date_added) })}</span>
              </li>
            ))}
          </ul>
        ) : <EmptyState title={t('lookup.textNone', { q })}>{t('lookup.textNoneBody')}</EmptyState>}
      </div>
    </>
  )
}
