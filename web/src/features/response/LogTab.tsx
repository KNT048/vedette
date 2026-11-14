import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { fmtDateTime } from '@/lib/format'
import { useLog } from './api'
import { verifyChain } from './logic'
import type { LogEntry } from './types'

const TONE: Partial<Record<LogEntry['kind'], Tone>> = { refused: 'warn', failed: 'danger', emergency_stop: 'danger', executed: 'ok', approved: 'ok', rolled_back: 'accent', ttl_removed: 'accent' }

/** Re-computes every hash in the browser (crypto.subtle) and checks each entry points at the one before it. */
function useChain(items: LogEntry[] | undefined) {
  const [res, setRes] = useState<{ for: LogEntry[]; ok: boolean; broken_at: number | null } | null>(null)
  useEffect(() => {
    let live = true
    if (items) void verifyChain(items).then((r) => { if (live) setRes({ for: items, ...r }) })
    return () => { live = false }
  }, [items])
  return res && res.for === items ? res : null
}

export function LogTab() {
  const { t } = useTranslation('response')
  const q = useLog()
  const chain = useChain(q.data?.items)
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const items = q.data.items
  return (
    <Section title={t('log.title')} description={t('log.description')} stories={['S-RESP-2', 'S-AI-8']}
      actions={chain === null ? <Chip tone="off">{t('log.checking')}</Chip> : chain.ok ? <Chip tone="ok">{t('log.verified')}</Chip> : <Chip tone="danger">{t('log.broken', { n: (chain.broken_at ?? 0) + 1 })}</Chip>}>
      {items.length ? (
        // a phone scrolls the table sideways: the box takes focus so the keyboard can scroll it too (axe scrollable-region-focusable)
        <div className="overflow-x-auto rounded-md border border-rule" tabIndex={0}>
          <table className="w-full text-sm">
            <caption className="sr-only">{t('log.title')}</caption>
            <thead><tr className="border-b border-rule text-left text-[12px] text-muted">
              <th scope="col" className="px-3 py-2 font-medium">{t('log.time')}</th><th scope="col" className="px-3 py-2 font-medium">{t('log.kind')}</th><th scope="col" className="px-3 py-2 font-medium">{t('log.actor')}</th><th scope="col" className="px-3 py-2 font-medium">{t('log.detail')}</th><th scope="col" className="px-3 py-2 font-medium">{t('log.hash')}</th>
            </tr></thead>
            <tbody className="divide-y divide-rule">
              {[...items].reverse().map((e) => (
                <tr key={e.id} className="align-top">
                  <td className="whitespace-nowrap px-3 py-2">{fmtDateTime(e.ts)}</td>
                  <td className="px-3 py-2"><Chip tone={TONE[e.kind] ?? 'off'}>{t(`log.kinds.${e.kind}`)}</Chip></td>
                  <td className="px-3 py-2">{e.actor}</td>
                  <td className="px-3 py-2">{e.detail}</td>
                  <td className="px-3 py-2 font-mono text-[12px] text-muted" title={e.hash}>{e.hash.slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <EmptyState title={t('log.empty')}>{t('log.emptyBody')}</EmptyState>}
    </Section>
  )
}
