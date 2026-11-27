import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { CornerDownRight } from 'lucide-react'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { KpiStrip, PageTabs } from '@/components/common/PageFrame'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { InfoTip } from '@/components/common/InfoTip'
import { DependencyLink } from '@/components/common/DependencyLink'
import { fmtRelative } from '@/lib/format'
import { AnchorRedirect, ScrollToHash } from './anchors'
import { BoxIpPanel } from './BoxIpPanel'
import { GreenboneSetting } from './GreenbonePanel'
import { InfoLine } from '@/components/common/InfoLine'
import { IssuesCell, ProofChip, ScanCell, ServicesCell } from './NodeParts'
import { AddTargetDialog } from './TargetDialogs'
import { useTree } from './api'
import { depths, proven } from './node'
import type { TargetNode } from './types'

// Old #anchor → tab: before the tabs these were stacked blocks of one page.
const ANCHOR_TAB: Record<string, string> = { targets: 'targets', 'box-ip': 'settings', 'box-ignored': 'settings', greenbone: 'settings' }

// modules.md: the module's API is read only while the module is on; off, the page says so and calls nothing.
export default function ExposurePage() {
  return <RequireModule module="exposure" page><ExposureView /></RequireModule>
}

function ExposureView() {
  const { t } = useTranslation('exposure')
  const q = useTree()
  const items = q.data?.items
  const sum = (f: (n: TargetNode) => number) => items?.reduce((a, n) => a + f(n), 0) ?? 0
  const issues = sum((n) => n.counts.issues)
  const services = sum((n) => n.counts.services)
  const waiting = items?.filter((n) => n.enabled && !proven(n)).length ?? 0
  const scanned = items?.some((n) => n.last_scan) ?? false
  // The first sentence says what is open, then what waits on a person, then that nothing was found.
  const status = !items ? null
    : items.length === 0 ? t('title.none')
    : issues > 0 ? t('title.issues', { count: issues })
    : services > 0 ? t('title.services', { count: services })
    : waiting > 0 ? t('title.pending', { count: waiting })
    : scanned ? t('title.clean') : t('title.ready', { count: items.length })
  return (
    <>
      <PageHeader title={t('common:shell.exposure')} stories={['S-EXP-1']} info={<p>{t('rule')}</p>}
        meta={<span className="flex flex-wrap items-center gap-2">{status}<SampleDataNote /></span>} />
      <AnchorRedirect map={ANCHOR_TAB} />
      <QueryState query={q}>
        {(d) => {
          const last = d.items.map((n) => n.last_scan?.started_at).filter((x): x is string => !!x).sort().at(-1)
          const kpis = d.items.length > 0 ? [
            { value: d.items.length, label: t('kpi.targets', { count: d.items.length }), to: '?tab=targets' },
            { value: services, label: t('kpi.services', { count: services }), to: '?tab=targets' },
            { value: issues, label: t('kpi.issues', { count: issues }), to: '?tab=targets' },
            { value: last ? fmtRelative(last) : t('kpi.never'), label: t('kpi.scan'), to: '?tab=targets' },
          ] : []
          return (
            <>
              <ScrollToHash />
              {kpis.length ? <KpiStrip label={t('kpi.label')} items={kpis} /> : null}
              <PageTabs label={t('tabs.label')} tabs={[
                { id: 'targets', label: t('tabs.targets'), panel: <TargetTree items={d.items} /> },
                { id: 'settings', label: t('tabs.settings'), panel: <>
                  <BoxIpPanel settings={d.box_ip} ignored={d.ignored} />
                  <GreenboneSetting />
                  <Section id="scan-settings" title={t('settings.scanTitle')} description={t('settings.scanDescription')}>
                    <DependencyLink reason={t('settings.scanReason')} to="/settings/scanning" label={t('settings.scanLink')} />
                  </Section>
                </> },
              ]} />
            </>
          )
        }}
      </QueryState>
    </>
  )
}

const INDENT = ['', 'ps-5', 'ps-10', 'ps-14', 'ps-16']

/** The value of a node in the tree: indented under its parent, which a screen reader hears as "under <parent>". */
function NodeName({ n, depth, parent }: { n: TargetNode; depth: number; parent?: string }) {
  const { t } = useTranslation('exposure')
  return (
    <span className={`flex min-w-0 items-start gap-1 ${INDENT[Math.min(depth, INDENT.length - 1)]}`}>
      {depth > 0 ? <CornerDownRight aria-hidden className="mt-0.5 size-3.5 shrink-0 text-muted" /> : null}
      <span className="grid min-w-0 gap-0.5">
        <Link className="break-all font-medium text-accent underline-offset-4 hover:underline" to={`/exposure/${encodeURIComponent(n.id)}`}>{n.value}</Link>
        {parent ? <span className="sr-only">{t('tree.under', { parent })}</span> : null}
        <span className="flex flex-wrap gap-1">
          {n.kind === 'ip' ? <Chip tone="off">{t(n.origin === 'box' ? 'tree.boxIp' : 'kind.ip')}</Chip> : null}
          {!n.enabled ? <Chip tone="off">{t('tree.off')}</Chip> : null}
        </span>
      </span>
    </span>
  )
}

/**
 * The targets as a tree: a name under a domain target sits under it, with whose proof covers it. The server sends the tree order
 * (each node right after its parent), so the table keeps it: no column sorts it into another order.
 */
function TargetTree({ items }: { items: TargetNode[] }) {
  const { t } = useTranslation('exposure')
  const depth = depths(items)
  const byId = new Map(items.map((n) => [n.id, n]))
  const parentOf = (n: TargetNode) => (n.parent_id ? byId.get(n.parent_id)?.value : undefined)
  const columns: ColumnDef<TargetNode>[] = [
    { id: 'value', header: t('tree.col.target'), enableSorting: false, accessorFn: (r) => r.value, cell: ({ row }) => <NodeName n={row.original} depth={depth.get(row.original.id) ?? 0} parent={parentOf(row.original)} /> },
    { id: 'proof', header: t('tree.col.proof'), enableSorting: false, cell: ({ row }) => <ProofChip node={row.original} linkParent={false} /> },
    { id: 'scope', header: t('tree.col.scope'), enableSorting: false, cell: ({ row }) => <span className="text-meta">{row.original.scope_mode ? t(`scope.short.${row.original.scope_mode}`) : '—'}</span> },
    { id: 'scan', header: t('tree.col.scan'), enableSorting: false, cell: ({ row }) => <ScanCell node={row.original} /> },
    { id: 'services', header: t('tree.col.services'), enableSorting: false, cell: ({ row }) => <ServicesCell node={row.original} /> },
    { id: 'issues', header: t('tree.col.issues'), enableSorting: false, cell: ({ row }) => <IssuesCell node={row.original} /> },
  ]
  return (
    <section id="targets" aria-label={t('tree.title')}>
      <DataTable urlKey="exposure-tree" caption={t('tree.caption')} data={items} columns={columns} pageSize={50}
        actions={<AddTargetDialog items={items} />}
        summary={items.length ? <>{t('tree.summary', { count: items.length })}<InfoTip topic={t('tree.title')}><p>{t('tree.description')}</p><p>{t('tree.descriptionInfo')}</p></InfoTip></> : null}
        mobileRow={(n) => (
          <div className="grid gap-1.5">
            <NodeName n={n} depth={depth.get(n.id) ?? 0} parent={parentOf(n)} />
            <div className="flex flex-wrap items-center gap-2"><ProofChip node={n} linkParent={false} /></div>
            <ScanCell node={n} />
            <p className="text-meta">{t('tree.mobileCounts', { services: n.counts.services, issues: n.counts.issues })}</p>
          </div>
        )}
        empty={<EmptyState title={t('tree.emptyTitle')}><InfoLine topic={t('tree.emptyTitle')} info={t('tree.emptyBodyInfo')}>{t('tree.emptyBody')}</InfoLine></EmptyState>} />
    </section>
  )
}
