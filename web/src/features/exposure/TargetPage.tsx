import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, Pencil, Trash2 } from 'lucide-react'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { QueryState, RequireModule } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { ScheduleEditor } from '@/components/schedule/ScheduleEditor'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { isLive, useNode, useTree } from './api'
import { AnchorRedirect, ScrollToHash } from './anchors'
import { CommitmentPanel } from './CommitmentPanel'
import { InfoLine } from '@/components/common/InfoLine'
import { IssuesPanel } from './IssuesPanel'
import { NamesPanel } from './NamesPanel'
import { boxIp, needsProof } from './node'
import { ProofChip } from './NodeParts'
import { OutsidePanel } from './OutsidePanel'
import { ProofPanel } from './ProofPanel'
import { ScanBar, ScanButton, useScanFlow } from './ScanBar'
import { ScansPanel } from './ScansPanel'
import { ServicesPanel } from './ServicesPanel'
import { DeleteTargetDialog, EditTargetDialog } from './TargetDialogs'
import { TermsPanel } from './TermsPanel'
import type { TargetNode } from './types'

// Old #anchor → tab (before the tabs these were stacked blocks of one page).
const ANCHOR_TAB: Record<string, string> = { 'step-verify': 'ownership', 'step-commit': 'ownership', 'step-terms': 'ownership', outside: 'outside' }

// modules.md: the module's API is read only while the module is on.
export default function TargetPage() {
  return <RequireModule module="exposure" page><TargetLoader /></RequireModule>
}

function TargetLoader() {
  const { t } = useTranslation('exposure')
  const { id = '' } = useParams()
  const q = useNode(id)
  return (
    <>
      <Link to="/exposure" className="mb-3 inline-flex items-center gap-1 text-meta text-muted hover:text-ink"><ArrowLeft className="size-3.5" />{t('target.back')}</Link>
      <QueryState query={q}>{(n) => <TargetView node={n} />}</QueryState>
    </>
  )
}

/** When a scan of the node ends, its rows are read again: the services, names and issues it left. */
function useRowsAfterScan(node: TargetNode) {
  const qc = useQueryClient()
  const live = isLive(node.last_scan)
  const was = useRef(live)
  useEffect(() => {
    if (was.current && !live) void qc.invalidateQueries({ queryKey: ['exposure', 'rows', node.id] })
    was.current = live
  }, [live, node.id, qc])
}

/** A target that needs ownership proof opens on its Ownership tab: proving it is the one thing to do there. */
function useOwnershipFirst(node: TargetNode) {
  const [params, setParams] = useSearchParams()
  const first = useRef(true)
  useEffect(() => {
    if (!first.current) return
    first.current = false
    if (!params.get('tab') && needsProof(node)) { const p = new URLSearchParams(params); p.set('tab', 'ownership'); setParams(p, { replace: true }) }
  }, [node, params, setParams])
}

function TargetView({ node }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const nav = useNavigate()
  const tree = useTree()
  const items = tree.data?.items ?? []
  const parent = items.find((n) => n.id === node.parent_id)
  const [editing, setEditing] = useState(false)
  const [deleting, setDeleting] = useState(false)
  useRowsAfterScan(node)
  useOwnershipFirst(node)
  const flow = useScanFlow(node)
  const needAdmin = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const c = node.counts
  const title = !node.enabled ? t('target.title.off', { value: node.value })
    : needsProof(node) ? t('target.title.proof', { value: node.value })
    : c.issues > 0 ? t('target.title.issues', { value: node.value, count: c.issues })
    : c.services > 0 ? t('target.title.services', { value: node.value, count: c.services })
    : node.last_scan ? t('target.title.clean', { value: node.value }) : t('target.title.ready', { value: node.value })
  const domain = node.kind === 'domain'
  return (
    <>
      <PageHeader title={<span className="[overflow-wrap:anywhere]">{title}</span>} stories={['S-EXP-1']}
        meta={<span className="flex flex-wrap items-center gap-2">
          <ProofChip node={node} />
          {parent ? <span className="text-meta">{t('target.under')} <Link className="font-medium text-accent underline-offset-4 hover:underline" to={`/exposure/${encodeURIComponent(parent.id)}`}>{parent.value}</Link></span> : null}
          {node.scope_mode ? <span className="text-meta text-muted">{t(`scope.short.${node.scope_mode}`)}</span> : null}
          {!node.enabled ? <Chip tone="off">{t('tree.off')}</Chip> : null}
        </span>}
        actions={<>
          <ScanButton node={node} flow={flow} />
          <Button onClick={() => setEditing(true)} disabled={!admin} title={needAdmin}><Pencil />{t('edit.button')}</Button>
          <Button onClick={() => setDeleting(true)} disabled={!admin} title={needAdmin}><Trash2 />{t('delete.button')}</Button>
        </>} />
      <ScanBar node={node} flow={flow} />
      <ScanSchedule node={node} />
      <AnchorRedirect map={ANCHOR_TAB} />
      <ScrollToHash />
      <PageTabs label={t('tabs.label')} tabs={[
        { id: 'issues', label: t('tabs.issues'), badge: c.issues > 0 ? { count: c.issues, label: t('tabs.issuesCount'), tone: 'off' as const } : undefined, panel: <IssuesPanel node={node} /> },
        { id: 'services', label: t('tabs.services'), badge: c.services > 0 ? { count: c.services, label: t('tabs.servicesCount'), tone: 'off' as const } : undefined, panel: <ServicesPanel node={node} gateway={boxIp(node) ? tree.data?.gateway ?? null : null} /> },
        ...(domain ? [{ id: 'names', label: t('tabs.names'), panel: <NamesPanel node={node} onEdit={() => setEditing(true)} /> }] : []),
        { id: 'scans', label: t('tabs.scans'), panel: <ScansPanel node={node} /> },
        { id: 'ownership', label: t('tabs.ownership'), badge: needsProof(node) ? { count: 1, label: t('tabs.needsYou') } : undefined, panel: <>
          <Section id="step-verify" title={t('proof.title')} description={t(`proof.description.${domain ? 'domain' : boxIp(node) ? 'boxIp' : 'ip'}`)} info={t(`proof.descriptionInfo.${domain ? 'domain' : boxIp(node) ? 'boxIp' : 'ip'}`)}>
            <ProofPanel node={node} />
          </Section>
          {node.commitment ? (
            <Section id="step-commit" title={t('step.commit')} description={t('step.commitHint')} info={t('step.commitHintInfo')}>
              <CommitmentPanel consent={node.commitment} />
            </Section>
          ) : null}
          <Section id="step-terms" title={t('terms.title')} description={t('terms.description')}
            info={<><p>{t('terms.descriptionInfo')}</p><p>{t('terms.who')}</p><p>{t('terms.stops')}</p></>}>
            <TermsPanel node={node} />
          </Section>
        </> },
        ...(node.kind === 'ip' ? [{ id: 'outside', label: t('tabs.outsideView'), panel: <OutsidePanel node={node} /> }] : []),
      ]} />
      {!operator ? <InfoLine className="mt-4 max-w-3xl text-meta text-muted" topic={t('target.accessTopic')} info={t('target.viewOnlyInfo')}>{t('target.viewOnly')}</InfoLine> : null}
      <EditTargetDialog node={node} open={editing} onOpenChange={setEditing} />
      <DeleteTargetDialog node={node} items={items} open={deleting} onOpenChange={setDeleting} onDone={() => void nav('/exposure')} />
    </>
  )
}

/**
 * How often the box scans the target by itself: the shared schedule editor on the target's schedule (exposure.target:<id>), with the
 * preview of the next starts, the pause and the window. Scan now is the page's own button, so the editor has no Run now of its own.
 */
function ScanSchedule({ node }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  return (
    <section aria-label={t('schedule.name', { value: node.value })} className="grid gap-1">
      <ScheduleEditor ownerKey={node.schedule_key} name={t('schedule.name', { value: node.value })} runNow={false} />
      {!node.deep ? <p className="text-meta text-muted">{t('schedule.needsTerms')}</p> : null}
    </section>
  )
}
