// AI proposals (S-MIT-1): what the AI proposed about possible CVEs the vendor advisories could not decide. Nothing changes until a
// person confirms: each row says the device, the software and version, the CVE, the verdict and how sure the box is of it
// ("Confident" only when the AI's quote is in the page word for word and names a release range of this version's line), the quoted
// sentence and the pages. Confirm one, confirm a whole class at once (never an exploited CVE proposed not affected: one by one), or
// reject (the CVE is possible again). GET /findings/possible?state=proposal.
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ChevronDown } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ExpandToggle, ListRow, LeadSpacer } from '@/components/common/ListParts'
import { EmptyState, QueryState } from '@/components/common/States'
import { SeverityBadge } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { useCan } from '@/lib/session'
import { useAllPossible, useConfirmProposals } from './api'
import { errMsg } from './errors'
import { DeviceLine } from './parts'
import { CheckChip, CheckDetails, ExploitedChip, ProposalActions } from './Possible'
import type { PossibleRow } from './types'

type Verdict = 'affected' | 'not_affected'
type Confidence = 'confident' | 'likely'
type Klass = { verdict: Verdict; confidence: Confidence }
const CLASSES: Klass[] = [
  { verdict: 'affected', confidence: 'confident' }, { verdict: 'affected', confidence: 'likely' },
  { verdict: 'not_affected', confidence: 'confident' }, { verdict: 'not_affected', confidence: 'likely' },
]
const classOf = (r: PossibleRow): number => CLASSES.findIndex((c) => c.verdict === r.check?.verdict && c.confidence === (r.check?.confidence ?? 'likely'))

/** One proposal: the CVE and what the AI proposes, the device and software, the quoted sentence; the pages behind one click. */
function ProposalRow({ r }: { r: PossibleRow }) {
  const { t } = useTranslation('findings')
  const [open, setOpen] = useState(false)
  const check = r.check!
  const panel = `proposal-${`${r.id}-${r.cve}`.replace(/[^\w-]/g, '_')}`
  return (
    <ListRow label={t('proposals.rowOf', { cve: r.cve, device: r.device.name })}
      lead={<LeadSpacer />}
      title={<>
        <Link to={`/cve/${encodeURIComponent(r.cve)}`} className="font-semibold text-accent underline-offset-4 hover:underline">{r.cve}</Link>
        <SeverityBadge severity={r.severity} compact />
        {r.exploited ? <ExploitedChip /> : null}
        <CheckChip check={check} />
      </>}
      meta={[
        <><DeviceLine device={r.device} badge={false} />{r.software ? <span className="[overflow-wrap:anywhere]">{r.software.version ? `${r.software.name} ${r.software.version}` : r.software.name}</span> : null}</>,
        check.quote ? <span className="italic text-ink [overflow-wrap:anywhere]">“{check.quote}”</span> : check.reason,
        !r.bulk ? <span>{t('proposals.oneByOne')}</span> : null,
      ]}
      actions={<>
        <ExpandToggle open={open} onToggle={() => setOpen((o) => !o)} controls={panel} label={t('possible.detail.toggleOf', { cve: r.cve })}>{t('possible.detail.toggle')}</ExpandToggle>
        <ProposalActions r={r} />
      </>}>
      {open ? <div id={panel}><CheckDetails check={check} /></div> : null}
    </ListRow>
  )
}

/** Confirm every proposal of one class at once: a menu of the classes that have rows that may be confirmed together, then a dialog
 *  that says how many and what it records. */
function ConfirmClass({ rows }: { rows: PossibleRow[] }) {
  const { t } = useTranslation('findings')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const confirm = useConfirmProposals()
  const [asking, setAsking] = useState<Klass | null>(null)
  const counts = CLASSES.map((c) => rows.filter((r) => r.bulk && r.check?.verdict === c.verdict && (r.check?.confidence ?? 'likely') === c.confidence).length)
  const any = counts.some((n) => n > 0)
  if (!any) return null
  const n = asking ? counts[CLASSES.indexOf(asking)]! : 0
  const send = (c: Klass) => confirm.mutate({ verdict: c.verdict, confidence: c.confidence }, {
    onSuccess: (r) => { toast.success(t('proposals.classDone', { count: r.confirmed })); setAsking(null) },
    onError: (e) => toast.error(errMsg(e)),
  })
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="sm" disabled={!operator} title={operator ? undefined : t('common:needRole', { role: t('common:role.operator') })}>{t('proposals.confirmClass')}<ChevronDown /></Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          {CLASSES.map((c, i) => counts[i] ? (
            <DropdownMenuItem key={`${c.verdict}-${c.confidence}`} disabled={c.verdict === 'affected' && !admin}
              title={c.verdict === 'affected' && !admin ? t('common:needRole', { role: t('common:role.admin') }) : undefined}
              onSelect={() => setAsking(c)}>{t(`proposals.class_${c.verdict}_${c.confidence}`, { count: counts[i] })}</DropdownMenuItem>
          ) : null)}
        </DropdownMenuContent>
      </DropdownMenu>
      {asking ? (
        <Dialog open onOpenChange={(o) => { if (!o) setAsking(null) }}>
          <DialogContent title={t(`proposals.classTitle_${asking.verdict}`, { count: n, confidence: t(`proposals.${asking.confidence}`) })} description={t(`proposals.classBody_${asking.verdict}`, { count: n })}>
            {asking.verdict === 'not_affected' ? <p className="text-sm text-muted">{t('proposals.classExploited')}</p> : null}
            <DialogFooter>
              <Button onClick={() => setAsking(null)}>{t('common:cancel')}</Button>
              <Button variant="primary" busy={confirm.isPending} busyLabel={t('common:busy.saving')}
                onClick={() => send(asking)}>{t('proposals.classSubmit', { count: n })}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  )
}

export function ProposalsTab() {
  const { t } = useTranslation('findings')
  const q = useAllPossible({ state: 'proposal' })
  // exploited first, then by class (affected before not affected, confident before likely), then the CVE
  const rows = useMemo(() => [...(q.data?.items ?? [])].filter((r) => r.check).sort((a, b) => Number(b.exploited) - Number(a.exploited) || classOf(a) - classOf(b) || a.cve.localeCompare(b.cve)), [q.data])
  const columns: ColumnDef<PossibleRow>[] = [
    { id: 'text', header: t('proposals.col'), accessorFn: (r) => [r.cve, r.device.name, r.device.ip ?? '', r.software?.name ?? '', r.check?.quote ?? ''].join(' ') },
  ]
  return (
    <QueryState query={q}>
      {() => !rows.length ? (
        <EmptyState title={t('proposals.empty')}>{t('proposals.emptyBody')}</EmptyState>
      ) : (
        <DataTable urlKey="proposals" caption={t('proposals.caption')} data={rows} columns={columns} pageSize={50} list={(r) => <ProposalRow r={r} />}
          summary={t('proposals.summary', { count: rows.length, affected: rows.filter((r) => r.check!.verdict === 'affected').length, not: rows.filter((r) => r.check!.verdict === 'not_affected').length })}
          actions={<ConfirmClass rows={rows} />} />
      )}
    </QueryState>
  )
}
