import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { FlaskConical } from 'lucide-react'
import { Notice, PageHeader, Section, KeyValue } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { DependencyLink } from '@/components/common/DependencyLink'
import { KpiStrip, PageTabs } from '@/components/common/PageFrame'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Button } from '@/components/ui/button'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useModules } from '@/lib/modules'
import { useHits, useOverview, useTestHit, useTokens } from './api'
import { hitName } from './hitName'
import { RespondLink } from './hitParts'
import { notOffered } from '@/lib/v1'
import TrapIpsTab from './TrapIps'
import TokensSection from './Tokens'
import CoverageSection from './Coverage'
import { portLabel } from './presets'
import { TrapStateChip } from './TrapStateChip'
import type { Hit, HpOverview, HpService, Trap } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

export default function HoneypotPage() {
  const { t } = useTranslation('honeypot')
  // On a container-only install the module cannot run. Checked before RequireModule, whose "turn it on" would lead to a locked switch;
  // one turned on before shows why and how to turn it off, and no control that would do nothing.
  const hp = useModules().data?.modules.find((m) => m.id === 'honeypot')
  if (hp?.available === false) return (
    <>
      <PageHeader title={t('notHere.page')} stories={['S-HP-1', 'S-CORE-9']} />
      <EmptyState title={t('notHere.title')} info={t('notHere.bodyInfo')}>
        {t('notHere.body')}
        {hp.enabled ? <DependencyLink className="mt-2" reason={t('notHere.modulesWhy')} to="/settings/modules#module-honeypot" label={t('notHere.modules')} /> : null}
      </EmptyState>
    </>
  )
  return <RequireModule module="honeypot" page><HoneypotBody /></RequireModule>
}

// Mounted only once GET /modules says the module is on (RequireModule): its reads never go to a route that is not there (404s on container-only).
// Page frame: header, KPI strip, tabs in ?tab=.
function HoneypotBody() {
  const { t } = useTranslation('honeypot')
  const overview = useOverview()
  const hits = useHits()
  const o = overview.data
  const title = !o ? t('titleLoading')
    : o.trap_ips.enabled === 0 ? t('title.noTraps')
    : o.problem ? t('title.failed')
    : o.trap_ips.listening === 0 && o.traps.some((x) => x.state === 'starting') ? t('title.starting')
    : o.summary.today > 0 ? t('title.today', { count: o.summary.today })
    : o.summary.week > 0 ? t('title.week', { count: o.summary.week, when: fmtRelative(o.summary.last_hit_at), src: o.summary.last_src ?? '' })
    : t('title.quiet')
  return (
    <>
      <PageHeader title={title} stories={['S-HP-1', 'S-HP-2']} info={t('metaInfo')}
        meta={<span className="flex flex-wrap items-center gap-2"><SampleDataNote />{o ? t('meta', { time: fmtDateTime(o.updated_at) }) : null}</span>} />
      <QueryState query={overview}>
        {(data) => {
          const lan = data.lan ?? t('lanUnknown')
          return (
            <>
              {data.trap_ips.total > 0 ? (
                <KpiStrip label={t('kpi.label')} items={[
                  { value: `${data.trap_ips.listening} / ${data.trap_ips.enabled}`, label: t('kpi.listening'), to: '?tab=trap-ips' },
                  { value: data.summary.today, label: t('kpi.today'), to: '?tab=hits' },
                  { value: data.summary.week, label: t('kpi.week'), to: '?tab=hits' },
                ]} />
              ) : null}
              {data.problem ? (
                <Notice tone="danger" role="alert" title={t('problem.title')}>{t('problem.body', { reason: data.problem.replace(/[.\s]+$/, '') })}</Notice>
              ) : null}
              <PageTabs label={t('tabs.label')} tabs={[
                { id: 'overview', label: t('tabs.overview'), panel: <OverviewTab data={data} lan={lan} /> },
                { id: 'trap-ips', label: t('tabs.trapIps'), panel: <TrapIpsTab hits={hits.data?.items ?? []} lan={lan} lanKnown={!!data.lan} smbName={data.smb_name} />, badge: { count: data.trap_ips.failing, label: t('tabs.attention') } },
                { id: 'services', label: t('tabs.services'), panel: <ServicesTab data={data} /> },
                { id: 'tokens', label: t('tabs.tokens'), panel: <TokensSection /> },
                { id: 'hits', label: t('tabs.hits'), panel: (
                  <Section id="hits" title={t('hits.title')} description={t('hits.description')} info={t('hits.descriptionInfo')}>
                    <QueryState query={hits}>{(h) => <HitsTable items={h.items} anyTrapOn={data.trap_ips.enabled > 0} />}</QueryState>
                  </Section>
                ) },
              ]} />
            </>
          )
        }}
      </QueryState>
    </>
  )
}

function OverviewTab({ data, lan }: { data: HpOverview; lan: string }) {
  const { t } = useTranslation('honeypot')
  const admin = useCan('admin') // #trap-ip-add is an administrator's button: anyone else lands on the tab (#875)
  const tokens = useTokens()
  return (
    <>
      {data.trap_ips.total === 0 ? (
        <EmptyState title={t('start.title')} info={t('start.info', { lan })} action={<Link className="text-sm font-medium text-accent underline underline-offset-4" to={admin ? '?tab=trap-ips#trap-ip-add' : '?tab=trap-ips'}>{t('start.action')}</Link>}>
          <ol className="mt-1 grid list-decimal gap-1 pl-5">
            <li>{t('start.step1', { lan })}</li>
            <li>{t('start.step2')}</li>
            <li>{t('start.step3')}</li>
          </ol>
        </EmptyState>
      ) : null}
      <ExclusionSection data={data} />
      <CoverageSection services={data.traps.filter((tr) => tr.state === 'listening').map((tr) => tr.service)} listeningIps={data.trap_ips.listening}
        bait={tokens.data?.items.filter((k) => k.type === 'file' || k.type === 'url').length} admin={admin} />
    </>
  )
}

function ServicesTab({ data }: { data: HpOverview }) {
  const { t } = useTranslation('honeypot')
  const operator = useCan('operator')
  const test = useTestHit()
  const svc = (s: HpService) => t(`service.${s}`)

  function doTest(trap: Trap) {
    test.mutate(trap.service, {
      onSuccess: () => toast.success(t('traps.testToast', { service: svc(trap.service) })),
      onError: (e) => toast.error(errMsg(e)),
    })
  }
  const stateChip = (tr: Trap) => <TrapStateChip state={tr.state}>{tr.state === 'off' && !tr.enabled ? t('state.none') : undefined}</TrapStateChip>
  const where = (tr: Trap) => (tr.trap_ips.length ? tr.trap_ips.join(', ') : <span className="text-muted">{t('traps.noTrapIp')}</span>)
  const testBtn = (tr: Trap) => {
    const reason = !operator ? t('common:needRole', { role: t('common:role.operator') }) : !tr.enabled ? t('traps.testOffReason') : tr.state === 'conflict' ? t('traps.testConflictReason') : undefined
    return <Button size="sm" disabled={!!reason || test.isPending} busy={test.isPending && test.variables === tr.service} busyLabel={t('common:busy.testing')} title={reason} aria-label={t('traps.testLabel', { service: svc(tr.service) })} onClick={() => doTest(tr)}><FlaskConical />{t('traps.test')}</Button>
  }
  const columns: ColumnDef<Trap>[] = [
    { id: 'service', header: t('traps.col.service'), cell: ({ row }) => (
      <span className="grid"><span className="font-medium">{svc(row.original.service)}</span><span className="text-caption text-muted">{t(`serviceHint.${row.original.service}`)}</span></span>
    ) },
    { id: 'port', header: t('traps.col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="tabular-nums">{portLabel(row.original.service)}</span> },
    { id: 'where', header: t('traps.col.trapIps'), enableSorting: false, cell: ({ row }) => <span className="text-meta">{where(row.original)}</span> },
    { id: 'state', header: t('traps.col.state'), cell: ({ row }) => stateChip(row.original) },
    { id: 'hits', header: t('traps.col.hits'), accessorFn: (r) => r.hits_7d, cell: ({ row }) => (
      <span className="grid"><span className="tabular-nums">{row.original.hits_7d}</span>{row.original.last_hit_at ? <span className="text-caption text-muted">{t('traps.lastHit', { when: fmtRelative(row.original.last_hit_at) })}</span> : null}</span>
    ) },
    { id: 'test', header: t('traps.col.test'), enableSorting: false, cell: ({ row }) => testBtn(row.original) },
  ]
  return (
    <>
      <Section id="services" title={t('traps.title')} description={t('traps.description')} info={<><p>{t('traps.descriptionInfo')}</p><p>{t('traps.testNote')}</p></>}>
        <DataTable urlKey="honeypot-traps" caption={t('traps.caption')} data={data.traps} columns={columns} pageSize={data.traps.length}
          mobileRow={(tr) => (
            <div className="grid gap-2">
              <span className="grid"><span className="font-medium">{svc(tr.service)} <span className="text-caption text-muted tabular-nums">{portLabel(tr.service)}</span></span><span className="text-caption text-muted">{t(`serviceHint.${tr.service}`)}</span></span>
              <span className="text-meta">{t('traps.col.trapIps')}: {where(tr)}</span>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="flex flex-wrap items-center gap-2">{stateChip(tr)}<span className="text-meta text-muted">{t('traps.col.hits')}: {tr.hits_7d}{tr.last_hit_at ? `, ${t('traps.lastHit', { when: fmtRelative(tr.last_hit_at) })}` : ''}</span></span>
                {testBtn(tr)}
              </div>
            </div>
          )} />
      </Section>
      <Section id="limits" title={t('traps.limitsTitle')} info={<>
        {data.smb_name ? <p>{t('traps.smbNameInfo')}</p> : null}
        {data.http_page ? <p>{t('traps.httpPageInfo')}</p> : null}
        <p>{t('traps.bannersInfo')}</p>
      </>}>
        <Card className="grid gap-1.5 text-sm">
          <p>{data.smb_name ? t('traps.smbName', { name: data.smb_name }) : t('traps.smbNone')}</p>
          <p>{data.http_page ? t('traps.httpPage', { page: t(`traps.page.${data.http_page}`) }) : t('traps.httpNone')}</p>
          <p>{t('traps.banners')}</p>
        </Card>
      </Section>
    </>
  )
}

function ExclusionSection({ data }: { data: HpOverview }) {
  const { t } = useTranslation('honeypot')
  return (
    <Section id="exclusion" title={t('exclusion.title')} description={t('exclusion.description')} info={t('exclusion.descriptionInfo')}>
      <Card>
        <KeyValue items={[
          { label: t('exclusion.who'), value: <span className="flex flex-wrap items-center gap-2">{data.box.name}{data.box.ip ? ` (${data.box.ip})` : ''} <Chip tone="off">{t('exclusion.locked')}</Chip></span> },
          { label: t('exclusion.why'), value: t('exclusion.whyBody') },
          { label: t('exclusion.ignored'), value: t('exclusion.ignoredBody', { count: data.ignored_7d }) },
        ]} />
      </Card>
    </Section>
  )
}

export function HitsTable({ items, anyTrapOn = true }: { items: Hit[]; anyTrapOn?: boolean }) {
  const { t } = useTranslation('honeypot')
  const admin = useCan('admin')
  const respond = !notOffered('response') // Respond starts a new action: none while this build does not offer the response module, even on a box that has it on
  const columns: ColumnDef<Hit>[] = [
    { id: 'ts', header: t('hits.col.time'), accessorFn: (r) => r.ts, cell: ({ row }) => (
      <Link className="whitespace-nowrap text-accent underline-offset-4 hover:underline" to={`/honeypot/hits/${row.original.id}`}>{fmtDateTime(row.original.ts)}</Link>
    ) },
    { id: 'service', header: t('hits.col.service'), accessorFn: (r) => hitName(t, r), cell: ({ row }) => (
      <span className="flex flex-wrap items-center gap-2">{hitName(t, row.original)} {row.original.port ? <span className="text-caption text-muted tabular-nums">{row.original.port}</span> : null}{row.original.kind === 'scan' ? <Chip tone="danger">{t('hits.kind.scan')}</Chip> : row.original.kind === 'token' ? <Chip tone="warn">{t('hits.kind.token')}</Chip> : null}{row.original.is_test ? <Chip tone="off">{t('hits.test')}</Chip> : null}</span>
    ) },
    // Which Trap IP was hit (a scan: the ones it touched; a token: the token).
    { id: 'trap', header: t('hits.col.trapIp'), accessorFn: (r) => `${r.trap_hostname} ${r.trap_ip}`, cell: ({ row }) => (
      <span className="grid max-w-64"><span className="truncate" title={row.original.trap_hostname}>{row.original.trap_hostname || row.original.trap_ip}</span>{row.original.kind === 'service' && row.original.trap_hostname ? <span className="text-caption text-muted tabular-nums">{row.original.trap_ip}</span> : null}</span>
    ) },
    { id: 'src', header: t('hits.col.src'), accessorFn: (r) => r.src_ip },
    { id: 'device', header: t('hits.col.device'), accessorFn: (r) => r.src_name ?? '', cell: ({ row }) => {
      const h = row.original
      if (h.src_asset_id && h.src_name) return <Link className="text-accent underline-offset-4 hover:underline" to={`/devices/${h.src_asset_id}`}>{h.src_name}</Link>
      return <span className="text-muted">{h.is_test ? t('hits.deviceBox') : t('hits.deviceUnknown')}</span>
    } },
    { id: 'excerpt', header: t('hits.col.excerpt'), enableSorting: false, accessorFn: (r) => r.excerpt, cell: ({ row }) => <span className="block max-w-xs truncate text-meta text-muted" title={row.original.excerpt}>{row.original.excerpt}</span> },
    ...(respond ? [{ id: 'respond', header: t('hits.col.respond'), enableSorting: false, cell: ({ row }) => <RespondLink h={row.original} /> } satisfies ColumnDef<Hit>] : []),
  ]
  // UI.md §6: no hit at all yet is "nothing yet" (the drawing, and the way to the step it waits for); the table's own filter keeps its text-only state.
  if (items.length === 0) return (
    <EmptyState art="no-alerts" title={t('hits.emptyTitle')} info={anyTrapOn ? t('hits.emptyBodyInfo') : t('hits.emptyBodyOffInfo')}
      action={<Link className="text-sm font-medium text-accent underline underline-offset-4" to={anyTrapOn ? '?tab=services#services' : admin ? '?tab=trap-ips#trap-ip-add' : '?tab=trap-ips'}>{anyTrapOn ? t('hits.emptyActionTest') : t('hits.emptyActionAdd')}</Link>}>
      {anyTrapOn ? t('hits.emptyBody') : t('hits.emptyBodyOff')}
    </EmptyState>
  )
  return (
    <DataTable urlKey="honeypot-hits" caption={t('hits.caption')} data={items} columns={columns}
      mobileRow={(h) => (
        <div className="grid gap-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Link className="font-medium text-accent underline-offset-4 hover:underline" to={`/honeypot/hits/${h.id}`}>{fmtDateTime(h.ts)}</Link>
            {h.is_test ? <Chip tone="off">{t('hits.test')}</Chip> : null}
          </div>
          <p className="text-sm">{hitName(t, h)} {h.port ? <span className="text-caption text-muted tabular-nums">{h.port}</span> : null}</p>
          <p className="text-meta">{t('hits.col.trapIp')}: {h.trap_hostname || h.trap_ip}{h.kind === 'service' && h.trap_hostname ? <span className="text-muted tabular-nums"> {h.trap_ip}</span> : null}</p>
          <p className="text-meta text-muted">{h.src_ip} · {h.src_name ?? (h.is_test ? t('hits.deviceBox') : t('hits.deviceUnknown'))}</p>
          {respond ? <RespondLink h={h} /> : null}
        </div>
      )}
      filterPlaceholder={t('hits.filter')} initialSort={[{ id: 'ts', desc: true }]} />
  )
}
