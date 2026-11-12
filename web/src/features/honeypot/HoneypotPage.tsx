import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { FlaskConical } from 'lucide-react'
import { PageHeader, Section, Panel, KeyValue } from '@/components/common/PageHeader'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useModules } from '@/lib/modules'
import { useHits, useOverview, useSaveConfig, useTestHit, useToggleTrap } from './api'
import { hitName } from './hitName'
import { RespondLink } from './hitParts'
import DecoysSection from './Decoys'
import TokensSection from './Tokens'
import CoverageSection from './Coverage'
import type { Hit, HpOverview, HpService, Trap } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

export default function HoneypotPage() {
  const { t } = useTranslation('honeypot')
  // D-381: on a container-only install the module cannot run. Checked before RequireModule, whose "turn it on" would lead to a locked switch;
  // one turned on before shows why and how to turn it off, and no control that would do nothing.
  const hp = useModules().data?.modules.find((m) => m.id === 'honeypot')
  if (hp?.available === false) return (
    <>
      <PageHeader title={t('notHere.title')} stories={['S-HP-1', 'S-CORE-9']} />
      <EmptyState title={t('notHere.title')}>
        <p>{t('notHere.body')}</p>
        {hp.enabled ? <p className="mt-2"><Link className="text-accent underline-offset-4 hover:underline" to="/settings/modules">{t('notHere.modules')}</Link></p> : null}
      </EmptyState>
    </>
  )
  return <HoneypotBody />
}

function HoneypotBody() {
  const { t } = useTranslation('honeypot')
  const overview = useOverview()
  const hits = useHits()
  const o = overview.data
  const title = !o ? t('titleLoading')
    : !o.traps.some((x) => x.enabled) ? t('title.noTraps')
    : o.summary.today > 0 ? t('title.today', { count: o.summary.today })
    : o.summary.week > 0 ? t('title.week', { count: o.summary.week, when: fmtRelative(o.summary.last_hit_at), src: o.summary.last_src ?? '' })
    : t('title.quiet')
  return (
    <RequireModule module="honeypot">
      <PageHeader title={title} stories={['S-HP-1', 'S-HP-2']}
        meta={<span className="flex flex-wrap items-center gap-2"><SampleDataNote />{o ? t('meta', { time: fmtDateTime(o.updated_at) }) : null}</span>} />
      <QueryState query={overview}>
        {(data) => (
          <>
            {data.conflict_asset ? (
              <div role="alert" className="mb-6 rounded-md border border-danger/40 bg-danger-soft px-4 py-3 text-sm">
                <p className="font-medium text-danger">{t('conflict.title', { ip: data.secondary_ip })}</p>
                <p className="mt-1">{t('conflict.body', { name: data.conflict_asset.name })} <Link className="text-accent underline-offset-4 hover:underline" to={`/devices/${data.conflict_asset.id}`}>{t('conflict.open')}</Link></p>
              </div>
            ) : null}
            {!data.secondary_ip ? (
              <EmptyState title={t('start.title')}>
                <ol className="mt-1 grid list-decimal gap-1 pl-5">
                  <li>{t('start.step1', { lan: data.lan ?? t('lanUnknown') })}</li>
                  <li>{t('start.step2')}</li>
                  <li>{t('start.step3')}</li>
                </ol>
              </EmptyState>
            ) : null}
            <DecoySection data={data} />
            <TrapsSection data={data} />
            <DecoysSection hits={hits.data?.items ?? []} />
            <TokensSection />
            <ExclusionSection data={data} />
            <Section id="hits" title={t('hits.title')} description={t('hits.description')}>
              <QueryState query={hits}>{(h) => <HitsTable items={h.items} anyTrapOn={data.traps.some((x) => x.enabled)} />}</QueryState>
            </Section>
            <CoverageSection listening={data.traps.some((x) => x.state === 'listening')} />
          </>
        )}
      </QueryState>
    </RequireModule>
  )
}

function DecoySection({ data }: { data: HpOverview }) {
  const { t } = useTranslation('honeypot')
  const can = useCan('admin')
  const save = useSaveConfig()
  const [ip, setIp] = useState(data.secondary_ip ?? '')
  const [host, setHost] = useState(data.hostname)
  const [error, setError] = useState<{ field: 'ip' | 'host'; message: string } | null>(null)
  useEffect(() => { setIp(data.secondary_ip ?? ''); setHost(data.hostname) }, [data.secondary_ip, data.hostname])
  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    save.mutate({ secondary_ip: ip.trim(), hostname: host.trim() }, {
      onSuccess: () => toast.success(t('decoy.saved')),
      onError: (er) => {
        const field = er instanceof ApiError && /hostname/.test(er.code) ? 'host' : 'ip'
        setError({ field, message: errMsg(er) })
        document.getElementById(field === 'host' ? 'hp-host' : 'hp-ip')?.focus()
      },
    })
  }
  const dirty = ip.trim() !== (data.secondary_ip ?? '') || host.trim() !== data.hostname
  return (
    <Section id="decoy" title={t('decoy.title')} description={t('decoy.description', { lan: data.lan ?? t('lanUnknown') })}>
      <Panel className="p-4">
        <form onSubmit={submit} className="grid gap-4 sm:grid-cols-[1fr_1fr_auto] sm:items-start" noValidate>
          <Field label={t('decoy.ip')} htmlFor="hp-ip" hint={t('decoy.ipHint', { lan: data.lan ?? t('lanUnknown') })} error={error?.field === 'ip' ? error.message : undefined}>
            <Input id="hp-ip" value={ip} onChange={(e) => setIp(e.target.value)} disabled={!can} inputMode="decimal" autoComplete="off" aria-invalid={error?.field === 'ip' ? true : undefined} aria-describedby={error?.field === 'ip' ? 'hp-ip-error' : 'hp-ip-hint'} />
          </Field>
          <Field label={t('decoy.hostname')} htmlFor="hp-host" hint={t('decoy.hostnameHint')} error={error?.field === 'host' ? error.message : undefined}>
            <Input id="hp-host" value={host} onChange={(e) => setHost(e.target.value)} disabled={!can} autoComplete="off" spellCheck={false} maxLength={15} aria-invalid={error?.field === 'host' ? true : undefined} aria-describedby={error?.field === 'host' ? 'hp-host-error' : 'hp-host-hint'} />
          </Field>
          <Button type="submit" variant="primary" className="sm:mt-[26px]" disabled={!can || !dirty || save.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })}>
            {t('common:save')}
          </Button>
        </form>
        {!can ? <p className="mt-3 text-[13px] text-muted">{t('needAdmin')}</p> : null}
      </Panel>
    </Section>
  )
}

function TrapsSection({ data }: { data: HpOverview }) {
  const { t } = useTranslation('honeypot')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const toggle = useToggleTrap()
  const test = useTestHit()
  const svc = (s: HpService) => t(`service.${s}`)

  function flip(trap: Trap, enabled: boolean) {
    toggle.mutate({ service: trap.service, enabled }, {
      onSuccess: () => toast.success(t(enabled ? 'traps.enabledToast' : 'traps.disabledToast', { service: svc(trap.service) })),
      onError: (e) => toast.error(errMsg(e)),
    })
  }
  function doTest(trap: Trap) {
    test.mutate(trap.service, {
      onSuccess: () => toast.success(t('traps.testToast', { service: svc(trap.service) })),
      onError: (e) => toast.error(errMsg(e)),
    })
  }
  const noIp = !data.secondary_ip

  const stateChip = (tr: Trap) => tr.state === 'listening' ? <Chip tone="ok">{t('state.listening')}</Chip> : tr.state === 'conflict' ? <Chip tone="danger">{t('state.conflict')}</Chip> : <Chip tone="off">{noIp ? t('state.needIp') : t('state.off')}</Chip>
  const switchOf = (tr: Trap) => {
    const blocked = !admin ? t('common:needRole', { role: t('common:role.admin') }) : noIp && !tr.enabled ? t('traps.needIpReason') : undefined
    return <Switch checked={tr.enabled} disabled={!!blocked || toggle.isPending} title={blocked} aria-label={t('traps.switchLabel', { service: svc(tr.service) })} onCheckedChange={(v) => flip(tr, v)} />
  }
  const testBtn = (tr: Trap) => {
    const reason = !operator ? t('common:needRole', { role: t('common:role.operator') }) : !tr.enabled ? t('traps.testOffReason') : tr.state === 'conflict' ? t('traps.testConflictReason') : undefined
    return <Button size="sm" disabled={!!reason || test.isPending} title={reason} aria-label={t('traps.testLabel', { service: svc(tr.service) })} onClick={() => doTest(tr)}><FlaskConical />{t('traps.test')}</Button>
  }
  const columns: ColumnDef<Trap>[] = [
    { id: 'service', header: t('traps.col.service'), cell: ({ row }) => (
      <span className="grid"><span className="font-medium">{svc(row.original.service)}</span><span className="text-[12px] text-muted">{t(`serviceHint.${row.original.service}`)}</span></span>
    ) },
    { id: 'port', header: t('traps.col.port'), accessorFn: (r) => r.port, cell: ({ row }) => <span className="tabular-nums">{row.original.port}</span> },
    { id: 'state', header: t('traps.col.state'), cell: ({ row }) => stateChip(row.original) },
    { id: 'hits', header: t('traps.col.hits'), accessorFn: (r) => r.hits_7d, cell: ({ row }) => (
      <span className="grid"><span className="tabular-nums">{row.original.hits_7d}</span>{row.original.last_hit_at ? <span className="text-[12px] text-muted">{t('traps.lastHit', { when: fmtRelative(row.original.last_hit_at) })}</span> : null}</span>
    ) },
    { id: 'enabled', header: t('traps.col.enabled'), enableSorting: false, cell: ({ row }) => switchOf(row.original) },
    { id: 'test', header: t('traps.col.test'), enableSorting: false, cell: ({ row }) => testBtn(row.original) },
  ]
  return (
    <Section id="traps" title={t('traps.title')} description={t('traps.description')}>
      <DataTable caption={t('traps.caption')} data={data.traps} columns={columns} pageSize={10}
        mobileRow={(tr) => (
          <div className="grid gap-2">
            <div className="flex items-start justify-between gap-3">
              <span className="grid"><span className="font-medium">{svc(tr.service)} <span className="text-[12px] text-muted tabular-nums">{tr.port}</span></span><span className="text-[12px] text-muted">{t(`serviceHint.${tr.service}`)}</span></span>
              {switchOf(tr)}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="flex flex-wrap items-center gap-2">{stateChip(tr)}<span className="text-[13px] text-muted">{t('traps.col.hits')}: {tr.hits_7d}{tr.last_hit_at ? `, ${t('traps.lastHit', { when: fmtRelative(tr.last_hit_at) })}` : ''}</span></span>
              {testBtn(tr)}
            </div>
          </div>
        )} />
      <p className="mt-2 text-[13px] text-muted">{t('traps.testNote')}</p>
    </Section>
  )
}

function ExclusionSection({ data }: { data: HpOverview }) {
  const { t } = useTranslation('honeypot')
  return (
    <Section id="exclusion" title={t('exclusion.title')} description={t('exclusion.description')}>
      <Panel className="p-4">
        <KeyValue items={[
          { label: t('exclusion.who'), value: <span className="flex flex-wrap items-center gap-2">{data.box.name}{data.box.ip ? ` (${data.box.ip})` : ''} <Chip tone="off">{t('exclusion.locked')}</Chip></span> },
          { label: t('exclusion.why'), value: t('exclusion.whyBody') },
          { label: t('exclusion.ignored'), value: t('exclusion.ignoredBody', { count: data.ignored_7d }) },
        ]} />
      </Panel>
    </Section>
  )
}

export function HitsTable({ items, anyTrapOn = true }: { items: Hit[]; anyTrapOn?: boolean }) {
  const { t } = useTranslation('honeypot')
  const columns: ColumnDef<Hit>[] = [
    { id: 'ts', header: t('hits.col.time'), accessorFn: (r) => r.ts, cell: ({ row }) => (
      <Link className="whitespace-nowrap text-accent underline-offset-4 hover:underline" to={`/honeypot/hits/${row.original.id}`}>{fmtDateTime(row.original.ts)}</Link>
    ) },
    { id: 'service', header: t('hits.col.service'), accessorFn: (r) => hitName(t, r), cell: ({ row }) => (
      <span className="flex flex-wrap items-center gap-2">{hitName(t, row.original)} {row.original.port ? <span className="text-[12px] text-muted tabular-nums">{row.original.port}</span> : null}{row.original.kind === 'scan' ? <Chip tone="danger">{t('hits.kind.scan')}</Chip> : row.original.kind === 'token' ? <Chip tone="warn">{t('hits.kind.token')}</Chip> : null}{row.original.is_test ? <Chip tone="off">{t('hits.test')}</Chip> : null}</span>
    ) },
    { id: 'src', header: t('hits.col.src'), accessorFn: (r) => r.src_ip },
    { id: 'device', header: t('hits.col.device'), accessorFn: (r) => r.src_name ?? '', cell: ({ row }) => {
      const h = row.original
      if (h.src_asset_id && h.src_name) return <Link className="text-accent underline-offset-4 hover:underline" to={`/devices/${h.src_asset_id}`}>{h.src_name}</Link>
      return <span className="text-muted">{h.is_test ? t('hits.deviceBox') : t('hits.deviceUnknown')}</span>
    } },
    { id: 'excerpt', header: t('hits.col.excerpt'), enableSorting: false, accessorFn: (r) => r.excerpt, cell: ({ row }) => <span className="block max-w-xs truncate text-[13px] text-muted" title={row.original.excerpt}>{row.original.excerpt}</span> },
    { id: 'respond', header: t('hits.col.respond'), enableSorting: false, cell: ({ row }) => <RespondLink h={row.original} /> },
  ]
  return (
    <DataTable caption={t('hits.caption')} data={items} columns={columns}
      mobileRow={(h) => (
        <div className="grid gap-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Link className="font-medium text-accent underline-offset-4 hover:underline" to={`/honeypot/hits/${h.id}`}>{fmtDateTime(h.ts)}</Link>
            {h.is_test ? <Chip tone="off">{t('hits.test')}</Chip> : null}
          </div>
          <p className="text-sm">{hitName(t, h)} {h.port ? <span className="text-[12px] text-muted tabular-nums">{h.port}</span> : null}</p>
          <p className="text-[13px] text-muted">{h.src_ip} · {h.src_name ?? (h.is_test ? t('hits.deviceBox') : t('hits.deviceUnknown'))}</p>
          <RespondLink h={h} />
        </div>
      )}
      filterPlaceholder={t('hits.filter')} initialSort={[{ id: 'ts', desc: true }]}
      empty={<EmptyState title={t('hits.emptyTitle')}>{anyTrapOn ? t('hits.emptyBody') : t('hits.emptyBodyOff')}</EmptyState>} />
  )
}
