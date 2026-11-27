import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { InfoTip } from '@/components/common/InfoTip'
import { Switch } from '@/components/ui/switch'
import { useFeedSources, hostOf } from '@/features/feeds/api'
import { useInstallKind, useModuleEnabled } from '@/lib/modules'
import { useScope } from '@/lib/v1'
import { usePrivacy, useSavePrivacy } from './api'
import { errMsg, ReadOnlyNote, useGate } from './parts'
import type { PrivacyFlow, PrivacyState } from './types'

// Flow 1 names the hosts of the custom feeds on the box, read from the same list as Settings → Feeds → "Where this box connects". Only mounted when the feeds module is on.
function CustomFeedHosts() {
  const { t } = useTranslation('core')
  const { data } = useFeedSources()
  if (!data) return null
  const hosts = [...new Set(data.items.filter((f) => !f.builtin && f.enabled).map((f) => hostOf(f.url)))]
  return <span className="mt-1 block">{hosts.length ? t('privacy.flow.1.custom', { hosts: hosts.join(', ') }) : t('privacy.flow.1.customNone')}</span>
}

// The twelve data flows that leave the box, exactly as in PRIVACY.md. A new flow = change PRIVACY.md + this table in the same commit (legal rule).
function Body({ d }: { d: PrivacyState }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const feedsOn = useModuleEnabled('feeds')
  // S-CORE-4: a container-only install has no vedette-host, apt, scan image build or chrony; flows 6 and 10 then
  // read as the container-only rows of PRIVACY.md. undefined while GET /modules loads: the appliance text.
  const container = useInstallKind() === 'container'
  const oidcShown = useScope('auth-oidc') !== 'hidden' // post-v1: its switch is not on Settings, Modules in a v1 build
  const mcpShown = useScope('mcp-server') !== 'hidden' // No link to a Settings page this build does not offer
  const txt = (id: number, part: 'what' | 'to' | 'control') => t(container && (id === 6 || id === 10) ? `privacy.flow.${id}.container.${part}` : `privacy.flow.${id}.${part}`)
  // #824: a long cell shows its one-line summary (privacy.flowShort) and the full PRIVACY.md text behind ⓘ; the full text stays
  // word for word as PRIVACY.md (privacyFlows.test.ts) and is also the button's accessible description.
  const brief = (id: number, part: 'what' | 'to' | 'control', full: ReactNode) => {
    const short = t(container && (id === 6 || id === 10) ? `privacy.flowShort.${id}.container.${part}` : `privacy.flowShort.${id}.${part}`, { defaultValue: '' })
    if (!short) return full
    return (
      <span className="flex items-start gap-1">
        <span>{short}</span>
        <InfoTip topic={t('privacy.flowFull', { flow: t(`privacy.flow.${id}.name`), part: t(`privacy.col.${part}`) })}>{full}</InfoTip>
      </span>
    )
  }
  // A flow with an "items" list (flow 3, one item per AI job) shows its lead sentence and then the list, as PRIVACY.md does.
  const whatCell = (f: PrivacyFlow) => {
    const items = t(`privacy.flow.${f.id}.items`, { returnObjects: true, defaultValue: null }) as unknown
    return brief(f.id, 'what', <>{txt(f.id, 'what')}{Array.isArray(items) ? <ul className="mt-1 grid list-disc gap-1 pl-4">{items.map((i: string) => <li key={i}>{i}</li>)}</ul> : null}</>)
  }
  const toCell = (f: PrivacyFlow) => <>{brief(f.id, 'to', txt(f.id, 'to'))}{f.id === 1 && feedsOn ? <CustomFeedHosts /> : null}</>
  const save = useSavePrivacy()
  async function set(v: { update_check?: boolean }) {
    try { await save.mutateAsync(v); toast.success(t('common:saved')) } catch (e) { toast.error(errMsg(e, t)) }
  }  // Flow 2 is never sent: ignore the state the API reports for it.
  const stateChip = (f: PrivacyFlow) => (f.id === 2 ? <Chip tone="off">{t('privacy.state.notSent')}</Chip> : f.state === 'on' ? <Chip tone="ok">{t('privacy.state.on')}</Chip> : f.state === 'off' ? <Chip tone="off">{t('privacy.state.off')}</Chip> : <Chip tone="off">{t('privacy.state.conditional')}</Chip>)
  const control = (f: PrivacyFlow) => {
      if (f.id === 6) return (
        <div className="flex items-center gap-2">
          <Switch id="privacy-update-check" checked={d.update_check} disabled={gate.disabled || save.isPending} title={gate.title} aria-label={t('privacy.flow.6.switch')} onCheckedChange={(v) => void set({ update_check: v })} />
          <span className="max-w-[220px] text-meta text-muted">{brief(6, 'control', txt(6, 'control'))}</span>
        </div>
      )
      return (
        <span className="block max-w-[240px] text-meta text-muted">
          {brief(f.id, 'control', txt(f.id, 'control'))}{' '}
          {f.id === 3 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/ai">{t('privacy.flow.3.link')}</Link> : null}
          {f.id === 5 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/channels">{t('privacy.flow.5.link')}</Link> : null}
          {f.id === 7 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/siem">{t('privacy.flow.7.link')}</Link> : null}
          {f.id === 8 || f.id === 9 ? <Link className="text-accent underline-offset-4 hover:underline" to={`/settings/modules#module-${f.id === 8 ? 'ai' : 'exposure'}`}>{t(`privacy.flow.${f.id}.link`)}</Link> : null}
          {f.id === 12 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/connections">{t('privacy.flow.12.link')}</Link> : null}
          {f.id === 13 && mcpShown ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/mcp">{t('privacy.flow.13.link')}</Link> : null}
          {f.id === 11 && oidcShown ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/modules#module-auth-oidc">{t('privacy.flow.11.link')}</Link> : null}
          {f.id === 10 && !container ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/network?tab=time#ntp-mode">{t('privacy.flow.10.link')}</Link> : null}
          {f.id === 1 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/feeds">{t('privacy.flow.1.link')}</Link> : null}
          {f.id === 15 ? <Link className="text-accent underline-offset-4 hover:underline" to="/exposure">{t('privacy.flow.15.link')}</Link> : null}
          {f.id === 16 ? <Link className="text-accent underline-offset-4 hover:underline" to="/exposure?tab=settings#greenbone">{t('privacy.flow.16.link')}</Link> : null}
        </span>
      )
  }
  const columns: ColumnDef<PrivacyFlow>[] = [
    { id: 'flow', header: t('privacy.col.flow'), accessorFn: (f) => f.id, cell: ({ row }) => <span id={`flow-${row.original.id}`} className="font-medium">{row.original.id}. {t(`privacy.flow.${row.original.id}.name`)}</span> },
    { id: 'what', header: t('privacy.col.what'), enableSorting: false, accessorFn: (f) => f.id, cell: ({ row }) => <div className="max-w-sm text-meta">{whatCell(row.original)}</div> },
    { id: 'to', header: t('privacy.col.to'), enableSorting: false, accessorFn: (f) => f.id, cell: ({ row }) => <span className="block max-w-[200px] text-meta">{toCell(row.original)}</span> },
    { id: 'state', header: t('privacy.col.state'), accessorFn: (f) => f.state, cell: ({ row }) => stateChip(row.original) },
    { id: 'control', header: t('privacy.col.control'), enableSorting: false, accessorFn: (f) => f.id, cell: ({ row }) => control(row.original) },
  ]
  return (
    <>
      <ReadOnlyNote role="admin" />
      <Section id="flows" title={t('privacy.flows')} description={t('privacy.flowsDesc')} info={t('privacy.flowsInfo')}>
        <DataTable urlKey="privacy-flows" data={d.flows} columns={columns} caption={t('privacy.flows')} pageSize={20} mobileRow={(f) => (
          <div className="grid gap-1.5">
            <div className="flex flex-wrap items-center justify-between gap-2"><span id={`flow-${f.id}`} className="font-medium">{f.id}. {t(`privacy.flow.${f.id}.name`)}</span>{stateChip(f)}</div>
            <div className="text-meta">{whatCell(f)}</div>
            <div className="text-meta text-muted"><span className="font-medium text-ink">{t('privacy.col.to')}: </span>{toCell(f)}</div>
            <div className="text-meta text-muted"><span className="font-medium text-ink">{t('privacy.col.control')}: </span>{control(f)}</div>
          </div>
        )} />
      </Section>

      {/* The statements without a switch share one folded line instead of headings that only explain. */}
      <details id="telemetry" className="max-w-3xl rounded-md border border-rule p-3">
        <summary className="cursor-pointer text-sm font-medium">{t('privacy.more.title')}</summary>
        <div className="mt-3 grid gap-2 text-sm">
          {([
            ['bugNote', 'privacy.bugNote.body', 'privacy.bugNote.bodyInfo'],
            ['mirrorNote', 'privacy.mirrorNote.body', 'privacy.mirrorNote.bodyInfo'],
            ['telemetry', 'privacy.telemetry.statement', 'privacy.telemetry.statementInfo'],
            ['cookie', 'privacy.cookie.body', 'privacy.cookie.bodyInfo'],
          ] as const).map(([k, body, info]) => (
            <p key={k} id={k === 'mirrorNote' ? 'mirror-port' : undefined} className="flex items-start gap-1">
              <span><span className="font-medium">{t(`privacy.${k}.title`)}.</span> {t(body)}</span>
              <InfoTip topic={t(`privacy.${k}.title`)}>{t(info)}</InfoTip>
            </p>
          ))}
        </div>
      </details>
    </>
  )
}

export default function PrivacySection() {
  const { t } = useTranslation('core')
  const q = usePrivacy()
  return (
    <>
      <PageHeader title={t('settings.privacy')} meta={t('privacy.meta')} info={t('privacy.metaInfo')} stories={['S-CORE-4']} />
      <QueryState query={q}>{(d) => <Body d={d} />}</QueryState>
    </>
  )
}
