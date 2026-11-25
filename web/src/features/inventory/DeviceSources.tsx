// A device's Sources: three equal rows, network scan, SNMP and agent, each decided on the server (GET /inventory/devices/{id}/sources):
// a coloured dot, the name, its state in words, when it last read the device, its switch, and its one button. Passive listening and
// what a person entered are not rows: when they are all that feeds the device, one quiet line says so. What each button opens (the
// SNMP check and settings, the agent's token and install command, its troubleshooting steps) is a dialog, never on the page.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { ErrorState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { kindLabel } from '@/lib/deviceTypes'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { cn } from '@/lib/utils'
import { useScanning, useScanningHistory } from '@/features/scanning/api'
import { ScanNowButton } from '@/features/scanning/ScanNow'
import { AgentCheckDialog } from './AgentQuiet'
import { AgentSetupDialog, InstallOnDeviceDialog } from './InstallAgent'
import { TurnOnModule } from './Inline'
import { SnmpBlockedLine, SnmpDialogs, useSnmpSource } from './SnmpCard'
import { useBoxCheck, useDeviceAction, useDeviceSourceRows, useDeviceSources } from './api'
import { firstCheck } from './firstCheck'
import { errMsg } from './kinds'
import { nameOf } from './nameOf'
import type { DeviceDetail, DeviceSourceRow } from './types'

const DOT: Record<DeviceSourceRow['dot'], string> = { green: 'bg-ok', amber: 'bg-warn', red: 'bg-danger', grey: 'bg-off' }
const MODULE = { scan: 'sensor-active', snmp: 'sensor-active', agent: 'agent-intake' } as const

function When({ at, text }: { at: string; text: string }) {
  return <time className="text-caption text-muted" dateTime={at} title={fmtDateTime(at)}>{text}</time>
}

/** The network scan's words while it is on and has read nothing from the device: when a device check reached it and found nothing,
 *  that check's time; else when its first check happens, from the scan window of Settings › Scanning, and why not when something
 *  stops it. */
function FirstCheckText({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const q = useScanning()
  const history = useScanningHistory(d.asset.id)
  const check = history.data?.items.find((r) => r.kind === 'device' && r.outcome !== 'stopped') ?? null
  if (check) return <>{t('sources.scan.checked', { when: fmtRelative(check.started_at) })}</>
  if (!q.data) return <>{t('sources.scan.firstNext')}</>
  // the checks of new devices run when the scan window opens (the version scans' next run), not when the sweep's schedule comes due
  const sweep = q.data.engines.find((e) => e.id === 'nmap-discovery')
  const disc = sweep ? { enabled: sweep.enabled, next_run_at: q.data.engines.find((e) => e.id === 'nmap-versions')?.next_run_at ?? null } : null
  const f = firstCheck({ ip: d.asset.ip, window: q.data.safety.window, scope: q.data.safety.scope, discovery: disc, now: new Date() })
  return <>{f.when === 'waiting' ? t(`sources.scan.waiting.${f.why}`)
    : f.when === 'now' ? t('sources.scan.firstNow')
    : f.when === 'next' ? t('sources.scan.firstNext')
    : f.when === 'day' ? t('sources.scan.firstDay', { day: f.day, time: f.time })
    : t(f.when === 'tonight' ? 'sources.scan.firstTonight' : f.when === 'today' ? 'sources.scan.firstToday' : 'sources.scan.firstTomorrow', { time: f.time })}</>
}

/** The row's state in words. Quiet says since when (its last call), so no "last report" time stands beside it. */
function StateWords({ d, row }: { d: DeviceDetail; row: DeviceSourceRow }) {
  const { t } = useTranslation('inventory')
  if (row.source === 'scan' && row.state === 'waiting') return <FirstCheckText d={d} />
  // the one place that says why a device added by hand is not scanned: on the switch that turns it on
  if (row.source === 'scan' && row.state === 'off' && d.asset.origin === 'manual') return <>{t('sources.state.offByHand')}</>
  if (row.state === 'quiet') return <>{row.last_at ? t('sources.state.quiet', { when: fmtRelative(row.last_at) }) : t('sources.state.quietUnknown')}</>
  if (row.state === 'waiting') return <>{t(`sources.state.waiting.${row.source}`)}</>
  if (row.state === 'reporting' && row.agent && row.agent !== 'none') return <>{t('sources.state.reportingBy', { agent: t(`sources.agentKind.${row.agent}`) })}</>
  if (row.state === 'box') return <>{t(`sources.state.boxRow.${row.source}`)}</>
  if (row.state === 'cert_changed' && row.refused) return <>{t('sources.state.certChangedSince', { when: fmtRelative(row.refused.since), count: row.refused.count })}</>
  return <>{t(`sources.state.${row.state}`)}</>
}

/** The person's switch of one source for this device. Administrators only; others see it locked with the reason. */
function SourceSwitch({ d, row }: { d: DeviceDetail; row: DeviceSourceRow }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const set = useDeviceSources(d.asset.id)
  const which = row.source
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  const toggle = (v: boolean) => set.mutate({ [which]: v ? 'on' : 'off' }, {
    onSuccess: () => toast.success(t(`sources.saved.${which}.${v ? 'on' : 'off'}`, { name })), onError: (e) => toast.error(errMsg(e)),
  })
  return (
    <Switch id={`device-source-${which}`} aria-label={t(`sources.toggle.${which}`)} checked={row.switch === 'on'} disabled={!admin || set.isPending}
      title={admin ? t(`sources.meaning.${which}.${row.switch === 'on' ? 'on' : 'off'}`) : t('common:needRole', { role: t('common:role.admin') })} onCheckedChange={toggle} />
  )
}

/** One source: dot, name, state, last time, switch and its one button. */
function Row({ d, row, onAction, busy }: { d: DeviceDetail; row: DeviceSourceRow; onAction: (r: DeviceSourceRow) => void; busy: boolean }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const a = row.action
  const byOperator = a === 'approve' || a === 'box_check'
  const role = byOperator ? operator : admin
  const need = role ? undefined : t('common:needRole', { role: t(byOperator ? 'common:role.operator' : 'common:role.admin') })
  const button = !a ? null
    : a === 'turn_on_module' ? <TurnOnModule id={MODULE[row.source]} reason={t(`sources.moduleOff.${row.source}`)} />
    : a === 'scan_now' ? (admin ? <ScanNowButton targets={[d.asset.id]} size="sm" variant="secondary" showProgress={false} /> : null)
    : <Button size="sm" disabled={!role} title={need} busy={busy} busyLabel={(a === 'approve' ? t('inventory:pending.adding') : t('common:busy.checking'))} onClick={() => onAction(row)}>{t(`sources.action.${a}`)}</Button>
  const info = row.source === 'agent' ? t('sources.what.agent') : t(`sources.what.${row.source}`)
  return (
    <li id={row.source === 'snmp' ? 'device-snmp' : row.source === 'agent' ? 'device-agent' : undefined} data-source={row.source} data-state={row.state}
      className="flex min-w-0 flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-md border border-rule bg-surface px-3 py-2.5">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        <span aria-hidden className={cn('size-2.5 shrink-0 rounded-full', DOT[row.dot])} />
        <span className="text-sm font-medium">{t(`sources.name.${row.source}`)}</span>
        <InfoTip topic={t(`sources.name.${row.source}`)}>{info}</InfoTip>
        <span className={cn('text-meta', row.dot === 'red' ? 'text-danger' : row.dot === 'amber' ? 'text-warn' : 'text-muted')}><StateWords d={d} row={row} /></span>
        {row.last_at && row.state !== 'quiet' && row.state !== 'module_off' ? <When at={row.last_at} text={t('sources.lastAt', { when: fmtRelative(row.last_at) })} /> : null}
        {row.next_at ? <When at={row.next_at} text={t('sources.nextAt', { when: fmtRelative(row.next_at) })} /> : null}
      </div>
      {row.switch || button ? (
        <div className="flex flex-wrap items-center gap-3">
          {row.switch ? <SourceSwitch d={d} row={row} /> : null}
          {button}
        </div>
      ) : null}
    </li>
  )
}

/** S-INV-1, S-INV-4: what feeds this device, switched per device, each source's one action right here. */
export function DeviceSources({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const snmpOn = useModuleEnabled('sensor-active') === true
  const agentsOn = useModuleEnabled('agent-intake') === true
  const q = useDeviceSourceRows(d.asset.id, `${snmpOn}|${agentsOn}`)
  const snmp = useSnmpSource(d, admin && snmpOn && !d.asset.is_box) // the box is never read over SNMP
  const approve = useDeviceAction(d.asset.id).approve
  const boxCheck = useBoxCheck(d.asset.id)
  const [open, setOpen] = useState<'create_token' | 'show_setup' | 'check' | null>(null)
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  const agentRow = q.data?.rows.find((r) => r.source === 'agent')
  const act = (row: DeviceSourceRow) => {
    switch (row.action) {
      case 'approve': approve.mutate(undefined, { onSuccess: () => toast.success(t('pending.approved', { name })), onError: (e) => toast.error(errMsg(e)) }); break
      case 'set_up': snmp.setEditing(true); break
      case 'check_now': snmp.check(); break
      case 'create_token': case 'show_setup': case 'check': setOpen(row.action); break
      case 'box_check': boxCheck.mutate(undefined, { onSuccess: () => toast.success(t('sources.boxChecked')), onError: (e) => toast.error(errMsg(e)) }); break
      default: break
    }
  }
  const only = q.data?.only
  return (
    <Section id="sources" title={t('sources.title')} info={t('sources.info')} stories={['S-INV-1', 'S-INV-4']}>
      {q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : !q.data ? <p className="text-meta text-muted">{t('common:loading')}</p> : (
        <div className="grid gap-2">
          <ul aria-label={t('sources.title')} className="grid gap-1.5">
            {q.data.rows.map((row) => (
              <Row key={row.source} d={d} row={row} onAction={act}
                busy={(row.action === 'approve' && approve.isPending) || (row.action === 'check_now' && snmp.act.check.isPending) || (row.action === 'box_check' && boxCheck.isPending)} />
            ))}
          </ul>
          {only ? (
            <p className="flex flex-wrap items-center gap-x-2 px-3 text-meta text-muted" data-testid="sources-only">
              <span aria-hidden className="size-2 shrink-0 rounded-full bg-ok" />
              {t(`sources.only.${only}`)}
              {only === 'manual' && q.data.manual_at ? <When at={q.data.manual_at} text={fmtRelative(q.data.manual_at)} /> : null}
            </p>
          ) : null}
          <SnmpBlockedLine d={d} src={snmp} />
        </div>
      )}
      {admin && snmpOn && !d.asset.is_box ? <SnmpDialogs d={d} src={snmp} /> : null}
      {open === 'create_token' ? <InstallOnDeviceDialog d={d} onClose={() => setOpen(null)} /> : null}
      {open === 'show_setup' ? <AgentSetupDialog d={d} token={agentRow?.token ?? null} onClose={() => setOpen(null)} /> : null}
      {open === 'check' && agentRow ? <AgentCheckDialog d={d} row={agentRow} onClose={() => setOpen(null)} /> : null}
    </Section>
  )
}
