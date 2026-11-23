import { useId, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { InfoTip } from '@/components/common/InfoTip'
import { Section } from '@/components/common/PageHeader'
import { ErrorState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { useDevice, useDeviceSnmp, useDeviceSourceRows } from '@/features/inventory/api'
import { useDeviceRuns, useScanConfig } from '@/features/scan/api'
import { RunStatusChip, runOutcome } from '@/features/scan/shared'
import type { ScanRun } from '@/features/scan/types'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled, useModules } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { useScanning, useScanningHistory } from './api'
import type { HistoryRun } from './types'
import { scanRefusal, useDeviceButtons, type DeviceRefusal } from './canScan'
import { runHref, runsHref } from './places'
import { hasSnmpCard, hasSourcesCard } from '@/features/inventory/nameOf'
import { DeviceActions, ScanOffSeeSources, useVulnCheckable } from './DeviceActions'

const link = 'text-accent underline-offset-4 hover:underline'
const outcomeTone = { ok: 'ok', partial: 'warn', failed: 'danger', stopped: 'warn', running: 'accent' } as const

/** A LAN run's outcome: the chip and the sentence the box wrote from what the run stored. */
function HistoryOutcome({ r }: { r: HistoryRun }) {
  const { t } = useTranslation('scanning')
  return <div className="grid justify-items-start gap-1 text-meta"><Chip tone={outcomeTone[r.outcome]}>{t(`history.outcome.${r.outcome}`)}</Chip><span>{r.text}</span></div>
}

/** The vulnerability check run of this device, as History counts it but with only this device's rows, so the shared sentence
 *  ("Checked 2 CVEs: 1 confirmed, …") is about it; a run that stopped before it reached the device says so ("Nothing to check"). */
function ofDevice(r: ScanRun, id: string): ScanRun {
  return { ...r, results: r.results.filter((x) => x.target_id === id), identification: r.identification.filter((x) => x.target_id === id) }
}

function Row({ title, when, children, href }: { title: string; when: string | null; children: ReactNode; href?: string }) {
  const { t } = useTranslation('scanning')
  const id = useId()
  return (
    <div role="group" aria-labelledby={id} className="grid gap-1.5 py-3 first:pt-0 last:pb-0 sm:grid-cols-[minmax(0,14rem)_minmax(0,1fr)] sm:gap-4">
      <div className="grid content-start gap-0.5">
        <h3 id={id} className="text-sm font-medium">{title}</h3>
        {when ? <span className="text-meta text-muted" title={fmtDateTime(when)}>{t('lastChecks.when', { time: fmtDateTime(when), ago: fmtRelative(when) })}</span> : null}
      </div>
      <div className="grid justify-items-start gap-1 text-meta">
        {children}
        {href ? <Link to={href} className={link}>{t('lastChecks.see')}</Link> : null}
      </div>
    </div>
  )
}

/** The words for a vulnerability check that cannot run on this device, from the scan list's reason the device page shows in place
 *  of its button. A device added by hand is "never" to that list until its network scan is on; the device rule (deviceRefusal)
 *  says what a person changes first: its address, or its network scan under Sources ('manual': a pointer to Sources). */
function vulnWhy(reason: string, origin: string | undefined, device: DeviceRefusal | null): string {
  if (reason === 'regular_scan_never' && origin === 'manual' && (device === 'no_ip' || device === 'manual')) return device
  return ['unapproved', 'excluded', 'out_of_scope', 'no_ip', 'regular_scan_never'].includes(reason) ? reason : 'out_of_scope'
}

/** "Never", with what would run it behind its info icon (`info`) and, visible, only a pointer a person acts on (`children`). */
function Never({ info, children }: { info?: string | null; children?: ReactNode }) {
  const { t } = useTranslation('scanning')
  return (
    <>
      <span className="inline-flex items-center gap-1"><Chip tone="off">{t('lastChecks.never')}</Chip>{info ? <InfoTip topic={t('lastChecks.never')}>{info}</InfoTip> : null}</span>
      {children ? <span>{children}</span> : null}
    </>
  )
}

/**
 * "Last checks" on the device page: the last identification of this device (Check this device now, the window's queue,
 * the first step of a vulnerability check), its last vulnerability check and its last SNMP read, each with when, the outcome as
 * the box wrote it and a link to its run page; a kind that never ran says so and what runs it.
 * Read from GET /scanning/history?asset= (the LAN runs that reached its address) and GET /scans/runs?asset= (its vulnerability
 * checks). A read that failed shows the error with Retry, never "Never" (#965).
 */
export function LastChecks(props: Record<string, unknown>) {
  const assetId = String(props.assetId ?? '')
  const { t } = useTranslation('scanning')
  const { t: ts } = useTranslation('scan')
  const modules = useModules()
  const scanOn = modules.data?.modules.find((m) => m.id === 'scan')?.enabled
  const admin = useCan('admin')
  const operator = useCan('operator')
  const device = useDevice(assetId)
  const scanning = useScanning()
  const history = useScanningHistory(assetId)
  const runs = useDeviceRuns(assetId, scanOn === true)
  const cfg = useScanConfig(scanOn === true)
  // the buttons the device page shows for this device (DeviceActions' own rule): a hint names a button only when it is there
  const buttons = useDeviceButtons(assetId, device.data?.asset)
  // no suspected finding a run could check: the page offers no "Run vulnerability checks now", so the row never names it
  const checkable = useVulnCheckable(assetId)
  // the device's SNMP set-up (administrators read it; the SNMP card is theirs too)
  const snmpState = useDeviceSnmp(assetId, admin && !!assetId).data?.state
  // the device's Sources rows (the same read as its Sources card): "Set it up in Sources" only when the SNMP row there offers Set up
  const snmpOn = useModuleEnabled('sensor-active') === true
  const agentsOn = useModuleEnabled('agent-intake') === true
  const sourceRows = useDeviceSourceRows(assetId, `${snmpOn}|${agentsOn}`, admin && !!assetId)
  if (!assetId) return null
  // #965: a read that failed or has not answered is never "Never"
  const failed = [history, modules, device].find((q) => q.isError)
  const loading = history.isPending || modules.isPending || device.isPending || (scanOn === true && (runs.isPending || buttons.pending))
  const items = history.data?.items ?? []
  const ident = items.find((r) => r.kind === 'device')
  const snmp = items.find((r) => r.kind === 'snmp')
  const last = runs.data?.items[0]
  const vuln = last ? ofDevice(last, assetId) : null
  const a = device.data?.asset
  // why "Check this device now" is not there (the device: the same rule as the button) or cannot start (the box's ranges, discovery)
  const refusal = a ? scanRefusal(a, scanning.data) : null
  // a device added by hand with its network scan off: the note is on its Sources card; here only a pointer to it
  const seeSources = <ScanOffSeeSources link={!!a && hasSourcesCard(a)} />
  // "Never" alone; what would run it sits behind its info icon. A cause is said once, above the rows (DeviceActions), and a device
  // added by hand keeps its visible pointer to the switch that turns its scan on.
  const neverIdentify = refusal === 'manual' ? <Never>{seeSources}</Never> : <Never info={refusal ? null : admin ? t('lastChecks.neverIdentify') : t('lastChecks.neverIdentifyRole')} />
  const vulnReason = buttons.vuln && buttons.vuln !== 'off' ? vulnWhy(buttons.vuln, a?.origin, buttons.identify) : null
  // why the box cannot scan now is a state: it stays in view, one line
  const blockReason = cfg.data && !cfg.data.can_scan && cfg.data.block_reason ? cfg.data.block_reason : null
  const neverVuln = vulnReason === 'manual' ? <Never>{seeSources}</Never>
    : vulnReason ? <Never />
    : checkable.none ? <Never info={checkable.suspected === 0 ? t('hint.vulnNoneSuspected') : t('hint.vulnNone', { count: checkable.suspected })}>{blockReason}</Never>
    : <Never info={operator ? t('lastChecks.neverVuln') : t('lastChecks.neverVulnRole')}>{blockReason}</Never>
  // the device's own SNMP card is on this page (the page's rule, SnmpCard.hasSnmpCard)
  // "Set it up in Sources" leads to that card's Set up button, which an approved device with an address has (SNMP reads approved
  // devices only; a device not added yet offers Add device there instead). A device whose SNMP row offers no Set up (a declared
  // device, SNMP turned off for it) gets no link: it would only jump to a row without the step it names.
  const snmpCard = !!a && a.approved && !!a.ip && hasSnmpCard(a, admin, modules.data?.modules.find((m) => m.id === 'sensor-active')?.enabled === true)
    && sourceRows.data?.rows.find((r) => r.source === 'snmp')?.action === 'set_up'
  // SNMP set up and not read yet: the row follows the set-up instead of asking to set it up
  const snmpSetUp = !!snmpState && snmpState !== 'not_set_up'
  return (
    <Section id="last-checks" title={t('lastChecks.title')} stories={['S-INV-1', 'S-SCAN-4']}
      actions={<Link to={runsHref({ device: assetId })} className={`text-meta ${link}`}>{t('lastChecks.allRuns')}</Link>}>
      {/* "Check this device now" and "Run vulnerability checks now" (or why neither is offered) sit here, with the checks they start */}
      {a ? <div className="mb-3"><DeviceActions assetId={assetId} asset={a} /></div> : null}
      {failed ? <ErrorState error={failed.error} onRetry={() => { for (const q of [history, modules, device]) if (q.isError) void q.refetch() }} /> : (
        <Card className="divide-y divide-rule">
          {loading ? <p className="text-meta text-muted">{t('common:loading')}</p> : (
            <>
              <Row title={t('lastChecks.kind.identify')} when={ident?.started_at ?? null} href={ident ? runHref(ident.id) : undefined}>
                {ident ? <HistoryOutcome r={ident} /> : neverIdentify}
              </Row>
              <Row title={t('lastChecks.kind.vuln')} when={vuln?.started_at ?? null} href={vuln ? runHref(vuln.id) : undefined}>
                {vuln ? <><RunStatusChip run={vuln} /><span>{runOutcome(vuln, ts)}</span></>
                  : scanOn === false ? <><span className="inline-flex items-center gap-1"><Chip tone="off">{t('lastChecks.off')}</Chip><InfoTip topic={t('lastChecks.off')}>{t('lastChecks.vulnOff')}</InfoTip></span><Link to="/settings/scanning?tab=engines#engine-nuclei-switch" className={link}>{t('lastChecks.vulnOffLink')}</Link></>
                  : runs.isError ? <ErrorState error={runs.error} onRetry={() => void runs.refetch()} />
                  : neverVuln}
              </Row>
              <Row title={t('lastChecks.kind.snmp')} when={snmp?.started_at ?? null} href={snmp ? runHref(snmp.id) : undefined}>
                {snmp ? <HistoryOutcome r={snmp} />
                  : snmpSetUp ? <span className="inline-flex items-center gap-1"><Chip tone="off">{t('lastChecks.notReadYet')}</Chip><InfoTip topic={t('lastChecks.notReadYet')}>{t('lastChecks.notReadYetInfo')}</InfoTip></span>
                  : <Never info={t('lastChecks.neverSnmp')}>{snmpCard ? <Link to="#device-snmp" className={link}>{t('lastChecks.neverSnmpLink')}</Link> : null}</Never>}
              </Row>
            </>
          )}
        </Card>
      )}
    </Section>
  )
}
