import { useId, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { Section } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { useDevice } from '@/features/inventory/api'
import { useRuns } from '@/features/scan/api'
import { runHref } from '@/features/scan/links'
import { RunStatusChip, runOutcome } from '@/features/scan/shared'
import type { ScanRun } from '@/features/scan/types'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useScanning, useScanningHistory } from './api'
import { scanRefusal } from './canScan'
import { HistoryOutcome, historyRowHref } from './RunHistory'

const link = 'text-accent underline-offset-4 hover:underline'

/** The vulnerability check run of this device, as History counts it but with only this device's rows, so the shared sentence
 *  ("Checked 2 CVEs: 1 confirmed, …") is about it. */
function ofDevice(r: ScanRun, id: string): ScanRun | null {
  const results = r.results.filter((x) => x.target_id === id)
  const identification = r.identification.filter((x) => x.target_id === id)
  return results.length || identification.length ? { ...r, results, identification } : null
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

function Never({ children }: { children: ReactNode }) {
  const { t } = useTranslation('scanning')
  return <><Chip tone="off">{t('lastChecks.never')}</Chip><span>{children}</span></>
}

/**
 * kien G7b/c: "Last checks" on the device page: the last identification of this device (Check this device now, the window's queue,
 * the first step of a vulnerability check), its last vulnerability check and its last SNMP read, each with when, the outcome as
 * Settings › Scanning › History says it (shared code) and a link to that run there; a kind that never ran says so and what runs it.
 * Read from GET /scanning/history?asset= (the LAN runs that reached its address) and GET /scans/runs (the vulnerability checks).
 */
export function LastChecks(props: Record<string, unknown>) {
  const assetId = String(props.assetId ?? '')
  const { t } = useTranslation('scanning')
  const { t: ts } = useTranslation('scan')
  const scanOn = useModuleEnabled('scan')
  const device = useDevice(assetId)
  const scanning = useScanning()
  const history = useScanningHistory(assetId)
  const runs = useRuns(scanOn === true)
  if (!assetId) return null
  const items = history.data?.items ?? []
  const ident = items.find((r) => r.kind === 'device')
  const snmp = items.find((r) => r.kind === 'snmp')
  let vuln: ScanRun | null = null
  for (const r of runs.data?.items ?? []) if ((vuln = ofDevice(r, assetId))) break
  const a = device.data?.asset
  const refusal = a ? scanRefusal(a, scanning.data) : null
  const loading = history.isPending || (scanOn === true && runs.isPending)
  return (
    <Section id="last-checks" title={t('lastChecks.title')} description={t('lastChecks.description')} stories={['S-INV-1', 'S-SCAN-4']}>
      <Card className="divide-y divide-rule">
        {loading ? <p className="text-meta text-muted">{t('common:loading')}</p> : (
          <>
            <Row title={t('lastChecks.kind.identify')} when={ident?.started_at ?? null} href={ident ? historyRowHref(assetId, ident.id) : undefined}>
              {ident ? <HistoryOutcome r={ident} /> : <Never>{refusal ? t(`selection.device.${refusal}`) : t('lastChecks.neverIdentify')}</Never>}
            </Row>
            <Row title={t('lastChecks.kind.vuln')} when={vuln?.started_at ?? null} href={vuln ? runHref(vuln.id) : undefined}>
              {vuln ? <><RunStatusChip run={vuln} /><span>{runOutcome(vuln, ts)}</span></>
                : scanOn === false ? <><Chip tone="off">{t('lastChecks.off')}</Chip><span>{t('lastChecks.vulnOff')} <Link to="/settings/scanning?tab=engines#engine-nuclei-switch" className={link}>{t('lastChecks.vulnOffLink')}</Link></span></>
                : <Never>{t('lastChecks.neverVuln')}</Never>}
            </Row>
            <Row title={t('lastChecks.kind.snmp')} when={snmp?.started_at ?? null} href={snmp ? historyRowHref(assetId, snmp.id) : undefined}>
              {snmp ? <HistoryOutcome r={snmp} /> : <Never>{t('lastChecks.neverSnmp')} <Link to="/settings/scanning#snmp" className={link}>{t('lastChecks.neverSnmpLink')}</Link></Never>}
            </Row>
          </>
        )}
      </Card>
    </Section>
  )
}
