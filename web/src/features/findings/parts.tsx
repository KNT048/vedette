// Small pieces the Findings screen's lists share: the fix in words, the severity count line, a device's name line and the link of
// a device's badge.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { StatusBadge } from '@/components/common/status'
import type { DeviceRef, DeviceStatus, Fix, SeverityCounts, SoftwareRef } from './types'
import { NotAddedChip } from './NotAdded'
import { deviceFindingsLink } from '@/features/inventory/RiskMarker'

/** Where a device's badge leads: the device's Findings tab filtered to that status, or its questions (one rule, inventory's). */
export const deviceStatusLink = (device: string, status: NonNullable<DeviceStatus>['code']): string => deviceFindingsLink(device, status)

/** The fix as a sentence. On a device (`software` given) the update names the installed version: "Update OpenSSH 10.2p1 → 10.6";
 *  across devices: "Update OpenSSH to 10.6". */
export function useFixTitle() {
  const { t } = useTranslation('findings')
  return (fix: Fix, software?: SoftwareRef | null) => {
    const from = software?.version ?? null
    const to = fix.version
    // a fix that names no release says what to do without an empty slot ("Install the Linux kernel package  or later")
    switch (fix.kind) {
      case 'update': return !to ? t('fixLine.updateAny', { product: fix.product }) : from ? t('fixLine.updateFrom', { product: fix.product, from, to }) : t('fixLine.update', { product: fix.product, to })
      case 'distro_update': return to ? t('fixLine.distro', { product: fix.product, to }) : t('fixLine.distroAny', { product: fix.product })
      case 'os_update': return fix.ref ? t('fixLine.osRef', { product: fix.product, ref: fix.ref }) : to ? t('fixLine.osBuild', { product: fix.product, to }) : t('fixLine.osAny', { product: fix.product })
      case 'feature_update': return to ? t('fixLine.feature', { product: fix.product, to }) : t('fixLine.featureAny', { product: fix.product })
      case 'none_yet': return t('fixLine.noneYet', { product: fix.product })
      default: return t('fixLine.unknown', { product: fix.product })
    }
  }
}

/** The advisory of a fix, when it has one. A fix with no release to install and no advisory link ("No fix data") links its cause's
 *  CVE page instead, where the CVE record's references are: the person always has somewhere to read what the vendor says. */
export function FixLink({ fix, cve }: { fix: Fix; cve?: string }) {
  const { t } = useTranslation('findings')
  if (!fix.url && cve && (fix.kind === 'none_yet' || fix.kind === 'unknown')) {
    return (
      <Link to={`/cve/${encodeURIComponent(cve)}`} onClick={(e) => e.stopPropagation()} className="text-meta text-accent underline-offset-4 hover:underline">
        {t('fixLine.advisories', { cve })}
      </Link>
    )
  }
  if (!fix.url) return null
  return (
    <a href={fix.url} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="text-meta text-accent underline-offset-4 hover:underline">
      {fix.kind === 'none_yet' || fix.kind === 'unknown' ? t('fixLine.advisory') : t('fixLine.notes')}
    </a>
  )
}

const BANDS = ['critical', 'high', 'medium', 'low', 'none'] as const
/** "2 Critical · 18 High · 5 Medium · 1 not scored yet". */
export function SeverityLine({ counts, className }: { counts: SeverityCounts; className?: string }) {
  const { t } = useTranslation()
  const parts = BANDS.filter((b) => counts[b] > 0).map((b) => `${counts[b]} ${t(`severity.${b}`)}`)
  if (counts.unscored > 0) parts.push(t('cveList.unscored', { count: counts.unscored }))
  return parts.length ? <span className={className ?? 'text-meta text-muted'}>{parts.join(' · ')}</span> : null
}

/** A device as the lists name it: its page, its address, "Not added yet", and its badge (a link to its findings with that status).
 * link false names the device without a link, where another row of the same list already links to its page. */
export function DeviceLine({ device, status, badge = true, link = true }: { device: DeviceRef; status?: DeviceStatus; badge?: boolean; link?: boolean }) {
  const { t } = useTranslation('findings')
  return (
    <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
      {link ? (
        <Link to={`/devices/${encodeURIComponent(device.id)}`} onClick={(e) => e.stopPropagation()}
          className="font-semibold text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{device.name}</Link>
      ) : <span className="font-semibold [overflow-wrap:anywhere]">{device.name}</span>}
      <span className="text-meta text-muted">{device.ip ?? t('noIp')}</span>
      <NotAddedChip asset={{ approved: device.added, ignored: device.ignored }} />
      {badge && status ? <StatusBadge code={status.code} count={status.count} to={deviceStatusLink(device.id, status.code)} /> : null}
    </span>
  )
}

/** The inventory's view of a device for its Add device and Ignore actions. */
export const asAsset = (d: DeviceRef) => ({ id: d.id, name: d.name, hostname: null, ip: d.ip ?? '—', kind: d.kind, display: d.name, approved: d.added, ignored: d.ignored })
