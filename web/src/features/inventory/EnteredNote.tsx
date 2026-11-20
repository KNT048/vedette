// What a person entered on a software row (a version, or the package release the device's package manager shows), said on the
// device's Software tab for good: the release, who entered it and when, and what it did (the CVEs it closed as not affected, the
// ones still affected), each linking to its finding. A row a person declared has no author or time on record: "Entered by hand".
import { useTranslation } from 'react-i18next'
import { EnteredOutcome } from '@/features/findings/EnteredRelease'
import { fmtDateTime } from '@/lib/format'
import type { SoftwareLine } from './types'

export function EnteredNote({ assetId, sw }: { assetId: string; sw: SoftwareLine }) {
  const { t } = useTranslation('inventory')
  if (sw.source !== 'manual' || sw.correction?.not_installed) return null
  const c = sw.correction
  const by = c ? (c.set_by ? t('software.enteredBy', { user: c.set_by, when: fmtDateTime(c.set_at) }) : t('software.enteredAt', { when: fmtDateTime(c.set_at) })) : t('software.enteredByHand')
  return (
    <div className="grid gap-0.5" data-testid="entered-note">
      {sw.pkg_version ? <span className="text-caption">{t('software.packageRelease', { release: sw.pkg_version })}</span> : null}
      <span className="text-caption text-muted">{by}</span>
      <EnteredOutcome assetId={assetId} rowIds={[sw.id]} entered={[sw.pkg_version, sw.version].filter((x): x is string => !!x)} always={!!sw.pkg_version || !!c} />
    </div>
  )
}
