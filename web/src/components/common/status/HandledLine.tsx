import { useTranslation } from 'react-i18next'
import { fmtDayMonth } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { Handled } from '@/features/findings/types'
import { useStatusLabel } from './StatusBadge'

/**
 * Who handled a finding and how, from stored fields, never from prose: "Patched by Vedette: version moved 6.24 → 7.23 (18 Nov)",
 * "Patched by Vedette: WinRAR was removed (18 Nov)", "Mitigated by ana (17 Nov): firewall rule on port 443". `software` names the
 * software line when it was removed.
 */
export function HandledLine({ handled: h, software, className }: { handled: Handled; software?: string | null; className?: string }) {
  const { t } = useTranslation()
  const label = useStatusLabel()
  const status = label(h.resolution, { until: h.accepted_until })
  const by = h.by === 'system' ? t('handled.vedette') : h.by
  const date = fmtDayMonth(h.at)
  const how = h.via === 'person' ? null
    : h.via === 'version_moved' ? t('handled.how.version_moved', { from: h.from_version ?? '?', to: h.to_version ?? '?' })
    : h.via === 'software_removed' ? (software ? t('handled.how.software_removed', { software }) : t('handled.how.software_removed_unnamed'))
    : t(`handled.how.${h.via}`)
  const line = how ? t('handled.lineHow', { status, by, how, date }) : t('handled.line', { status, by, date })
  return (
    <span data-handled={h.resolution} className={cn('text-meta text-muted', className)}>
      {h.note ? t('handled.withNote', { line, note: h.note }) : line}
    </span>
  )
}
