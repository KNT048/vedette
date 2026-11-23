import { useTranslation } from 'react-i18next'
import { fmtDate } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { Handled } from '@/features/findings/types'
import { useStatusLabel } from './StatusBadge'

/**
 * Who handled a finding and how, from stored fields, never from prose: "Patched by Vedette: version moved 6.24 → 7.23 (18 Nov 2026)",
 * "Patched by Vedette: WinRAR was removed (18 Nov 2026)", "Mitigated by ana (17 Nov 2026): firewall rule on port 443". `software`
 * names the software line when it was removed. `underBadge`: the line sits under the status badge, which already says the status
 * ("Risk accepted until 24 Dec 2026"), so it starts with who: "By ana (17 Nov 2026): isolated segment".
 */
export function HandledLine({ handled: h, software, underBadge = false, className }: { handled: Handled; software?: string | null; underBadge?: boolean; className?: string }) {
  const { t } = useTranslation()
  const label = useStatusLabel()
  const status = label(h.resolution, { until: h.accepted_until })
  const by = h.by === 'system' ? t('handled.vedette') : h.by
  const date = fmtDate(h.at)
  const how = h.via === 'person' ? null
    // a version move a person made (they changed the version they had entered) is theirs: "Patched by ana: version changed 1.30.5 → 1.30.6"
    : h.via === 'version_moved' ? t(h.by === 'system' ? 'handled.how.version_moved' : 'handled.how.version_set', { from: h.from_version ?? '?', to: h.to_version ?? '?' })
    : h.via === 'software_removed' ? (software ? t('handled.how.software_removed', { software }) : t('handled.how.software_removed_unnamed'))
    : t(`handled.how.${h.via}`)
  const line = underBadge
    ? (how ? t('handled.byHow', { by, how, date }) : t('handled.by', { by, date }))
    : how ? t('handled.lineHow', { status, by, how, date }) : t('handled.line', { status, by, date })
  return (
    <span data-handled={h.resolution} className={cn('text-meta text-muted', className)}>
      {h.note ? t('handled.withNote', { line, note: h.note }) : line}
    </span>
  )
}
