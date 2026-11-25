import { useTranslation } from 'react-i18next'
import { CircleCheck, CircleDashed } from 'lucide-react'
import { fmtDate } from '@/lib/format'
import { cn } from '@/lib/utils'
import type { Basis, Verified } from '@/features/findings/types'

/**
 * How Vedette knows: the second line under a status, never a second chip. "Confirmed by a safe check", "Confirmed: the device
 * reports this version", "Confirmed by <user>", "Confirmed: the version <user> entered" (`entered`: Vedette confirmed it on that
 * person's entry, they pressed nothing), "Not confirmed yet: based on a scan banner". `basis` (what the match rests on) is named only
 * while not confirmed; without it the line says "Not confirmed yet".
 */
export function VerificationLine({ verified, basis, by, entered, at, className }: {
  verified: Verified; basis?: Basis | null; by?: string | null; entered?: boolean; at?: string | null; className?: string
}) {
  const { t } = useTranslation()
  const person = by ? t(entered ? 'verification.personEntered' : 'verification.person', { by }) : t('verification.personUnnamed')
  const text = verified === 'no'
    ? (basis ? t('verification.notYetBasis', { basis: t(`verification.basis.${basis}`) }) : t('verification.notYet'))
    : verified === 'person' ? person : t(`verification.${verified}`)
  const Icon = verified === 'no' ? CircleDashed : CircleCheck
  return (
    <span data-verified={verified} title={at ? fmtDate(at) : undefined} className={cn('inline-flex items-center gap-1 text-meta text-muted', className)}>
      <Icon aria-hidden className={cn('size-3.5 shrink-0', verified === 'no' ? 'text-warn' : 'text-ok')} />
      {text}
    </span>
  )
}
