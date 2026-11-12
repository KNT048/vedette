import { useTranslation } from 'react-i18next'
import { Chip, type Tone } from '@/components/common/StatusChip'
import type { TrapState } from './types'

const TONE: Record<TrapState, Tone> = { listening: 'ok', off: 'off', conflict: 'danger', failed: 'danger', starting: 'warn', stopping: 'warn' }

/** The state the box reports for a trap or a decoy (S-HP-1), never inferred from the switch. */
export function TrapStateChip({ state, children }: { state: TrapState; children?: React.ReactNode }) {
  const { t } = useTranslation('honeypot')
  return <Chip tone={TONE[state]}>{children ?? t(`state.${state}`)}</Chip>
}
