import type { ReactNode } from 'react'
import { InfoTip } from '@/components/common/InfoTip'
import { cn } from '@/lib/utils'

/** #824: one short visible line with the rest of its explanation behind ⓘ (InfoTip). A div, never inside a <p>. */
export function InfoLine({ topic, info, children, className }: { topic: string; info: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={cn('flex items-center gap-1', className)}>
      <span className="min-w-0">{children}</span>
      <InfoTip topic={topic}>{info}</InfoTip>
    </div>
  )
}
