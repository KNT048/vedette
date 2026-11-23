import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Chip } from './StatusChip'
import { InfoTip } from './InfoTip'
import type { ModuleId } from '@/lib/modules'
import { useScope, type Scope } from '@/lib/v1'
import { cn } from '@/lib/utils'

// The Preview badge, and the "not in this release" badge with its one line (detail behind ⓘ, #824). A preview module says so with
// its badge only: how a release is planned is not the customer's business.

export function ScopeBadge({ scope, className }: { scope: Scope; className?: string }) {
  const { t } = useTranslation()
  if (scope === 'preview') return <Chip tone="accent" className={className}>{t('scope.preview')}</Chip>
  if (scope === 'leaving') return <Chip tone="warn" className={className}>{t('scope.leaving')}</Chip>
  return null
}

/** The one line under a leaving module's name; `turnOff` adds the link to the only action left (the way out). A preview module has
 *  its badge and no line. */
export function ScopeLine({ scope, turnOff, module, className }: { scope: Scope; turnOff?: boolean; module?: ModuleId; className?: string }) {
  const { t } = useTranslation()
  if (scope !== 'leaving') return null
  return (
    <div className={cn('flex flex-wrap items-center gap-x-1 text-meta text-warn', className)}>
      <span>{t('scope.leavingLine')}</span>
      <InfoTip topic={t('scope.leaving')}>{t('scope.leavingInfo')}</InfoTip>
      {turnOff ? <Link to={module ? `/settings/modules#module-${module}` : '/settings/modules'} className="text-accent underline-offset-4 hover:underline">{t('scope.turnOff')}</Link> : null}
    </div>
  )
}

/** The badge and line of a module, from its state on this box; PageHeader renders them only under a PageModule, so a page
 *  outside any module (and a test without a query client) does not ask for GET /modules. */
export function ModuleBadge({ id, className }: { id: ModuleId; className?: string }) {
  return <ScopeBadge scope={useScope(id)} className={className} />
}
export function ModuleLine({ id, turnOff }: { id: ModuleId; turnOff?: boolean }) {
  return <ScopeLine scope={useScope(id)} turnOff={turnOff} module={id} /> // the link lands on the module's own switch (UI.md §0.2)
}
