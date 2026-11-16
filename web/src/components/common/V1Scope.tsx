import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Chip } from './StatusChip'
import { InfoTip } from './InfoTip'
import type { ModuleId } from '@/lib/modules'
import { useScope, type Scope } from '@/lib/v1'
import { cn } from '@/lib/utils'

// D-624, #818, #819: the Preview badge and the "not in v1" badge, each with its one line (detail behind ⓘ, #824).

export function ScopeBadge({ scope, className }: { scope: Scope; className?: string }) {
  const { t } = useTranslation()
  if (scope === 'preview') return <Chip tone="accent" className={className}>{t('scope.preview')}</Chip>
  if (scope === 'leaving') return <Chip tone="warn" className={className}>{t('scope.leaving')}</Chip>
  return null
}

/** The one line under a preview or leaving module's name; `turnOff` adds the link to the only action left (D-403's way out). */
export function ScopeLine({ scope, turnOff, module, className }: { scope: Scope; turnOff?: boolean; module?: ModuleId; className?: string }) {
  const { t } = useTranslation()
  if (scope !== 'preview' && scope !== 'leaving') return null
  const line = t(scope === 'preview' ? 'scope.previewLine' : 'scope.leavingLine')
  return (
    <div className={cn('flex flex-wrap items-center gap-x-1 text-meta', scope === 'leaving' ? 'text-warn' : 'text-muted', className)}>
      <span>{line}</span>
      <InfoTip topic={t(scope === 'preview' ? 'scope.preview' : 'scope.leaving')}>{t(scope === 'preview' ? 'scope.previewInfo' : 'scope.leavingInfo')}</InfoTip>
      {turnOff && scope === 'leaving' ? <Link to={module ? `/settings/modules#module-${module}` : '/settings/modules'} className="text-accent underline-offset-4 hover:underline">{t('scope.turnOff')}</Link> : null}
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
