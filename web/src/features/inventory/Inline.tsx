import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { DependencyLink } from '@/components/common/DependencyLink'
import { useToggleModule } from '@/features/core/api'
import { useCan } from '@/lib/session'
import { useModules, type ModuleId } from '@/lib/modules'
import { errMsg } from './kinds'

// docs/UI.md §0 "do it where you are": a module a step needs is turned on where the step is.

/** A module the step needs is off: an admin turns it on right here (with what it depends on); anyone else is told who can. */
export function TurnOnModule({ id, reason }: { id: ModuleId; reason: string }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const toggle = useToggleModule()
  const name = t(`common:modules.${id}.name`)
  // What turns on with it, said before the click as Settings › Modules does (#849 review L8).
  const mods = useModules().data?.modules ?? []
  const deps = (mods.find((m) => m.id === id)?.depends ?? []).filter((d) => mods.find((m) => m.id === d)?.enabled === false)
  // ponytail: Settings › Modules has no per-module id yet (asked of the core owner); the anchor lands once it does.
  if (!admin) return <DependencyLink reason={reason} to={`/settings/modules#module-${id}`} label={t('inline.modulesPage')} />
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
      <p className="text-meta text-muted">{reason}{deps.length ? ` ${t('inline.alsoOn', { list: deps.map((d) => t(`common:modules.${d}.name`)).join(', ') })}` : ''}</p>
      <Button size="sm" variant="primary" busy={toggle.isPending} busyLabel={t('common:busy.turningOn')}
        onClick={() => toggle.mutate({ id, enabled: true, withDependencies: true }, {
          onSuccess: (r) => { if (r.kind === 'ok') toast.success(t('inline.moduleOn', { name })) },
          onError: (e) => toast.error(errMsg(e)),
        })}>
        {t('inline.turnOn', { name })}
      </Button>
    </div>
  )
}
