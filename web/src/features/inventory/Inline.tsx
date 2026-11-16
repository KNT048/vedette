import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Select } from '@/components/ui/input'
import { useToggleModule } from '@/features/core/api'
import { useCan } from '@/lib/session'
import type { ModuleId } from '@/lib/modules'
import { errMsg } from './kinds'

// kien 2026-11-16 (#842 rule "do it where you are"): what a step needs is created on the spot, or linked straight to the exact place.
// Local until the shell's shared "+ New …" select and dependency link land in components/common; the props are kept the same shape
// (options, value, onChange, newLabel, onNew; reason, to, label) so they swap in one import.

const NEW = '__new__'

/** A native select whose last option is "+ New …": choosing it calls `onNew` (a small dialog) and keeps the current value. */
export function SelectWithNew({ id, value, onChange, options, newLabel, onNew, disabled, className }: {
  id: string; value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; newLabel: string; onNew?: () => void; disabled?: boolean; className?: string
}) {
  return (
    <Select id={id} value={value} disabled={disabled} className={className} onChange={(e) => { if (e.target.value === NEW) onNew?.(); else onChange(e.target.value) }}>
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      {onNew ? <option value={NEW}>{`+ ${newLabel}`}</option> : null}
    </Select>
  )
}

/** A dependency that cannot be created here: one short reason and a link to the exact tab or field. */
export function NeedLink({ reason, to, label, className }: { reason: ReactNode; to: string; label: string; className?: string }) {
  return (
    <p className={className ?? 'text-[13px] text-muted'}>
      {reason}{' '}
      <Link to={to} className="font-medium text-accent underline-offset-4 hover:underline">{label}</Link>
    </p>
  )
}

/** A module the step needs is off: an admin turns it on right here (with what it depends on); anyone else is told who can. */
export function TurnOnModule({ id, reason }: { id: ModuleId; reason: string }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const toggle = useToggleModule()
  const name = t(`common:modules.${id}.name`)
  if (!admin) return <NeedLink reason={reason} to="/settings/modules" label={t('inline.modulesPage')} />
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
      <p className="text-[13px] text-muted">{reason}</p>
      <Button size="sm" variant="primary" disabled={toggle.isPending}
        onClick={() => toggle.mutate({ id, enabled: true, withDependencies: true }, {
          onSuccess: (r) => { if (r.kind === 'ok') toast.success(t('inline.moduleOn', { name })) },
          onError: (e) => toast.error(errMsg(e)),
        })}>
        {t('inline.turnOn', { name })}
      </Button>
    </div>
  )
}
