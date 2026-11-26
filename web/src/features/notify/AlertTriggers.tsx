import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { useCan } from '@/lib/session'
import { useSaveTriggers } from './api'
import type { AlertTrigger, AlertTriggerView, RouteSeverity } from './types'

const MINS: RouteSeverity[] = ['critical', 'high', 'medium', 'low']

/** Which kinds of event send an alert, and from which severity. What is off is still recorded on Incidents and the finding: only the
 *  message is left out, so a busy network does not bury the alerts a person must act on. */
export function AlertTriggers({ init }: { init: AlertTriggerView[] }) {
  const { t } = useTranslation('notify')
  const isAdmin = useCan('admin')
  const save = useSaveTriggers()
  const [rows, setRows] = useState<AlertTrigger[]>(init.map(({ id, on, min }) => ({ id, on, min })))
  const [error, setError] = useState<string | null>(null)
  const set = (id: AlertTrigger['id'], v: Partial<AlertTrigger>) => setRows((rs) => rs.map((r) => (r.id === id ? { ...r, ...v } : r)))
  const changed = rows.some((r, i) => r.on !== init[i]?.on || r.min !== init[i]?.min)
  const atDefaults = rows.every((r, i) => r.on === init[i]?.default_on && r.min === init[i]?.default_min)
  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    save.mutate({ triggers: rows }, { onSuccess: () => toast.success(t('triggers.saved')), onError: (er) => setError(er instanceof ApiError ? er.message : String(er)) })
  }
  return (
    <form onSubmit={submit} className="grid max-w-3xl gap-3" noValidate aria-label={t('triggers.title')}>
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      <ul className="grid divide-y divide-border rounded-md border border-border">
        {rows.map((r, i) => {
          const d = init[i]
          const sw = `trigger-${r.id}`
          return (
            <li key={r.id} id={sw} className="grid gap-2 p-3 sm:grid-cols-[1fr_auto] sm:items-center">
              <div className="grid gap-0.5">
                <Label htmlFor={`${sw}-on`} className="font-medium">{t(`triggers.kind.${r.id}.label`)}</Label>
                <p className="text-meta text-muted">{t(`triggers.kind.${r.id}.why`)}</p>
                {d && (r.on !== d.default_on || r.min !== d.default_min) ? (
                  <p className="text-caption text-muted">{t('triggers.default', { rule: d.default_on ? t('triggers.onFrom', { min: t(`triggers.min.${d.default_min}`) }) : t('triggers.off') })}</p>
                ) : null}
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-2">
                  <Switch id={`${sw}-on`} checked={r.on} disabled={!isAdmin} onCheckedChange={(v) => set(r.id, { on: v })} />
                  <span className="text-meta" aria-hidden>{r.on ? t('triggers.send') : t('triggers.dontSend')}</span>
                </div>
                <Label htmlFor={`${sw}-min`} className="sr-only">{t('triggers.fromFor', { what: t(`triggers.kind.${r.id}.label`) })}</Label>
                <Select id={`${sw}-min`} value={r.min} disabled={!isAdmin || !r.on} className="w-auto" onChange={(e) => set(r.id, { min: e.target.value as RouteSeverity })}>
                  {MINS.map((m) => <option key={m} value={m}>{t(`triggers.min.${m}`)}</option>)}
                </Select>
              </div>
            </li>
          )
        })}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="primary" disabled={!isAdmin || !changed} busy={save.isPending} busyLabel={t('common:busy.saving')} title={isAdmin ? undefined : t('channels.needRole')}>{t('triggers.save')}</Button>
        <Button type="button" disabled={!isAdmin || atDefaults} onClick={() => setRows(init.map(({ id, default_on, default_min }) => ({ id, on: default_on, min: default_min })))}>{t('triggers.reset')}</Button>
      </div>
    </form>
  )
}
