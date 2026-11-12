import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { useGeneral, useSaveGeneral } from './api'
import { errMsg, ReadOnlyNote, useGate } from './parts'
import { browserTimeZone, TIMEZONES } from './util'
import type { GeneralSettings } from './types'

function Form({ initial }: { initial: GeneralSettings }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const save = useSaveGeneral()
  const [v, setV] = useState(initial)
  const [error, setError] = useState<string | null>(null)
  const [tzError, setTzError] = useState<string | null>(null)
  const here = browserTimeZone()
  const dirty = v.name !== initial.name || v.timezone !== initial.timezone
  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (v.name.trim().length < 2) { setError(t('general.nameError')); return }
    if (!TIMEZONES.includes(v.timezone)) { setTzError(t('general.timezoneError')); return }
    setTzError(null)
    try {
      await save.mutateAsync({ ...v, name: v.name.trim() })
      toast.success(t('common:saved'))
    } catch (err) { setError(errMsg(err, t)) }
  }
  return (
    <form onSubmit={(e) => void submit(e)} className="grid max-w-xl gap-4" noValidate>
      <Field label={t('general.name')} hint={t('general.nameHint')} htmlFor="org-name" error={error ?? undefined}>
        <Input id="org-name" value={v.name} disabled={gate.disabled} maxLength={80} aria-invalid={!!error} onChange={(e) => setV({ ...v, name: e.target.value })} />
      </Field>
      <Field label={t('general.timezone')} hint={t('general.timezoneHint')} htmlFor="org-tz" error={tzError ?? undefined}>
        <Input id="org-tz" list="org-tz-list" autoComplete="off" spellCheck={false} value={v.timezone} disabled={gate.disabled} aria-invalid={!!tzError} onChange={(e) => setV({ ...v, timezone: e.target.value })} />
        <datalist id="org-tz-list">{TIMEZONES.map((z) => <option key={z} value={z} />)}</datalist>
        {here && here !== v.timezone && !gate.disabled ? <button type="button" className="mt-1 w-fit text-[13px] text-accent underline-offset-4 hover:underline" onClick={() => setV({ ...v, timezone: here })}>{t('general.useBrowserZone', { zone: here })}</button> : null}
      </Field>
      <div><Button type="submit" variant="primary" disabled={gate.disabled || !dirty || save.isPending} title={gate.title}>{t('common:save')}</Button></div>
    </form>
  )
}

export default function GeneralSection() {
  const { t } = useTranslation('core')
  const q = useGeneral()
  return (
    <>
      <PageHeader title={q.data ? t('general.title', { name: q.data.name }) : t('settings.general')} stories={['S-CORE-1']} />
      <ReadOnlyNote role="admin" />
      <QueryState query={q}>{(d) => <Form initial={d} />}</QueryState>
    </>
  )
}
