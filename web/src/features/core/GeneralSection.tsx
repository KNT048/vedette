import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useGeneral, useSaveGeneral, useTerms } from './api'
import { errMsg, ReadOnlyNote, useGate } from './parts'
import { browserTimeZone, sameTimeZone, TIMEZONES, validTimeZone } from './util'
import type { GeneralSettings, TermsState } from './types'
import { TermsText } from './TermsText'

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
    if (!validTimeZone(v.timezone)) { setTzError(t('general.timezoneError')); return }
    setTzError(null)
    try {
      await save.mutateAsync({ ...v, name: v.name.trim() })
      toast.success(t('common:saved'))
    } catch (err) { // under the field it is about
      if (err instanceof ApiError && /timezone/.test(`${err.code} ${String(err.details.field ?? '')}`)) setTzError(errMsg(err, t))
      else setError(errMsg(err, t))
    }
  }
  return (
    <Card className="mb-8 max-w-xl">
    <form onSubmit={(e) => void submit(e)} className="grid gap-4" noValidate>
      <Field label={t('general.name')} hint={t('general.nameHint')} htmlFor="org-name" error={error ?? undefined}>
        <Input id="org-name" value={v.name} disabled={gate.disabled} maxLength={80} aria-invalid={!!error} onChange={(e) => setV({ ...v, name: e.target.value })} />
      </Field>
      <Field label={t('general.timezone')} hint={t('general.timezoneHint')} info={t('general.timezoneInfo')} htmlFor="org-tz" error={tzError ?? undefined}>
        <Input id="org-tz" list="org-tz-list" autoComplete="off" spellCheck={false} value={v.timezone} disabled={gate.disabled} aria-invalid={!!tzError} onChange={(e) => setV({ ...v, timezone: e.target.value })} />
        <datalist id="org-tz-list">{TIMEZONES.map((z) => <option key={z} value={z} />)}</datalist>
        {here && !sameTimeZone(here, v.timezone) && !gate.disabled ? <button type="button" className="mt-1 w-fit text-meta text-accent underline-offset-4 hover:underline" onClick={() => setV({ ...v, timezone: here })}>{t('general.useBrowserZone', { zone: here })}</button> : null}
      </Field>
      <div><Button type="submit" variant="primary" disabled={gate.disabled || !dirty} busy={save.isPending} busyLabel={t('common:busy.saving')} title={gate.title}>{t('common:save')}</Button></div>
    </form>
    </Card>
  )
}

/** Who accepted the terms of use on this box, when and which version, and the text to read again. */
function Terms({ s }: { s: TermsState }) {
  const { t } = useTranslation('core')
  const [open, setOpen] = useState(false)
  const a = s.accepted
  return (
    <Card id="terms" title={t('general.terms.title')} info={a ? undefined : t('general.terms.noneInfo')} className="max-w-xl">
      <div className="grid gap-2">
        <p className="text-sm">{a
          ? t(a.by === null ? 'general.terms.at' : a.via === 'restore' ? 'general.terms.byRestore' : 'general.terms.by', { by: a.by, when: fmtDateTime(a.at), version: a.version })
          : t('general.terms.none')}</p>
        {a && a.version !== s.version ? <p className="text-meta text-muted">{t('general.terms.changed', { version: s.version })}</p> : null}
        <div><Button size="sm" aria-expanded={open} aria-controls="terms-text" onClick={() => setOpen((x) => !x)}>{t(open ? 'general.terms.hide' : 'general.terms.read')}</Button></div>
        {open ? <TermsText id="terms-text" /> : null}
      </div>
    </Card>
  )
}

export default function GeneralSection() {
  const { t } = useTranslation('core')
  const q = useGeneral()
  const terms = useTerms()
  return (
    <>
      <PageHeader title={q.data ? t('general.title', { name: q.data.name }) : t('settings.general')} meta={t('general.meta')} info={t('general.metaInfo')} stories={['S-CORE-1']} />
      <ReadOnlyNote role="admin" />
      <QueryState query={q}>{(d) => <Form initial={d} />}</QueryState>
      <QueryState query={terms}>{(d) => <Terms s={d} />}</QueryState>
    </>
  )
}
