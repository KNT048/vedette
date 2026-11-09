import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Panel } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/input'
import { dateTimeText } from './dates'
import { useCan } from '@/lib/session'
import { useCommit } from './api'
import type { Target } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** Step 2: one commitment per target, recorded with who ticked it and when. Replaces signed consent documents. */
export function CommitmentPanel({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const commit = useCommit()
  const [ticked, setTicked] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const c = target.commitment

  if (c) {
    return (
      <Panel className="grid gap-2 p-4 text-sm">
        <p>{t('commit.doneBody', { user: c.by, time: dateTimeText(c.at) })}</p>
        <p className="text-[13px] text-muted">{t('commit.asIs')}</p>
      </Panel>
    )
  }
  if (target.status !== 'verified') return <Panel className="p-4 text-sm text-muted">{t('commit.waitVerify')}</Panel>

  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!ticked) return setError(t('commit.err'))
    commit.mutate(target.id, { onSuccess: () => toast.success(t('commit.savedToast')), onError: (er) => setError(errMsg(er)) })
  }
  return (
    <Panel className="p-4">
      <p className="mb-3 max-w-3xl text-sm">{t('commit.intro', { value: target.value })}</p>
      <form onSubmit={submit} noValidate className="grid max-w-3xl gap-3">
        <div className="flex items-start gap-2">
          <Checkbox id="ex-commit" checked={ticked} disabled={!can} onCheckedChange={(v) => { setTicked(v === true); setError(null) }} className="mt-0.5" aria-invalid={error ? true : undefined} aria-describedby="ex-commit-asis" />
          <Label htmlFor="ex-commit" className="font-normal">{t('commit.checkbox')}</Label>
        </div>
        <p id="ex-commit-asis" className="text-[13px] text-muted">{t('commit.asIs')}</p>
        {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
        {!can ? <p className="text-[13px] text-muted">{t('commit.needAdmin')}</p> : null}
        <div>
          <Button type="submit" variant="primary" disabled={!can || commit.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })}>{t('commit.save')}</Button>
        </div>
      </form>
    </Panel>
  )
}
