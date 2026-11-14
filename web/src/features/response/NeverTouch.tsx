import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus, Trash2 } from 'lucide-react'
import { Notice, Panel } from '@/components/common/PageHeader'
import { ErrorState, Loading } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { useCan } from '@/lib/session'
import { errText, useAllowlist, useSaveAllowlist } from './api'
import { isCidr, isDomain, isIpv4 } from './logic'

/** Never-touch list (D-51): gateway, DNS, domain controllers, this box, management IPs. No rule and no AI request can change them. Editable by an admin. */
export function NeverTouch() {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const q = useAllowlist()
  const save = useSaveAllowlist()
  const [draft, setDraft] = useState<{ value: string; label: string }[] | null>(null)
  const [nv, setNv] = useState('')
  const [nl, setNl] = useState('')
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const items = draft ?? q.data.items
  const valid = (v: string) => isIpv4(v) || isCidr(v) || isDomain(v)
  const add = () => { if (valid(nv.trim())) { setDraft([...items, { value: nv.trim().toLowerCase(), label: nl.trim() || nv.trim() }]); setNv(''); setNl('') } }
  return (
    <div className="grid gap-3">
      <div><h3 className="text-sm font-medium">{t('allow.title')}</h3><p className="text-[13px] text-muted">{t('allow.description')}</p></div>
      {!items.length ? <Notice tone="warn" className="mb-0" title={t('allow.empty')} /> : null}
      <Panel>
        <ul className="divide-y divide-rule">
          {items.map((e, i) => (
            <li key={e.value} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm">
              <span><span className="font-medium">{e.value}</span> <span className="text-muted">{e.label}</span></span>
              {admin ? <Button size="sm" variant="ghost" aria-label={t('allow.remove', { value: e.value })} onClick={() => setDraft(items.filter((_, j) => j !== i))}><Trash2 className="size-4" aria-hidden /></Button> : null}
            </li>
          ))}
        </ul>
      </Panel>
      {admin ? (
        <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => { e.preventDefault(); add() }}>
          <Field htmlFor="al-value" label={t('allow.value')} hint={t('allow.valueHint')} className="min-w-52"><Input id="al-value" value={nv} onChange={(e) => setNv(e.target.value)} placeholder="192.168.10.5" /></Field>
          <Field htmlFor="al-label" label={t('allow.label')} className="min-w-52"><Input id="al-label" value={nl} maxLength={80} onChange={(e) => setNl(e.target.value)} placeholder="Accounting server" /></Field>
          <Button type="submit" disabled={!valid(nv.trim())}><Plus className="size-4" aria-hidden />{t('allow.add')}</Button>
          <Button type="button" variant="primary" disabled={!draft || save.isPending} onClick={() => save.mutate({ items }, { onSuccess: () => { toast.success(t('common:saved')); setDraft(null) }, onError: (e) => toast.error(errText(e)) })}>{t('common:save')}</Button>
        </form>
      ) : null}
    </div>
  )
}
