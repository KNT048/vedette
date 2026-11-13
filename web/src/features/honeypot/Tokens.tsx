import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { FlaskConical, Trash2 } from 'lucide-react'
import { Section, Panel } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Button } from '@/components/ui/button'
import { Field, Input, Select } from '@/components/ui/input'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useAddToken, useDeleteToken, useTestToken, useTokens } from './api'
import { TOKEN_TYPES, type Token, type TokenType } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** S-HP-2: honey tokens. Each says where to plant it and what triggers it. A DNS token cannot be created: the box answers no DNS (D-507). */
export default function TokensSection() {
  const { t } = useTranslation('honeypot')
  const q = useTokens()
  return (
    <Section id="tokens" title={t('token.title')} description={t('token.description')}>
      <QueryState query={q}>{(d) => <Inner items={d.items} />}</QueryState>
    </Section>
  )
}

function Inner({ items }: { items: Token[] }) {
  const { t } = useTranslation('honeypot')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const add = useAddToken()
  const del = useDeleteToken()
  const test = useTestToken()
  const [type, setType] = useState<TokenType>('file')
  const [ext, setExt] = useState<'docx' | 'xlsx'>('xlsx')
  const [name, setName] = useState('')
  const [plant, setPlant] = useState('')
  const [error, setError] = useState<string | null>(null)

  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    add.mutate({ type, name: name.trim(), plant_at: plant.trim(), ...(type === 'file' ? { ext } : {}) }, {
      onSuccess: () => { toast.success(t('token.created')); setName(''); setPlant('') },
      onError: (er) => setError(errMsg(er)),
    })
  }

  return (
    <div className="grid gap-4">
      <Panel className="p-4">
        <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2 lg:grid-cols-[1fr_1fr_1.2fr_auto] lg:items-start" noValidate>
          <Field label={t('token.form.type')} htmlFor="tk-type" hint={t(`token.what.${type}`)}>
            <Select id="tk-type" value={type} disabled={!admin} onChange={(e) => { setType(e.target.value as TokenType); setName(''); setPlant(''); setError(null) }}>
              {TOKEN_TYPES.map((x) => <option key={x} value={x}>{t(`token.type.${x}`)}</option>)}
            </Select>
          </Field>
          <Field label={t(`token.form.name.${type}`)} htmlFor="tk-name" error={error ?? undefined} hint={t(`token.form.nameHint.${type}`)}>
            <div className="flex gap-2">
              <Input id="tk-name" value={name} onChange={(e) => setName(e.target.value)} disabled={!admin} autoComplete="off" spellCheck={false} aria-invalid={error ? true : undefined} />
              {type === 'file' ? (
                <Select aria-label={t('token.form.ext')} value={ext} disabled={!admin} onChange={(e) => setExt(e.target.value as 'docx' | 'xlsx')} className="w-24">
                  <option value="xlsx">.xlsx</option><option value="docx">.docx</option>
                </Select>
              ) : null}
            </div>
          </Field>
          <Field label={t('token.form.plant')} htmlFor="tk-plant" hint={t(`token.form.plantHint.${type}`)}>
            <Input id="tk-plant" value={plant} onChange={(e) => setPlant(e.target.value)} disabled={!admin} autoComplete="off" />
          </Field>
          <Button type="submit" variant="primary" className="sm:mt-[26px]" disabled={!admin || add.isPending || type === 'dns'} title={!admin ? t('common:needRole', { role: t('common:role.admin') }) : type === 'dns' ? t('token.what.dns') : undefined}>{t('token.form.create')}</Button>
        </form>
      </Panel>

      {items.length === 0 ? <EmptyState title={t('token.emptyTitle')}>{t('token.emptyBody')}</EmptyState> : (
        <ul className="grid gap-3" aria-label={t('token.listLabel')}>
          {items.map((k) => (
            <li key={k.id} className="rounded-md border border-rule bg-surface p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="grid gap-1">
                  <p className="flex flex-wrap items-center gap-2 text-sm font-medium">{k.name} <Chip tone="accent">{t(`token.type.${k.type}`)}</Chip></p>
                  <p className="text-[13px] text-muted">{t('token.plantedAt', { where: k.plant_at })}</p>
                  <p className="text-[13px] text-muted">{k.last_triggered_at ? t('token.lastTriggered', { when: fmtRelative(k.last_triggered_at), count: k.triggers }) : t('token.never')}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Button size="sm" disabled={!operator || test.isPending} title={operator ? undefined : t('common:needRole', { role: t('common:role.operator') })} aria-label={t('token.testLabel', { name: k.name })}
                    onClick={() => test.mutate(k.id, { onSuccess: () => toast.success(t('token.testToast', { name: k.name })), onError: (e) => toast.error(errMsg(e)) })}><FlaskConical />{t('token.test')}</Button>
                  <Button size="sm" variant="ghost" disabled={!admin || del.isPending} title={admin ? undefined : t('common:needRole', { role: t('common:role.admin') })} aria-label={t('token.deleteLabel', { name: k.name })}
                    onClick={() => del.mutate(k.id, { onSuccess: () => toast.success(t('token.deleted', { name: k.name })), onError: (e) => toast.error(errMsg(e)) })}><Trash2 /></Button>
                </div>
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <div className="grid content-start gap-2">
                  <CodeBlock code={k.type === 'credential' ? `user: ${k.value}\npassword: ${k.password ?? ''}` : k.value} label={t(`token.valueLabel.${k.type}`)} />
                </div>
                <div className="grid content-start gap-1 text-[13px]">
                  <p><span className="font-medium">{t('token.triggerLabel')}</span> {t(`token.trigger.${k.type}`)}</p>
                  <p><span className="font-medium">{t('token.howLabel')}</span> {t(`token.how.${k.type}`, { value: k.value })}</p>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
