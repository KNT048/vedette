import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { FlaskConical, Trash2 } from 'lucide-react'
import { Section, Panel } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Field, Input, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useAddDecoy, useDecoys, useDeleteDecoy, useTestScan, useToggleDecoy } from './api'
import { PERSONALITIES, personalityDef } from './personalities'
import type { DecoysResponse, Hit, Personality } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** S-HP-2: what the decoy looks like, chosen from device types that really exist in the inventory; scan detection across decoy IPs. */
export default function DecoysSection({ hits }: { hits: Hit[] }) {
  const { t } = useTranslation('honeypot')
  const q = useDecoys()
  return (
    <Section id="personalities" title={t('personality.title')} description={t('personality.description')}>
      <QueryState query={q}>{(d) => <Inner data={d} hits={hits} />}</QueryState>
    </Section>
  )
}

function Inner({ data, hits }: { data: DecoysResponse; hits: Hit[] }) {
  const { t } = useTranslation('honeypot')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const add = useAddDecoy()
  const toggle = useToggleDecoy()
  const del = useDeleteDecoy()
  const scan = useTestScan()
  const [personality, setPersonality] = useState<Personality>(data.suggestions[0]?.personality ?? 'windows_fs')
  const [name, setName] = useState('')
  const [ip, setIp] = useState('')
  const [error, setError] = useState<string | null>(null)
  const def = personalityDef(personality)
  const lastScan = hits.find((h) => h.kind === 'scan' && !h.is_test)
  const scanReason = !operator ? t('common:needRole', { role: t('common:role.operator') }) : data.items.length < 1 ? t('personality.scan.needDecoys') : undefined

  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    add.mutate({ personality, name: name.trim(), ip: ip.trim() }, {
      onSuccess: () => { toast.success(t('personality.added')); setName(''); setIp('') },
      onError: (er) => setError(errMsg(er)),
    })
  }

  return (
    <div className="grid gap-4">
      {data.suggestions.length ? (
        <Panel className="p-4">
          <p className="text-sm font-medium">{t('personality.suggestTitle')}</p>
          <ul className="mt-2 grid gap-1.5 text-sm">
            {data.suggestions.map((s) => (
              <li key={s.personality} className="flex flex-wrap items-center justify-between gap-2">
                <span>{t('personality.suggestItem', { count: s.count, type: t(`personality.type.${s.personality}`), names: s.examples.join(', ') })}</span>
                <Button size="sm" disabled={!admin} title={admin ? undefined : t('common:needRole', { role: t('common:role.admin') })} onClick={() => { setPersonality(s.personality); document.getElementById('dc-name')?.focus() }}>
                  {t('personality.useType', { type: t(`personality.type.${s.personality}`) })}
                </Button>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      <Panel className="p-4">
        <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2 lg:grid-cols-[1.2fr_1fr_1fr_auto] lg:items-start" noValidate>
          <Field label={t('personality.form.type')} htmlFor="dc-type" hint={t('personality.form.typeHint', { services: def.services.map((s) => `${s.name} ${s.port}`).join(', ') })}>
            <Select id="dc-type" value={personality} disabled={!admin} onChange={(e) => { setPersonality(e.target.value as Personality); setError(null) }}>
              {PERSONALITIES.map((p) => <option key={p.id} value={p.id}>{t(`personality.type.${p.id}`)}</option>)}
            </Select>
          </Field>
          <Field label={t('personality.form.name')} htmlFor="dc-name" hint={t('personality.form.nameHint', { example: def.namePlaceholder })}>
            <Input id="dc-name" value={name} onChange={(e) => setName(e.target.value)} disabled={!admin} maxLength={15} autoComplete="off" spellCheck={false} placeholder={def.namePlaceholder} />
          </Field>
          <Field label={t('personality.form.ip')} htmlFor="dc-ip" hint={data.spare_ips.length ? t('personality.form.ipHint', { ips: data.spare_ips.join(', ') }) : t('personality.form.ipHintNone')} error={error ?? undefined}>
            <Input id="dc-ip" value={ip} onChange={(e) => setIp(e.target.value)} disabled={!admin} inputMode="decimal" autoComplete="off" placeholder={data.spare_ips[0] ?? ''} aria-invalid={error ? true : undefined} />
          </Field>
          <Button type="submit" variant="primary" className="sm:mt-[26px]" disabled={!admin || add.isPending} title={admin ? undefined : t('common:needRole', { role: t('common:role.admin') })}>{t('personality.form.add')}</Button>
        </form>
      </Panel>

      {data.items.length ? (
        <ul className="grid divide-y divide-rule rounded-md border border-rule bg-surface" aria-label={t('personality.listLabel')}>
          {data.items.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm">
              <span className="grid">
                <span className="font-medium">{d.name} <span className="text-[13px] font-normal text-muted tabular-nums">{d.ip}</span></span>
                <span className="text-[12px] text-muted">{t(`personality.type.${d.personality}`)}: {d.services.map((s) => `${s.name} ${s.port}`).join(', ')}</span>
              </span>
              <span className="flex items-center gap-3">
                {d.enabled ? <Chip tone="ok">{t('state.listening')}</Chip> : <Chip tone="off">{t('state.off')}</Chip>}
                <Switch checked={d.enabled} disabled={!admin || toggle.isPending} title={admin ? undefined : t('common:needRole', { role: t('common:role.admin') })} aria-label={t('personality.switchLabel', { name: d.name })}
                  onCheckedChange={(v) => toggle.mutate({ id: d.id, enabled: v }, { onError: (e) => toast.error(errMsg(e)) })} />
                <Button size="sm" variant="ghost" disabled={!admin || del.isPending} aria-label={t('personality.deleteLabel', { name: d.name })} title={admin ? undefined : t('common:needRole', { role: t('common:role.admin') })}
                  onClick={() => del.mutate(d.id, { onSuccess: () => toast.success(t('personality.deleted', { name: d.name })), onError: (e) => toast.error(errMsg(e)) })}><Trash2 /></Button>
              </span>
            </li>
          ))}
        </ul>
      ) : <p className="text-sm text-muted">{t('personality.none')}</p>}

      <Panel className="p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="grid max-w-3xl gap-1">
            <p className="text-sm font-medium">{t('personality.scan.title')}</p>
            <p className="text-[13px] text-muted">{t('personality.scan.body')}</p>
            <p className="text-[13px] text-muted">{lastScan ? t('personality.scan.last', { when: fmtRelative(lastScan.ts), src: lastScan.src_name ?? lastScan.src_ip }) : t('personality.scan.never')}</p>
          </div>
          <Button size="sm" disabled={!!scanReason || scan.isPending} title={scanReason} onClick={() => scan.mutate(undefined, { onSuccess: () => toast.success(t('personality.scan.testToast')), onError: (e) => toast.error(errMsg(e)) })}>
            <FlaskConical />{t('personality.scan.test')}
          </Button>
        </div>
      </Panel>
    </div>
  )
}
