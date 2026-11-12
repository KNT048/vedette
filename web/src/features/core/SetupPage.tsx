import { useEffect, useRef, useState } from 'react'
import { Navigate, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Check, Plus, Trash2 } from 'lucide-react'
import { ErrorState, Loading } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Field, Input, Select } from '@/components/ui/input'
import { toast } from 'sonner'
import { Segmented } from '@/components/ui/segmented'
import type { ModuleId } from '@/lib/modules'
import { ApiError } from '@/lib/api'
import { cn } from '@/lib/utils'
import { saveInventoryScope, saveNotifyChannel, useSetupModules, useSetupStatus, useSubmitSetup } from './api'
import { BUNDLES, closure, without } from './bundles'
import { errMsg } from './parts'
import { EMAIL_RE, isBareIp, isPrivateCidr, MIN_PASSWORD, normaliseCidr } from './util'
import type { BundleId, ChannelType, SetupPayload } from './types'

const STEPS = ['account', 'network', 'modules', 'channel'] as const
type Step = (typeof STEPS)[number]

interface State {
  org: string; name: string; email: string; password: string; again: string; code: string
  lan: string[]; commitment: boolean; notes: { to: string; text: string }[]
  bundle: BundleId; picked: Set<ModuleId>
  chType: ChannelType; ch: Record<string, string>; chSecret: string
}
const INIT: State = {
  org: '', name: '', email: '', password: '', again: '', code: '', lan: [''], commitment: false, notes: [],
  bundle: 'smb', picked: new Set<ModuleId>(['core']), chType: 'telegram', ch: { port: '587', security: 'starttls' }, chSecret: '',
}
const CH_FIELDS: Record<ChannelType, string[]> = { telegram: ['chat_id'], zalo: ['oa_id', 'user_id'], email: ['host', 'port', 'username', 'from', 'to'] }

export default function SetupPage() {
  const { t } = useTranslation('core')
  const navigate = useNavigate()
  const status = useSetupStatus()
  const submit = useSubmitSetup()
  const [step, setStep] = useState<Step>('account')
  const [s, setS] = useState<State>(INIT)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [finished, setFinished] = useState(false)
  const [setupDone, setSetupDone] = useState(false)
  const heading = useRef<HTMLHeadingElement>(null)
  const idx = STEPS.indexOf(step)
  useEffect(() => { heading.current?.focus() }, [step])

  if (status.isPending) return <div className="p-8"><Loading /></div>
  if (status.error) return <div className="p-8"><ErrorState error={status.error} onRetry={() => void status.refetch()} /></div>
  if (status.data?.complete && !finished) return <Navigate to="/login" replace />

  const set = (patch: Partial<State>) => setS((x) => ({ ...x, ...patch }))

  function validate(which: Step): boolean {
    const e: Record<string, string> = {}
    if (which === 'account') {
      if (!s.code.trim()) e.code = t('setup.account.codeError')
      if (s.org.trim().length < 2) e.org = t('setup.account.orgError')
      if (!s.name.trim()) e.name = t('setup.account.nameError')
      if (!EMAIL_RE.test(s.email.trim())) e.email = t('setup.account.emailError')
      if (s.password.length < MIN_PASSWORD) e.password = t('setup.account.passwordError', { min: MIN_PASSWORD, count: s.password.length })
      else if (s.password !== s.again) e.again = t('setup.account.againError')
    }
    if (which === 'network') {
      const rows = s.lan.map((x) => x.trim())
      const filled = rows.filter(Boolean)
      const seen = new Set<string>()
      if (!filled.length) e.lanAll = t('setup.network.lanEmpty')
      if (filled.length > 16) e.lanAll = t('setup.network.lanMany')
      rows.forEach((raw, i) => {
        if (!raw) { if (filled.length) e[`lan${i}`] = t('setup.network.lanBlank'); return }
        const n = normaliseCidr(raw)
        if (!n) e[`lan${i}`] = isBareIp(raw) ? t('setup.network.lanNoPrefix', { value: raw.trim() }) : t('setup.network.lanBad', { value: raw })
        else if (!isPrivateCidr(n.value)) e[`lan${i}`] = t('setup.network.lanPublic', { value: raw })
        else if (seen.has(n.value)) e[`lan${i}`] = t('setup.network.lanDup', { value: n.value })
        else seen.add(n.value)
      })
    }
    if (which === 'modules' && s.bundle === 'custom' && s.picked.size < 2) e.modules = t('setup.modules.customEmpty')
    if (which === 'channel') {
      const f = s.ch
      if (s.chType === 'email') {
        if (!EMAIL_RE.test((f.from ?? '').trim())) e.from = t('setup.channel.emailError')
        const to = (f.to ?? '').split(',').map((x) => x.trim()).filter(Boolean)
        if (!to.length || !to.every((x) => EMAIL_RE.test(x))) e.to = t('setup.channel.toError')
      }
      for (const k of CH_FIELDS[s.chType]) if (!(f[k] ?? '').trim() && !e[k]) e[k] = t('setup.channel.required')
      if (!s.chSecret) e.secret = t('setup.channel.required')
    }
    setErrors(e)
    return Object.keys(e).length === 0
  }

  function next() {
    if (!validate(step)) return
    if (step === 'network') {
      const notes: State['notes'] = []
      const lan = s.lan.map((x) => {
        const n = normaliseCidr(x)!
        if (n.note) notes.push({ to: n.value, text: t(`setup.network.note.${n.note}`, { from: x.trim(), to: n.value }) })
        return n.value
      })
      set({ lan, notes })
    }
    setStep(STEPS[idx + 1] ?? step)
  }

  async function finish(withChannel: boolean) {
    if (withChannel && !validate('channel')) return
    setFormError(null)
    setFinished(true)
    if (!setupDone) {
      const p: SetupPayload = {
        org: s.org.trim(),
        admin: { name: s.name.trim(), email: s.email.trim(), password: s.password },
        lan: s.lan.map((x) => x.trim()).filter(Boolean),
        commitment: s.commitment,
        bundle: s.bundle,
        modules: s.bundle === 'custom' ? [...s.picked] : undefined,
        setup_code: s.code.trim(),
      }
      try { await submit.mutateAsync(p) } catch (err) {
        setFinished(false)
        // A wrong setup code belongs on the first step, next to its field.
        if (err instanceof ApiError && err.code === 'invalid_setup_code') { setErrors({ code: errMsg(err, t) }); setStep('account'); return }
        setFormError(errMsg(err, t)); return
      }
      setSetupDone(true)
      // Đã đăng nhập bằng tài khoản quản trị: ghi phạm vi quét vào module kiểm kê (nơi lưu xác nhận phạm vi và người xác nhận).
      try {
        await saveInventoryScope(s.lan.map((x) => x.trim()).filter(Boolean), s.commitment)
      } catch (err) { toast.error(t('setup.network.saveFailed', { message: errMsg(err, t) })) }
    }
    if (withChannel) {
      const fields = Object.fromEntries(CH_FIELDS[s.chType].map((k) => [k, (s.ch[k] ?? '').trim()]))
      if (s.chType === 'email') fields.security = s.ch.security ?? 'starttls'
      try { await saveNotifyChannel(s.chType, fields, s.chSecret) } catch (err) {
        setFormError(t('setup.channel.saveFailed', { message: errMsg(err, t) }))
        return
      }
    }
    navigate('/', { replace: true })
  }

  async function startWithSample() {
    setFormError(null)
    setFinished(true)
    try { await submit.mutateAsync({ sample: true }); navigate('/', { replace: true }) } catch (err) { setFinished(false); setFormError(errMsg(err, t)) }
  }

  return (
    <main className="mx-auto min-h-dvh w-full max-w-2xl px-4 py-10">
      <h1 className="text-2xl font-semibold tracking-[-0.01em]">{t('setup.title')}</h1>
      <p className="mt-1 text-sm text-muted">{t('setup.subtitle')}</p>

      <ol aria-label={t('setup.steps')} className="mt-6 flex flex-wrap gap-x-5 gap-y-2 text-sm">
        {STEPS.map((k, i) => (
          <li key={k} aria-current={i === idx ? 'step' : undefined} className={cn('flex items-center gap-1.5', i === idx ? 'font-medium text-ink' : 'text-muted')}>
            <span className={cn('grid size-5 place-items-center rounded-full border text-[11px]', i < idx ? 'border-ok bg-ok-soft text-ok' : i === idx ? 'border-accent bg-accent text-accent-ink' : 'border-rule')}>{i < idx ? <Check className="size-3" aria-hidden /> : i + 1}</span>
            {t(`setup.step.${k}`)}
          </li>
        ))}
      </ol>

      {step === 'account' && import.meta.env.VITE_API_MOCK !== 'off' ? (
        <section className="mt-6 flex flex-wrap items-center justify-between gap-3 rounded-md border border-dashed border-rule px-5 py-3" aria-labelledby="sample-title">
          <div className="grid max-w-md gap-0.5">
            <h2 id="sample-title" className="text-sm font-semibold">{t('setup.sample.title')}</h2>
            <p className="text-[13px] text-muted">{t('setup.sample.desc')}</p>
          </div>
          <Button onClick={() => void startWithSample()} disabled={submit.isPending}>{t('setup.sample.button')}</Button>
        </section>
      ) : null}
      <section className="mt-6 rounded-md border border-rule bg-surface p-5" aria-labelledby="step-title">
        <form noValidate onSubmit={(e) => { e.preventDefault(); if (step === 'channel') void finish(true); else next() }}>
        <h2 id="step-title" ref={heading} tabIndex={-1} className="text-lg font-semibold outline-none">{t(`setup.${step}.title`)}</h2>
        <p className="mt-1 text-sm text-muted">{t(`setup.${step}.desc`)}</p>

        {step === 'account' ? (
          <div className="mt-4 grid gap-4">
            <Field label={t('setup.account.code')} hint={t('setup.account.codeHint')} htmlFor="s-code" error={errors.code}><Input id="s-code" autoComplete="off" spellCheck={false} value={s.code} aria-invalid={!!errors.code} onChange={(e) => set({ code: e.target.value })} /></Field>
            <Field label={t('setup.account.org')} htmlFor="s-org" error={errors.org}><Input id="s-org" autoComplete="organization" value={s.org} aria-invalid={!!errors.org} onChange={(e) => set({ org: e.target.value })} /></Field>
            <Field label={t('setup.account.name')} htmlFor="s-name" error={errors.name}><Input id="s-name" autoComplete="name" value={s.name} aria-invalid={!!errors.name} onChange={(e) => set({ name: e.target.value })} /></Field>
            <Field label={t('setup.account.email')} htmlFor="s-email" error={errors.email}><Input id="s-email" type="email" autoComplete="username" value={s.email} aria-invalid={!!errors.email} onChange={(e) => set({ email: e.target.value })} /></Field>
            <Field label={t('setup.account.password')} hint={t('setup.account.passwordHint', { min: MIN_PASSWORD })} htmlFor="s-pw" error={errors.password}><Input id="s-pw" type="password" autoComplete="new-password" value={s.password} aria-invalid={!!errors.password} onChange={(e) => set({ password: e.target.value })} /></Field>
            <Field label={t('setup.account.again')} htmlFor="s-again" error={errors.again}><Input id="s-again" type="password" autoComplete="new-password" value={s.again} aria-invalid={!!errors.again} onChange={(e) => set({ again: e.target.value })} /></Field>
          </div>
        ) : null}

        {step === 'network' ? (
          <div className="mt-4 grid gap-4">
            <fieldset className="grid gap-2">
              <legend className="text-sm font-medium">{t('setup.network.lan')}</legend>
              <p className="text-[13px] text-muted">{t('setup.network.lanHint')}</p>
              {s.lan.map((v, i) => (
                <div key={i} className="grid gap-1">
                  <div className="flex items-center gap-2">
                    <Input aria-label={t('setup.network.lanRow', { n: i + 1 })} aria-invalid={!!errors[`lan${i}`]} className="max-w-xs font-mono" value={v} placeholder={i === 0 ? '192.168.10.0/24' : '10.0.0.0/16'} inputMode="decimal"
                      onChange={(e) => set({ lan: s.lan.map((x, k) => (k === i ? e.target.value : x)) })}
                      onBlur={() => {
                        const n = normaliseCidr(v)
                        if (!n?.note) return
                        set({ lan: s.lan.map((x, k) => (k === i ? n.value : x)), notes: [...s.notes.filter((x) => x.to !== n.value), { to: n.value, text: t(`setup.network.note.${n.note}`, { from: v.trim(), to: n.value }) }] })
                      }} />
                    <Button variant="ghost" size="icon" aria-label={t('setup.network.lanRemove', { n: i + 1 })} disabled={s.lan.length === 1} title={s.lan.length === 1 ? t('setup.network.lanKeepOne') : undefined}
                      onClick={() => set({ lan: s.lan.filter((_, k) => k !== i) })}><Trash2 /></Button>
                  </div>
                  {errors[`lan${i}`] ? <p role="alert" className="text-[13px] text-danger">{errors[`lan${i}`]}</p> : null}
                </div>
              ))}
              {errors.lanAll ? <p role="alert" className="text-[13px] text-danger">{errors.lanAll}</p> : null}
              <div><Button size="sm" onClick={() => set({ lan: [...s.lan, ''] })} disabled={s.lan.length >= 16}><Plus />{t('setup.network.lanAdd')}</Button></div>
              {s.notes.some((n) => s.lan.includes(n.to)) ? <ul className="grid gap-1 text-[13px] text-muted" aria-label={t('setup.network.noteLabel')}>{s.notes.filter((n) => s.lan.includes(n.to)).map((n) => <li key={n.to}>{n.text}</li>)}</ul> : null}
            </fieldset>
            <div className="grid gap-3 rounded-md border border-rule bg-sunken p-4">
              <div className="flex items-start gap-2.5">
                <Checkbox id="s-commit" checked={s.commitment} onCheckedChange={(v) => set({ commitment: v === true })} className="mt-0.5" />
                <label htmlFor="s-commit" className="text-sm">{t('setup.network.commitment')}</label>
              </div>
              {s.commitment ? null : <p className="text-[13px] text-muted">{t('setup.network.passiveOnly')}</p>}
              <p className="text-[13px] text-muted">{t('setup.network.license')}</p>
            </div>
          </div>
        ) : null}

        {step === 'modules' ? <ModulesStep s={s} set={set} error={errors.modules} /> : null}

        {step === 'channel' ? <ChannelStep s={s} set={set} errors={errors} /> : null}

        {formError ? <p role="alert" className="mt-4 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{formError}</p> : null}

        <div className="mt-6 flex flex-wrap items-center justify-between gap-2">
          <Button onClick={() => { setErrors({}); setStep(STEPS[idx - 1] ?? step) }} disabled={idx === 0 || submit.isPending}>{t('setup.back')}</Button>
          {step === 'channel' ? (
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => void finish(false)} disabled={submit.isPending}>{setupDone ? t('setup.channel.skipDone') : t('setup.channel.skip')}</Button>
              <Button type="submit" variant="primary" disabled={submit.isPending}>{t('setup.finish')}</Button>
            </div>
          ) : <Button type="submit" variant="primary">{t('setup.next')}</Button>}
        </div>
        </form>
      </section>

    </main>
  )
}

function ModulesStep({ s, set, error }: { s: State; set: (p: Partial<State>) => void; error?: string }) {
  const { t } = useTranslation('core')
  const q = useSetupModules()
  const name = (id: ModuleId) => t(`modules.${id}.name`, { ns: 'common' })
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const all = q.data.modules
  const choose = (b: BundleId) => set({ bundle: b, picked: b === 'custom' ? new Set(s.picked.size > 1 ? s.picked : BUNDLES.smb) : new Set(BUNDLES[b]) })
  const toggle = (id: ModuleId, on: boolean) => set({ picked: on ? closure(id, all, s.picked) : without(id, all, s.picked) })
  return (
    <div className="mt-4 grid gap-4">
      <RadioGroup value={s.bundle} onValueChange={(v) => choose(v as BundleId)} aria-label={t('setup.modules.title')}>
        {(['smb', 'mid', 'custom'] as const).map((b) => (
          <div key={b} className={cn('flex items-start gap-3 rounded-md border p-3', s.bundle === b ? 'border-accent bg-accent-soft' : 'border-rule')}>
            <RadioItem id={`bundle-${b}`} value={b} className="mt-0.5" />
            <label htmlFor={`bundle-${b}`} className="grid gap-0.5 text-sm">
              <span className="font-medium">{t(`setup.modules.${b}.name`)}</span>
              <span className="text-[13px] text-muted">{t(`setup.modules.${b}.desc`)}</span>
              {b !== 'custom' ? <span className="text-[13px] text-muted">{BUNDLES[b].filter((m) => m !== 'core').map(name).join(', ')}</span> : null}
            </label>
          </div>
        ))}
      </RadioGroup>
      {s.bundle === 'custom' ? (
        <fieldset className="grid gap-2 rounded-md border border-rule p-3">
          <legend className="px-1 text-sm font-medium">{t('setup.modules.pick')}</legend>
          <p className="text-[13px] text-muted">{t('setup.modules.pickHint')}</p>
          {all.filter((m) => m.tier !== 'core').map((m) => (
            <div key={m.id} className="flex items-start gap-2.5">
              <Checkbox id={`m-${m.id}`} checked={s.picked.has(m.id)} onCheckedChange={(v) => toggle(m.id, v === true)} className="mt-0.5" />
              <label htmlFor={`m-${m.id}`} className="grid text-sm"><span>{name(m.id)}</span>{m.depends.filter((d) => d !== 'core').length ? <span className="text-[12px] text-muted">{t('setup.modules.needs', { list: m.depends.filter((d) => d !== 'core').map(name).join(', ') })}</span> : null}</label>
            </div>
          ))}
        </fieldset>
      ) : null}
      {error ? <p role="alert" className="text-[13px] text-danger">{error}</p> : null}
    </div>
  )
}

function ChannelStep({ s, set, errors }: { s: State; set: (p: Partial<State>) => void; errors: Record<string, string> }) {
  const { t } = useTranslation('core')
  const f = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => set({ ch: { ...s.ch, [k]: e.target.value } })
  return (
    <div className="mt-4 grid gap-4">
      <Segmented<ChannelType> label={t('setup.channel.type')} value={s.chType} onChange={(v) => set({ chType: v, chSecret: '' })} options={[{ value: 'telegram', label: 'Telegram' }, { value: 'zalo', label: 'Zalo OA' }, { value: 'email', label: 'Email' }]} />
      {CH_FIELDS[s.chType].map((k) => (
        <Field key={k} label={t(`setup.channel.field.${k}`)} htmlFor={`ch-${k}`} error={errors[k]}>
          <Input id={`ch-${k}`} type={k === 'port' ? 'number' : 'text'} value={s.ch[k] ?? ''} aria-invalid={!!errors[k]} onChange={f(k)} />
        </Field>
      ))}
      {s.chType === 'email' ? (
        <Field label={t('setup.channel.field.security')} htmlFor="ch-security">
          <Select id="ch-security" value={s.ch.security ?? 'starttls'} onChange={f('security')}><option value="starttls">STARTTLS</option><option value="ssl">SSL/TLS</option><option value="none">{t('setup.channel.noEncryption')}</option></Select>
        </Field>
      ) : null}
      <Field label={t(`setup.channel.secret.${s.chType}`)} hint={t('setup.channel.secretHint')} htmlFor="ch-secret" error={errors.secret}>
        <Input id="ch-secret" type="password" autoComplete="off" value={s.chSecret} aria-invalid={!!errors.secret} onChange={(e) => set({ chSecret: e.target.value })} />
      </Field>
      <p className="text-[13px] text-muted">{t('setup.channel.later')}</p>
    </div>
  )
}
