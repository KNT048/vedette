// My account → Approval channels (S-RESP-2, D-191): I prove the address or ID an administrator typed for me on each approval channel.
// Mounted by the account page only for operators and admins while the response module is on.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { Section } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { PreviewCode } from '@/features/core/parts'
import { useCountdown } from '@/features/core/useCountdown'
import { errText } from './api'
import type { CodeSent, Identity, IdentityList } from './types'

const enc = encodeURIComponent

function useIdentities() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['response', 'me', 'identities'], queryFn: () => api.get<IdentityList>('/response/me/identities') })
  const done = { onSettled: () => { void qc.invalidateQueries({ queryKey: ['response'] }) } }
  const send = useMutation({ mutationFn: (ch: string) => api.post<CodeSent>(`/response/me/identities/${enc(ch)}/code`), ...done })
  const confirm = useMutation({ mutationFn: (v: { ch: string; code: string }) => api.post<Identity>(`/response/me/identities/${enc(v.ch)}/confirm`, { code: v.code }), ...done })
  const unlink = useMutation({ mutationFn: (ch: string) => api.del<void>(`/response/me/identities/${enc(ch)}`), ...done })
  return { q, send, confirm, unlink }
}

function Row({ r, m }: { r: Identity; m: ReturnType<typeof useIdentities> }) {
  const { t } = useTranslation('response')
  const [code, setCode] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [sent, setSent] = useState<CodeSent | null>(null)
  const cooldown = useCountdown()
  const id = `ident-${r.channel}`
  async function send() {
    setErr(null)
    try { const s = await m.send.mutateAsync(r.channel); setSent(s); cooldown.start(s.resend_after) } catch (e) { setErr(errText(e)) }
  }
  async function confirm(e: React.FormEvent) {
    e.preventDefault()
    setErr(null)
    if (!/^\d{6}$/.test(code.trim())) { setErr(t('identity.codeShape')); return }
    try { await m.confirm.mutateAsync({ ch: r.channel, code: code.trim() }); setCode(''); setSent(null); toast.success(t('identity.linkedToast', { channel: r.label })) } catch (e2) { setErr(errText(e2)) }
  }
  async function unlink() {
    try { await m.unlink.mutateAsync(r.channel); toast.success(t('identity.unlinkedToast', { channel: r.label })) } catch (e) { toast.error(errText(e)) }
  }
  const askCode = r.method === 'chat_code' || sent || r.code_waiting
  if (r.method === 'unavailable' && !r.linked) {
    return (
      <li className="grid gap-2 rounded-md border border-rule bg-surface p-4" aria-labelledby={`${id}-title`}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p id={`${id}-title`} className="text-sm"><span className="font-semibold">{r.label}</span> <span className="break-all font-mono text-[13px] text-muted">{r.address}</span></p>
          <Chip tone="off">{t('identity.notLinked')}</Chip>
        </div>
        <p className="text-[13px] text-muted">{t('identity.unavailable', { channel: r.label })}</p>
      </li>
    )
  }
  return (
    <li className="grid gap-3 rounded-md border border-rule bg-surface p-4" aria-labelledby={`${id}-title`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p id={`${id}-title`} className="text-sm"><span className="font-semibold">{r.label}</span> <span className="break-all font-mono text-[13px] text-muted">{r.address}</span></p>
        {r.linked ? <Chip tone="ok">{t('identity.linked')}</Chip> : <Chip tone="warn">{t('identity.notLinked')}</Chip>}
      </div>
      {r.linked ? (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-[13px] text-muted">{t('identity.linkedAt', { at: fmtDateTime(r.linked_at) })}</p>
          <Button onClick={() => void unlink()} disabled={m.unlink.isPending}>{t('identity.unlink')}</Button>
        </div>
      ) : (
        <form onSubmit={(e) => void confirm(e)} className="grid gap-3" noValidate>
          <p className="text-[13px]">{r.method === 'email_code' ? t('identity.howEmail') : t('identity.howChat', { channel: r.label })}</p>
          {sent ? <><p className="text-[13px]" role="status">{t('identity.sent', { to: sent.sent_to })}</p><PreviewCode code={sent.preview_code} /></> : null}
          {askCode ? (
            <Field label={t('identity.code')} htmlFor={`${id}-code`} error={err ?? undefined}>
              <Input id={`${id}-code`} inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} aria-invalid={!!err} onChange={(e) => setCode(e.target.value)} className="max-w-40" />
            </Field>
          ) : err ? <p className="text-[13px] text-danger" role="alert">{err}</p> : null}
          <div className="flex flex-wrap gap-2">
            {askCode ? <Button type="submit" variant="primary" disabled={m.confirm.isPending}>{t('identity.confirm')}</Button> : null}
            {r.method === 'email_code'
              ? <Button variant={askCode ? undefined : 'primary'} disabled={cooldown.left > 0 || m.send.isPending} onClick={() => void send()}>{cooldown.left > 0 ? t('identity.resendIn', { s: cooldown.left }) : sent || r.code_waiting ? t('identity.resend') : t('identity.send')}</Button>
              : null}
          </div>
        </form>
      )}
    </li>
  )
}

export function ApproverIdentities() {
  const { t } = useTranslation('response')
  const m = useIdentities()
  return (
    <Section title={t('identity.title')} description={t('identity.desc')} stories={['S-RESP-2']} id="approver-identities">
      <QueryState query={m.q}>{(d) => d.items.length
        ? <ul className="grid max-w-2xl gap-3">{d.items.map((r) => <Row key={`${r.channel}|${r.address}`} r={r} m={m} />)}</ul>
        : <p className="text-sm text-muted">{t('identity.none')}</p>}</QueryState>
    </Section>
  )
}
