// My account → Approval channels (S-RESP-2, D-191): I prove the address or ID an administrator typed for me on each approval channel
// (Telegram D-414 and Zalo personal D-447: status and Send again only; a confirm link comes to my chat account when an administrator saves me
// as an approver, and I confirm it on /link/<telegram|zalo>).
// Mounted by the account page only for operators and admins while the response module is on.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { InfoTip } from '@/components/common/InfoTip'
import { Section } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { PreviewCode } from '@/features/core/parts'
import { useCountdown } from '@/features/core/useCountdown'
import { errText } from './api'
import { useLeaving } from './frozen'
import type { CodeSent, Identity, IdentityList } from './types'

const enc = encodeURIComponent

function useIdentities() {
  const qc = useQueryClient()
  // A confirm link (send_code) is confirmed on its own page, maybe on another device: look again every 5 s while one is waiting.
  const q = useQuery({ queryKey: ['response', 'me', 'identities'], queryFn: () => api.get<IdentityList>('/response/me/identities'),
    refetchInterval: (s) => s.state.data?.items.some((r) => r.method === 'send_code' && !r.linked && r.code_waiting) ? 5000 : false })
  const done = { onSettled: () => { void qc.invalidateQueries({ queryKey: ['response'] }) } }
  const send = useMutation({ mutationFn: (ch: string) => api.post<CodeSent>(`/response/me/identities/${enc(ch)}/code`), ...done })
  const confirm = useMutation({ mutationFn: (v: { ch: string; code: string }) => api.post<Identity>(`/response/me/identities/${enc(v.ch)}/confirm`, { code: v.code }), ...done })
  const unlink = useMutation({ mutationFn: (ch: string) => api.del<void>(`/response/me/identities/${enc(ch)}`), ...done })
  return { q, send, confirm, unlink }
}

function Row({ r, m }: { r: Identity; m: ReturnType<typeof useIdentities> }) {
  const { t } = useTranslation('response')
  const navigate = useNavigate()
  const [code, setCode] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [sent, setSent] = useState<CodeSent | null>(null)
  const cooldown = useCountdown()
  const frozen = useLeaving()
  const id = `ident-${r.channel}`
  async function send() {
    setErr(null)
    try { const s = await m.send.mutateAsync(r.channel); setSent(s); cooldown.start(s.resend_after) } catch (e) { setErr(errText(e)) }
  }
  async function confirm(e: React.FormEvent) {
    e.preventDefault()
    setErr(null)
    try { await m.confirm.mutateAsync({ ch: r.channel, code: code.trim() }); setCode(''); setSent(null); toast.success(t('identity.linkedToast', { channel: r.label })) } catch (e2) { setErr(errText(e2)) }
  }
  async function unlink() {
    try { await m.unlink.mutateAsync(r.channel); toast.success(t('identity.unlinkedToast', { channel: r.label })) } catch (e) { toast.error(errText(e)) }
  }
  async function sendLink() {
    setErr(null)
    try {
      const s = await m.send.mutateAsync(r.channel)
      cooldown.start(s.resend_after)
      if (s.link) void navigate(s.link) // your own row with the box's own Zalo: confirm it here
      else toast.success(t('identity.sentLink', { to: s.sent_to }))
    } catch (e) { setErr(errText(e)) }
  }
  const askCode = sent || r.code_waiting
  // m is shared by every row: only the row acted on shows the busy state
  const sending = m.send.isPending && m.send.variables === r.channel
  // D-624 (M2): while AI response is on but not offered, a link can be removed and none added: an unlinked row shows its state only
  if (frozen && !r.linked) {
    return (
      <li className="grid gap-2 rounded-md border border-rule bg-surface p-4" aria-labelledby={`${id}-title`}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p id={`${id}-title`} className="text-sm"><span className="font-semibold">{r.label}</span> <span className="break-all font-mono text-meta text-muted">{r.address}</span></p>
          <Chip tone="off">{t('identity.notLinked')}</Chip>
        </div>
        <p className="text-meta text-muted">{t('leaving.noNewLink')}</p>
      </li>
    )
  }
  if (r.method === 'send_code' && !r.linked) {
    return (
      <li className="grid gap-3 rounded-md border border-rule bg-surface p-4" aria-labelledby={`${id}-title`}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p id={`${id}-title`} className="text-sm"><span className="font-semibold">{r.label}</span> <span className="break-all font-mono text-meta text-muted">{r.address}</span></p>
          <Chip tone="warn">{r.code_waiting ? t('identity.waiting') : t('identity.notLinked')}</Chip>
        </div>
        {/* D-414, D-447: status and Send again only; the link goes to this chat account and I confirm it signed in. */}
        {r.code_waiting ? <p className="text-meta">{t('identity.waitingNote', { channel: r.label })}</p>
          : <div className="flex items-center gap-1 text-meta"><p>{t('identity.howSend', { channel: r.label })}</p><InfoTip topic={r.label}>{t('identity.howSendInfo', { channel: r.label })}</InfoTip></div>}
        {err ? <p className="text-meta text-danger" role="alert">{err}</p> : null}
        <div><Button disabled={cooldown.left > 0 || m.send.isPending} busy={sending} busyLabel={t('common:busy.sending')} aria-describedby={`${id}-wait`} onClick={() => void sendLink()}>{cooldown.left > 0 ? t('identity.sendAgainIn', { s: cooldown.left }) : t('identity.sendAgain')}</Button></div>
        <BusyNote id={`${id}-wait`} busy={sending}>{t('identity.sendLinkWaiting', { channel: r.label })}</BusyNote>
      </li>
    )
  }
  if (r.method === 'unavailable' && !r.linked) {
    return (
      <li className="grid gap-2 rounded-md border border-rule bg-surface p-4" aria-labelledby={`${id}-title`}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p id={`${id}-title`} className="text-sm"><span className="font-semibold">{r.label}</span> <span className="break-all font-mono text-meta text-muted">{r.address}</span></p>
          <Chip tone="off">{t('identity.notLinked')}</Chip>
        </div>
        <div className="flex items-center gap-1 text-meta text-muted"><p>{t('identity.unavailable', { channel: r.label })}</p><InfoTip topic={r.label}>{t('identity.unavailableInfo', { channel: r.label })}</InfoTip></div>
      </li>
    )
  }
  return (
    <li className="grid gap-3 rounded-md border border-rule bg-surface p-4" aria-labelledby={`${id}-title`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p id={`${id}-title`} className="text-sm"><span className="font-semibold">{r.label}</span> <span className="break-all font-mono text-meta text-muted">{r.address}</span></p>
        {r.linked ? <Chip tone="ok">{t('identity.linked')}</Chip> : <Chip tone="warn">{t('identity.notLinked')}</Chip>}
      </div>
      {r.linked ? (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-meta text-muted">{t('identity.linkedAt', { at: fmtDateTime(r.linked_at) })}</p>
          <Button onClick={() => void unlink()} disabled={m.unlink.isPending} busy={m.unlink.isPending && m.unlink.variables === r.channel} busyLabel={t('common:busy.unlinking')}>{t('identity.unlink')}</Button>
        </div>
      ) : (
        <form onSubmit={(e) => void confirm(e)} className="grid gap-3" noValidate>
          <div className="flex items-center gap-1 text-meta"><p>{t('identity.howEmail')}</p><InfoTip topic={r.label}>{t('identity.howEmailInfo')}</InfoTip></div>
          {sent ? <><p className="text-meta" role="status">{t('identity.sent', { to: sent.sent_to })}</p><PreviewCode code={sent.preview_code} /></> : null}
          {askCode ? (
            <Field label={t('identity.code')} htmlFor={`${id}-code`} error={err ?? undefined}>
              <Input id={`${id}-code`} inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} aria-invalid={!!err} onChange={(e) => setCode(e.target.value)} className="max-w-40" />
            </Field>
          ) : err ? <p className="text-meta text-danger" role="alert">{err}</p> : null}
          <div className="flex flex-wrap gap-2">
            {/* no red error before anything is typed (D-414): Link waits for the 6 digits */}
            {askCode ? <Button type="submit" variant="primary" disabled={m.confirm.isPending || !/^\d{6}$/.test(code.trim())} busy={m.confirm.isPending && m.confirm.variables?.ch === r.channel} busyLabel={t('common:busy.linking')}>{t('identity.confirm')}</Button> : null}
            {r.method === 'email_code'
              ? <Button variant={askCode ? undefined : 'primary'} disabled={cooldown.left > 0 || m.send.isPending} busy={sending} busyLabel={t('common:busy.sending')} aria-describedby={`${id}-wait`} onClick={() => void send()}>{cooldown.left > 0 ? t('identity.resendIn', { s: cooldown.left }) : sent || r.code_waiting ? t('identity.resend') : t('identity.send')}</Button>
              : null}
          </div>
          {/* kien G1: the code goes out by email, which can take up to 30 s */}
          <BusyNote id={`${id}-wait`} busy={sending}>{t('identity.sendCodeWaiting')}</BusyNote>
        </form>
      )}
    </li>
  )
}

export function ApproverIdentities() {
  const { t } = useTranslation('response')
  const m = useIdentities()
  return (
    <Section title={t('identity.title')} description={t('identity.desc')} info={t('identity.descInfo')} stories={['S-RESP-2']} id="approver-identities">
      <QueryState query={m.q}>{(d) => d.items.length
        ? <ul className="grid max-w-2xl gap-3">{d.items.map((r) => <Row key={`${r.channel}|${r.address}`} r={r} m={m} />)}</ul>
        : <p className="text-sm text-muted">{t('identity.none')}</p>}</QueryState>
    </Section>
  )
}
