// Zalo personal set-up in the channel dialog (S-NOT-1, S-RESP-2, D-447): a real QR sign-in, the recipient picked from the account's groups
// and friends (or found from an invite link or a phone number), and approvers who confirm, signed in as themselves, the link the box sends
// to their Zalo (your own Zalo: you confirm it now, in this session).
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { QrCode, TriangleAlert } from 'lucide-react'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Field, Input, Select } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { cancelZaloLogin, useLinkApprovers, useResolveZalo, useSendLink, useStartZaloLogin, useZaloContacts, useZaloLogin, type LinkKind } from './api'
import type { Approver, Channel, ZaloContact, ZaloLogin } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))
const NEW_QR: ZaloLogin['state'][] = ['expired', 'declined', 'failed']

/** One neutral line, not an alarm (Z4): the channel is unofficial and the account can be locked. */
export function ZaloWarning() {
  const { t } = useTranslation('notify')
  return <p role="note" className="flex items-start gap-2 text-[13px] text-warn"><TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />{t('zp.warning')}</p>
}

/** The QR code, redrawn by the box as one SVG path on a white square (the quiet zone is part of the view box). */
function QrImage({ size, path, label }: { size: number; path: string; label: string }) {
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${size} ${size}`} className="size-48 rounded-md border border-rule" shapeRendering="crispEdges">
      <rect width={size} height={size} fill="#fff" />
      <path d={path} fill="#000" />
    </svg>
  )
}

/** Sign in with a QR code. onSigned gets the account's name once the box has really signed in; Save then keeps that session. */
export function ZaloSignIn({ channel, onSigned }: { channel: Channel; onSigned: (name: string | null) => void }) {
  const { t } = useTranslation('notify')
  const qc = useQueryClient()
  const [started, setStarted] = useState(false)
  const login = useZaloLogin(started)
  const start = useStartZaloLogin()
  const [err, setErr] = useState<string | null>(null)
  const v = started ? login.data : undefined
  const signedName = v?.state === 'signed_in' ? v.name : null
  const seen = useRef<string | null>(null)
  useEffect(() => {
    if (signedName === seen.current) return
    seen.current = signedName
    onSigned(signedName)
    if (signedName) void qc.invalidateQueries({ queryKey: ['zalo-contacts'] }) // another account: another contact list
  }, [signedName, onSigned, qc])
  // A sign-in still waiting when the dialog closes is cancelled, so it does not hold the box's one sign-in.
  useEffect(() => () => { if (started) void cancelZaloLogin().catch(() => undefined) }, [started])
  async function begin() {
    setErr(null)
    try { await start.mutateAsync(); setStarted(true) } catch (e) { setErr(errMsg(e)) }
  }
  const saved = channel.fields.account
  return (
    <div className="grid gap-2 rounded-md border border-rule p-3">
      <span className="text-sm font-medium">{t('zp.login')}</span>
      <p className="text-[13px] text-muted">{signedName ? t('zp.signedNew', { name: signedName }) : saved ? t('zp.signedSaved', { name: saved }) : channel.secret_last4 ? t('zp.sessionSaved') : t('zp.none')}</p>
      {v && v.qr && (v.state === 'waiting' || v.state === 'scanned') ? (
        <div className="grid justify-items-start gap-2">
          <QrImage size={v.qr.size} path={v.qr.path} label={t('zp.qrAlt')} />
          <p role="status" className="text-[13px]">{v.state === 'scanned' ? (v.name ? t('zp.scannedBy', { name: v.name }) : t('zp.scannedConfirm')) : t('zp.scan', { time: v.expires_at ? fmtDateTime(v.expires_at) : '' })}</p>
        </div>
      ) : null}
      {v && NEW_QR.includes(v.state) ? <p role="status" className="text-[13px] text-danger">{v.state === 'failed' ? v.error : t(`zp.state.${v.state}`)}</p> : null}
      {err ? <p role="alert" className="text-[13px] text-danger">{err}</p> : null}
      <p className="text-[13px] text-muted">{t('zp.signOutHint')}</p>
      {!v || v.state === 'none' || NEW_QR.includes(v.state) || v.state === 'signed_in' ? (
        <div><Button disabled={start.isPending} onClick={() => void begin()}><QrCode />{v && v.state !== 'none' && v.state !== 'signed_in' ? t('zp.newQr') : saved || channel.secret_last4 || signedName ? t('zp.relogin') : t('zp.show')}</Button></div>
      ) : null}
    </div>
  )
}

/** Find a person or a group from an invite link, a phone number or a typed ID (the box answers; it never guesses). */
function Finder({ id, label, hint, onFound, groups }: { id: string; label: string; hint: string; onFound: (c: ZaloContact, member: boolean) => void; groups: boolean }) {
  const { t } = useTranslation('notify')
  const resolve = useResolveZalo()
  const [q, setQ] = useState('')
  const [err, setErr] = useState<string | null>(null)
  async function find() {
    setErr(null)
    try {
      const f = await resolve.mutateAsync(q.trim())
      if (f.group && !groups) { setErr(t('zp.notAGroup')); return }
      onFound(f, f.member); setQ('')
    } catch (e) { setErr(errMsg(e)) }
  }
  return (
    <div className="flex flex-wrap items-end gap-2">
      <Field label={label} hint={hint} htmlFor={id} error={err ?? undefined} className="min-w-56 flex-1">
        <Input id={id} value={q} autoComplete="off" aria-invalid={err ? true : undefined} aria-describedby={`${id}-${err ? 'error' : 'hint'}`}
          onChange={(e) => { setQ(e.target.value); setErr(null) }} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void find() } }} />
      </Field>
      <Button disabled={!q.trim() || resolve.isPending} onClick={() => void find()}>{t('zp.find')}</Button>
    </div>
  )
}

export interface ZaloTarget { user_id: string; group: boolean; name: string }

/** The recipient of alerts: a group or a friend of the account, picked or found. */
export function ZaloRecipient({ value, onChange, canLook, error }: { value: ZaloTarget; onChange: (v: ZaloTarget) => void; canLook: boolean; error?: string }) {
  const { t } = useTranslation('notify')
  const contacts = useZaloContacts(canLook)
  const [notMember, setNotMember] = useState<string | null>(null)
  const pick = (c: ZaloContact, member = true) => { onChange({ user_id: c.id, group: c.group, name: c.name }); setNotMember(member ? null : c.name || c.id) }
  const all = [...(contacts.data?.groups ?? []), ...(contacts.data?.friends ?? [])]
  const id = 'ch-zalo-personal-user_id'
  return (
    <fieldset className="grid gap-3 rounded-md border border-rule p-3">
      <legend className="px-1 text-sm font-medium">{t('zp.recipient')}</legend>
      <p id={`${id}-now`} className="text-[13px]">{value.user_id ? t(value.group ? 'zp.toGroup' : 'zp.toPerson', { name: value.name || value.user_id, id: value.user_id }) : t('zp.noRecipient')}</p>
      {error ? <p role="alert" className="text-[13px] text-danger">{error}</p> : null}
      {canLook ? (
        <Field label={t('zp.pick')} hint={contacts.isError ? errMsg(contacts.error) : t('zp.pickHint')} htmlFor={`${id}-pick`}>
          <Select id={`${id}-pick`} value={all.some((c) => c.id === value.user_id) ? value.user_id : ''} disabled={!contacts.data} aria-describedby={`${id}-pick-hint`}
            onChange={(e) => { const c = all.find((x) => x.id === e.target.value); if (c) pick(c) }}>
            <option value="">{contacts.isLoading ? t('zp.loading') : t('zp.choose')}</option>
            {contacts.data?.groups.length ? <optgroup label={t('zp.groups')}>{contacts.data.groups.map((g) => <option key={g.id} value={g.id}>{g.members ? t('zp.groupOption', { name: g.name || g.id, count: g.members }) : g.name || g.id}</option>)}</optgroup> : null}
            {contacts.data?.friends.length ? <optgroup label={t('zp.friends')}>{contacts.data.friends.map((f) => <option key={f.id} value={f.id}>{f.name || f.id}</option>)}</optgroup> : null}
          </Select>
        </Field>
      ) : <p className="text-[13px] text-muted">{t('zp.signInToPick')}</p>}
      <Finder id={id} label={t('zp.findLabel')} hint={t('zp.findHint')} groups onFound={pick} />
      {notMember ? <p role="status" className="text-[13px] text-warn">{t('zp.notMember', { name: notMember })}</p> : null}
    </fieldset>
  )
}

/** One approver's Zalo: picked from the account's friends or found by phone number; its link state once saved. */
export function LinkApproverField({ approver, saved, onChange, canLook }: { approver: Approver; saved: Channel | null; onChange: (a: Approver) => void; canLook: boolean }) {
  const { t } = useTranslation('notify')
  const contacts = useZaloContacts(canLook)
  const id = `ap-zalo-personal-${approver.user_id}`
  const friends = contacts.data?.friends ?? []
  return (
    <div className="grid gap-2">
      <p className="text-[13px]">{approver.address ? t('zp.approverIs', { name: approver.name || approver.address, id: approver.address }) : t('zp.approverNone')}</p>
      {canLook && friends.length ? (
        <Field label={t('zp.approverPick')} htmlFor={`${id}-pick`}>
          <Select id={`${id}-pick`} value={friends.some((f) => f.id === approver.address) ? approver.address : ''} onChange={(e) => { const f = friends.find((x) => x.id === e.target.value); if (f) onChange({ ...approver, address: f.id, name: f.name }) }}>
            <option value="">{t('zp.choose')}</option>
            {friends.map((f) => <option key={f.id} value={f.id}>{f.name || f.id}</option>)}
          </Select>
        </Field>
      ) : null}
      <Finder id={id} label={t('zp.approverFind')} hint={t('zp.approverFindHint')} groups={false} onFound={(c) => onChange({ ...approver, address: c.id, name: c.name })} />
      {saved ? <ApproverLinkState kind="zalo" approver={approver} saved={saved} /> : approver.address ? <p className="text-[13px] text-muted">{t('zp.link.unsaved')}</p> : null}
    </div>
  )
}

/** Linked, or waiting for the person to confirm the link; Send again makes a new link (the old one stops working). Your own row with the
 * box's own Zalo: link it now. Only for a saved approver. Zalo personal (D-447) and Telegram (D-414). */
export function ApproverLinkState({ kind, approver, saved }: { kind: LinkKind; approver: Approver; saved: Channel }) {
  const { t } = useTranslation('notify')
  const navigate = useNavigate()
  const on = saved.configured && saved.approvals
  const states = useLinkApprovers(kind, on)
  const send = useSendLink(kind)
  const s = states.data?.items.find((x) => x.user_id === approver.user_id && x.address === approver.address)
  const unsaved = kind === 'zalo' ? t('zp.link.unsaved') : t('tg.unsaved')
  if (!on || !s) return approver.address ? <p className="text-[13px] text-muted">{unsaved}</p> : null
  const who = s.name || s.address
  const again = () => send.mutate(approver.user_id, {
    onSuccess: (v) => { if (v.link) void navigate(v.link); else toast.success(t('zp.link.sentToast', { name: who })) },
    onError: (e) => toast.error(errMsg(e)),
  })
  if (s.state !== 'linked' && s.self && s.box_account) { // the box's own account, proved by the QR sign-in: confirm it here
    return (
      <div className="flex flex-wrap items-center gap-2 text-[13px]" role="status">
        <Chip tone="warn">{t('zp.link.not_sent')}</Chip>
        <span>{t('zp.link.yours')}</span>
        <Button size="sm" variant="primary" disabled={send.isPending} onClick={again}>{t('zp.link.mine')}</Button>
      </div>
    )
  }
  return (
    <div className="flex flex-wrap items-center gap-2 text-[13px]" role="status">
      {s.state === 'linked' ? <Chip tone="ok">{t('zp.link.linked')}</Chip> : <Chip tone="warn">{t(`zp.link.${s.state}`)}</Chip>}
      {s.state === 'waiting' ? <span>{t('zp.link.waitingFor', { name: who, time: s.sent_at ? fmtDateTime(s.sent_at) : '' })}</span> : null}
      {s.state === 'not_sent' && s.error ? <span className="text-danger">{s.error}</span> : null}
      {s.state === 'waiting' || s.state === 'not_sent' ? <Button size="sm" disabled={send.isPending} onClick={again}>{t('zp.link.again')}</Button> : null}
    </div>
  )
}
