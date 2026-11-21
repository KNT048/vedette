import { useState, type FormEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Pencil, Trash2 } from 'lucide-react'
import { Notice } from '@/components/common/PageHeader'
import { ErrorState } from '@/components/common/States'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { ApiError } from '@/lib/api'
import { kindLabel } from '@/lib/deviceTypes'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { cn } from '@/lib/utils'
import { ScopeButton } from '@/features/scanning/Fixes'
import { useDeviceAction, useDeviceSnmp, useDeviceSnmpActions, useDeviceSources, useDismissSnmpNotices, useSnmp } from './api'
import { errMsg } from './kinds'
import { nameOf } from './nameOf'
import type { DeviceDetail, DeviceSnmp, DeviceSnmpInput, SnmpAuth, SnmpDeviceRow, SnmpPriv, SnmpState, SnmpVersion } from './types'
import { IPV4_RE_UI, isPrivateCidr, LOCAL_RANGE_NAMES } from './validate'

/** The SNMP port (RFC 3417): reads go there unless the device answers on another. */
const SNMP_PORT = 161
// Browser-side checks so a mistake shows at its field at once; the server checks the same rules again (contract.ts DeviceSnmpInput).
const PRINTABLE_RE = /^[\x20-\x7e]{1,64}$/
const USER_RE = /^[A-Za-z0-9._@-]{1,64}$/
const PORT_RE = /^[0-9]{1,5}$/

/** What the device did on a read (the others mean nothing was sent). */
const DEVICE_OUTCOME: ReadonlySet<string> = new Set(['no_answer', 'auth_failed', 'unknown_user', 'error'])
/** Not the address of one device: unspecified, loopback, multicast, reserved and broadcast, link-local (the server's bad_read_from). */
const RESERVED_RE = /^(0|127|22[4-9]|23\d|24\d|25[0-5])\.|^169\.254\./
const DOT: Record<SnmpState, string> = { working: 'bg-ok', not_answering: 'bg-danger', waiting: 'bg-warn', not_set_up: 'bg-off' }
const own = (d: DeviceDetail) => (IPV4_RE_UI.test(d.asset.ip ?? '') ? d.asset.ip : '')

/** The state of one device's SNMP in a coloured dot and plain words; the words carry the meaning, the dot only repeats it. */
export function SnmpStateLabel({ state }: { state: SnmpState }) {
  const { t } = useTranslation('inventory')
  return (
    <span className="inline-flex items-center gap-2 text-sm font-medium">
      <span aria-hidden className={cn('size-2.5 shrink-0 rounded-full', DOT[state])} />
      {t(`deviceSnmp.state.${state}`)}
    </span>
  )
}

/** Everything the SNMP row of a device's Sources list needs: the device's SNMP state, the other devices' settings (to copy from), and
 *  the person's dialogs (check, edit, remove) and the last Check now message. `enabled` is false for a device or person that has no
 *  SNMP row (not an admin, active discovery off): nothing is asked of the box then. */
export function useSnmpSource(d: DeviceDetail, enabled: boolean) {
  const { t } = useTranslation('inventory')
  const id = d.asset.id
  const q = useDeviceSnmp(id, enabled)
  const list = useSnmp(enabled)
  const act = useDeviceSnmpActions(id)
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [checking, setChecking] = useState(false)
  const [checked, setChecked] = useState<{ message: string } | null>(null)
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  /** Check now: read the device at once and open the dialog that shows the answer, the settings and what answered. */
  const check = () => {
    setChecked(null)
    setChecking(true)
    act.check.mutate(undefined, {
      onSuccess: (r) => {
        qc.setQueryData(['inventory', 'snmp', 'device', id], r.snmp)
        void qc.invalidateQueries({ queryKey: ['inventory', 'device', id, 'sources'] })
        if (r.ok) toast.success(t('deviceSnmp.check.answered', { name }))
        // the device itself did not answer: the state says why; a refusal (nothing sent) is said in the dialog
        else if (DEVICE_OUTCOME.has(r.reason)) toast.error(t('deviceSnmp.check.noAnswer', { name }))
        else setChecked({ message: r.message })
      },
      onError: (e) => setChecked({ message: errMsg(e) }),
    })
  }
  // the routes answer 404 module_off while active discovery is off (the module list may lag a moment): no SNMP row content then
  const off = q.error instanceof ApiError && q.error.status === 404
  return { q, list, act, editing, setEditing, removing, setRemoving, checking, setChecking, checked, setChecked, check, name, off }
}
export type SnmpSource = ReturnType<typeof useSnmpSource>

/** Why SNMP sends nothing to the device now, under its row, with the fix where it can be made (moved, secret lost, switched off…). */
export function SnmpBlockedLine({ d, src }: { d: DeviceDetail; src: SnmpSource }) {
  const s = src.q.data
  if (src.off || !s?.blocked) return null
  return <Blocked d={d} s={s} onEdit={() => src.setEditing(true)} />
}

/** The dialogs of the SNMP row: Check now (the state and why, the settings, the times and what answered, with Edit and Remove), the
 *  settings form, and the removal confirmation. */
export function SnmpDialogs({ d, src }: { d: DeviceDetail; src: SnmpSource }) {
  const { t } = useTranslation('inventory')
  const id = d.asset.id
  const { q, list, act, checked, name } = src
  if (src.off) return null
  const s = q.data
  const ip = own(d)
  const edit = () => { src.setChecking(false); src.setEditing(true) }
  return (
    <>
      <Dialog open={src.checking} onOpenChange={(o) => { if (!o) src.setChecking(false) }}>
        <DialogContent wide title={t('deviceSnmp.checkTitle', { name })}>
          <div className="grid min-w-0 gap-3 [&>*]:min-w-0" data-testid="snmp-state">
            {list.data && !list.data.ready ? <Notice tone="warn" role="status" className="mb-0" title={t('deviceSnmp.notReady')}>{list.data.message}</Notice> : null}
            <BusyNote busy={act.check.isPending}>{(s?.read_from ?? ip) ? t('deviceSnmp.check.pending', { ip: s?.read_from ?? ip }) : t('deviceSnmp.check.pendingNoIp')}</BusyNote>
            {checked && !act.check.isPending ? <Notice tone="danger" role="alert" className="mb-0" title={t('deviceSnmp.check.failed')}>{checked.message}</Notice> : null}
            {q.isPending ? <p className="text-meta text-muted">{t('common:loading')}</p>
              : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} />
              : <StateView d={d} s={q.data} onEdit={edit} />}
          </div>
          <DialogFooter>
            {s && s.state !== 'not_set_up' ? (
              <span className="mr-auto flex flex-wrap gap-2">
                <Button onClick={edit}><Pencil />{t('deviceSnmp.edit')}</Button>
                <Button onClick={() => { src.setChecking(false); src.setRemoving(true) }}><Trash2 />{t('deviceSnmp.remove')}</Button>
              </span>
            ) : null}
            <Button busy={act.check.isPending} busyLabel={t('common:busy.checking')} onClick={src.check}>{t('deviceSnmp.check.again')}</Button>
            <DialogClose asChild><Button variant="primary">{t('common:close')}</Button></DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {src.editing && s ? <SnmpDialog d={d} s={s} others={(list.data?.devices ?? []).filter((x) => x.device_id !== id)} onClose={() => src.setEditing(false)} /> : null}
      <Dialog open={src.removing} onOpenChange={(o) => { if (!o) src.setRemoving(false) }}>
        <DialogContent title={t('deviceSnmp.removeTitle', { name })} description={t('deviceSnmp.removeBody')}>
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button variant="danger" busy={act.remove.isPending} busyLabel={t('common:busy.removing')}
              onClick={() => act.remove.mutate(undefined, {
                onSuccess: () => { src.setRemoving(false); src.setChecked(null); toast.success(t('deviceSnmp.removed', { name })) },
                onError: (e) => toast.error(errMsg(e)),
              })}>{t('deviceSnmp.removeConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

function When({ at, none }: { at: string | null; none: string }) {
  return at ? <time dateTime={at} title={fmtDateTime(at)}>{fmtRelative(at)}</time> : <span className="text-muted">{none}</span>
}

function Mask({ last4 }: { last4: string }) {
  const { t } = useTranslation('inventory')
  return last4 ? <span className="whitespace-nowrap font-mono text-meta">{t('agents.tokenMask', { last4 })}</span> : <span className="text-muted">{t('deviceSnmp.secretShort')}</span>
}

/** What Check now shows: the state and why, the settings (secrets as their last 4 characters), the times, and what answered. */
function StateView({ d, s, onEdit }: { d: DeviceDetail; s: DeviceSnmp; onEdit: () => void }) {
  const { t } = useTranslation('inventory')
  const row = (label: string, value: ReactNode) => <div className="contents"><dt className="text-meta text-muted">{label}</dt><dd className="min-w-0 text-sm [overflow-wrap:anywhere]">{value}</dd></div>
  if (s.state === 'not_set_up') {
    return (
      <div className="grid gap-1.5">
        <SnmpStateLabel state="not_set_up" />
        <p className="max-w-3xl text-meta text-muted">{own(d) ? t('deviceSnmp.notSetUpBody') : t('deviceSnmp.noIp')}</p>
      </div>
    )
  }
  const a = s.answer
  const answerRows = a ? ([
    ['sysName', a.sys_name], ['vendor', [a.vendor, a.product].filter(Boolean).join(' ')], ['model', a.model], ['serial', a.serial],
    ['firmware', a.firmware], ['os', a.os], ['kind', a.kind ? kindLabel(a.kind) : ''], ['objectId', a.sys_object_id],
  ] as [string, string][]).filter(([, v]) => v) : []
  return (
    <>
      <div className="grid gap-1.5">
        <SnmpStateLabel state={s.state} />
        <p className={cn('max-w-3xl text-meta', s.state === 'not_answering' ? 'text-danger' : 'text-muted')}>
          {s.state === 'working' ? t('deviceSnmp.why.working', { ip: s.read_from })
            : s.state === 'waiting' ? t('deviceSnmp.why.waiting')
            : s.error ?? t('deviceSnmp.why.notAnswering', { ip: s.read_from })}
        </p>
      </div>
      {s.blocked ? <Blocked d={d} s={s} onEdit={onEdit} /> : null}
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-[minmax(140px,max-content)_1fr]">
        {row(t('deviceSnmp.readFrom'), <>{s.read_from} <span className="text-meta text-muted">{s.read_from === s.ip ? t('deviceSnmp.readFromOwn') : t('deviceSnmp.readFromOther')}</span></>)}
        {row(t('deviceSnmp.version'), s.version === 'v3' ? t('deviceSnmp.v3User', { user: s.username ?? '' }) : t('deviceSnmp.v2c'))}
        {s.version === 'v2c' ? row(t('deviceSnmp.form.community'), <Mask last4={s.secret_last4} />) : (
          <>
            {row(t('deviceSnmp.form.auth'), <>{s.auth ? t(`deviceSnmp.authName.${s.auth}`) : ''} · <Mask last4={s.secret_last4} /></>)}
            {row(t('deviceSnmp.form.priv'), s.priv === 'aes128' ? <>{t('deviceSnmp.privName.aes128')} · <Mask last4={s.priv_last4} /></> : t('deviceSnmp.privName.none'))}
          </>
        )}
        {row(t('deviceSnmp.port'), t('deviceSnmp.portValue', { port: s.port ?? SNMP_PORT }))}
        {row(t('deviceSnmp.lastRead'), <When at={s.last_checked_at} none={t('deviceSnmp.notYet')} />)}
        {row(t('deviceSnmp.lastAnswer'), <When at={s.last_answer_at} none={t('deviceSnmp.never')} />)}
      </dl>
      {a ? (
        <div className="grid min-w-0 gap-2 border-t border-rule pt-3">
          <p className="text-sm font-medium">{t('deviceSnmp.answer.title', { ip: s.read_from })}</p>
          <dl className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-[minmax(140px,max-content)_1fr]">
            {answerRows.map(([k, v]) => <div key={k} className="contents"><dt className="text-meta text-muted">{t(`deviceSnmp.answer.${k}`)}</dt><dd className="min-w-0 text-sm [overflow-wrap:anywhere]">{v}</dd></div>)}
          </dl>
          {a.sys_descr ? <p className="text-meta text-muted [overflow-wrap:anywhere]">{t('deviceSnmp.answer.descr', { text: a.sys_descr })}</p> : null}
          <p className="text-caption text-muted">{t('deviceSnmp.answer.check')}</p>
        </div>
      ) : null}
    </>
  )
}

/** Why nothing is sent now, in the server's plain words, with the fix where it can be made here (docs/UI.md §0). */
function Blocked({ d, s, onEdit }: { d: DeviceDetail; s: DeviceSnmp; onEdit: () => void }) {
  const { t } = useTranslation('inventory')
  const sources = useDeviceSources(d.asset.id)
  const approve = useDeviceAction(d.asset.id).approve
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  const b = s.blocked!
  const reason = b.reason
  const fix = reason === 'moved' || reason === 'secret_lost' ? <Button size="sm" onClick={onEdit}>{t(`deviceSnmp.blocked.fix.${reason}`)}</Button>
    : reason === 'snmp_off' || reason === 'declared_by_hand' || reason === 'out_of_scope' ? (
      <Button size="sm" busy={sources.isPending} busyLabel={t('common:busy.turningOn')}
        onClick={() => sources.mutate({ snmp: 'on' }, { onSuccess: () => toast.success(t('sources.saved.snmp.on', { name })), onError: (e) => toast.error(errMsg(e)) })}>{t('deviceSnmp.blocked.fix.turnOn')}</Button>
    )
    : reason === 'not_approved' ? (
      <Button size="sm" busy={approve.isPending} busyLabel={t('common:busy.approving')}
        onClick={() => approve.mutate(undefined, { onSuccess: () => toast.success(t('pending.approved', { name })), onError: (e) => toast.error(errMsg(e)) })}>{t('deviceSnmp.blocked.fix.approve')}</Button>
    )
    : reason === 'scope_not_confirmed' ? <ScopeButton />
    : reason === 'scanning_off' ? <Link to="/settings/scanning?tab=engines" className="text-meta font-medium text-accent underline underline-offset-4">{t('deviceSnmp.blocked.fix.scanning')}</Link>
    : null
  return (
    <Notice tone={reason === 'secret_lost' ? 'danger' : 'warn'} role="status" className="mb-0" title={t(`deviceSnmp.blocked.title.${reason === 'moved' || reason === 'secret_lost' ? reason : 'other'}`)} actions={fix}>
      {b.message}
    </Notice>
  )
}

type Errors = Partial<Record<'copy' | 'read_from' | 'version' | 'community' | 'username' | 'auth' | 'auth_password' | 'priv' | 'priv_password' | 'port', ReactNode>>

/** Which field a refusal of PUT /inventory/snmp/devices/{id} belongs to; anything else is said above the buttons. */
const FIELD_OF: Record<string, keyof Errors | ((v: SnmpVersion, copy: boolean, msg: string) => keyof Errors)> = {
  read_from_not_local: 'read_from', bad_read_from: 'read_from', read_from_box: 'read_from', read_from_taken: 'read_from',
  copy_from_self: 'copy', copy_from_not_found: 'copy',
  secret_required: (v, copy) => (copy ? 'copy' : v === 'v2c' ? 'community' : 'auth_password'),
  bad_secret: (v, _c, msg) => (v === 'v2c' ? 'community' : /privacy/i.test(msg) ? 'priv_password' : 'auth_password'),
  bad_user: 'username', bad_auth: 'auth', bad_priv: 'priv', bad_port: 'port', bad_version: 'version',
}

/** Set up or edit the device's SNMP, or copy it from another device (the box copies the secret; it never reaches the browser). */
function SnmpDialog({ d, s, others, onClose }: { d: DeviceDetail; s: DeviceSnmp; others: SnmpDeviceRow[]; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const act = useDeviceSnmpActions(d.asset.id)
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  const setUp = s.state !== 'not_set_up'
  const switchOff = d.asset.snmp_source !== 'on'
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={setUp ? t('deviceSnmp.form.editTitle', { name }) : t('deviceSnmp.form.addTitle', { name })} description={t('deviceSnmp.form.body')} info={t('deviceSnmp.form.bodyInfo')}>
        <SnmpForm ip={own(d)} s={s} others={others} switchOff={switchOff} saving={act.save.isPending} onCancel={onClose} onLinkClick={onClose}
          save={(body) => act.save.mutateAsync(body).then(() => {
            toast.success(t('deviceSnmp.saved', { name }), switchOff ? { description: t('deviceSnmp.savedOn') } : undefined)
            onClose()
          })} />
      </DialogContent>
    </Dialog>
  )
}

export interface SnmpFormProps {
  /** The device's own address (the read address when none is typed); '' while the device has none. */
  ip: string
  /** The device's SNMP settings, or null while it has none. */
  s: DeviceSnmp | null
  others: SnmpDeviceRow[]
  /** The device's SNMP switch is off: saving turns it on, and the consent line says so. */
  switchOff: boolean
  saving: boolean
  /** Sends the settings; rejects with the box's refusal, which the form shows at its field. */
  save: (body: DeviceSnmpInput) => Promise<unknown>
  onCancel: () => void
  onLinkClick?: () => void
  submitLabel?: string
  /** Fields drawn above the SNMP fields (Add a device: address, name, product), and a check of them before anything is sent. */
  lead?: ReactNode
  precheck?: () => boolean
}

/** The SNMP settings form: Read from, version, community or v3 user, port, or copy from another device. In the device's settings
 *  dialog and in Add a device (the device is created first, then these are saved on it). */
export function SnmpForm({ ip, s, others, switchOff, saving, save, onCancel, onLinkClick, submitLabel, lead, precheck }: SnmpFormProps) {
  const { t } = useTranslation('inventory')
  const setUp = !!s && s.state !== 'not_set_up'
  const cur = setUp ? s : null
  const [copy, setCopy] = useState('')
  // a Read from left to the device's IP shows empty (the IP is the placeholder); a typed management address shows as typed
  const [readFrom, setReadFrom] = useState(setUp && !cur?.read_from_default ? (cur?.read_from ?? '') : '')
  const [version, setVersion] = useState<SnmpVersion>(cur?.version ?? 'v2c')
  const [community, setCommunity] = useState('')
  const [username, setUsername] = useState(cur?.username ?? '')
  const [auth, setAuth] = useState<SnmpAuth>(cur?.auth ?? 'sha256')
  const [authPassword, setAuthPassword] = useState('')
  const [priv, setPriv] = useState<SnmpPriv>(cur?.priv ?? 'aes128')
  const [privPassword, setPrivPassword] = useState('')
  const [port, setPort] = useState(cur?.port && cur?.port !== SNMP_PORT ? String(cur?.port) : '')
  const [errors, setErrors] = useState<Errors>({})
  const [error, setError] = useState<string | null>(null)

  const target = readFrom.trim() || ip // where reads (and the secret) will go
  const moved = setUp && target !== cur?.read_from
  // a blank secret keeps the saved one only when it is of the same kind, this box can open it, and it still goes to the same address
  const keepable = setUp && !moved && !cur?.secret_lost && cur?.version === version
  const keepCommunity = keepable && version === 'v2c'
  const keepAuth = keepable && version === 'v3'
  const keepPriv = keepAuth && cur?.priv === 'aes128'
  const copying = copy !== ''
  const source = others.find((o) => o.device_id === copy)
    const set = (k: keyof Errors) => () => setErrors((e) => ({ ...e, [k]: undefined }))

  function checkForm(): Errors {
    const e: Errors = {}
    const rf = readFrom.trim()
    if (rf) {
      if (!IPV4_RE_UI.test(rf)) e.read_from = t('deviceSnmp.error.readFromBad')
      else if (RESERVED_RE.test(rf)) e.read_from = t('deviceSnmp.error.readFromReserved', { ip: rf })
      else if (!isPrivateCidr(`${rf}/32`)) e.read_from = t('deviceSnmp.error.readFromNotLocal', { ip: rf, ranges: LOCAL_RANGE_NAMES })
    }
    if (copying) {
      if (target !== ip) e.copy = t(ip ? 'deviceSnmp.form.copyOwnIpOnly' : 'deviceSnmp.form.copyOwnIpOnlyNoIp', { ip, target })
      return e
    }
    const pw = (v: string, keep: boolean) => (!v ? (keep ? undefined : moved ? t('deviceSnmp.error.secretAgain') : t('deviceSnmp.error.passwordRequired'))
      : v.length < 8 ? t('deviceSnmp.error.passwordShort') : PRINTABLE_RE.test(v) ? undefined : t('deviceSnmp.error.password'))
    if (version === 'v2c') {
      if (!community) { if (!keepCommunity) e.community = moved ? t('deviceSnmp.error.secretAgain') : t('deviceSnmp.error.communityRequired') }
      else if (!PRINTABLE_RE.test(community)) e.community = t('deviceSnmp.error.community')
    } else {
      if (!username.trim()) e.username = t('deviceSnmp.error.userRequired')
      else if (!USER_RE.test(username.trim())) e.username = t('deviceSnmp.error.user')
      e.auth_password = pw(authPassword, keepAuth)
      if (priv === 'aes128') e.priv_password = pw(privPassword, keepPriv)
    }
    const p = port.trim()
    if (p && (!PORT_RE.test(p) || Number(p) < 1 || Number(p) > 65535)) e.port = t('deviceSnmp.error.port')
    return Object.fromEntries(Object.entries(e).filter(([, v]) => v)) as Errors
  }

  /** read_from_taken names the other device; when the list knows it, the message links to its page. */
  function taken(msg: string): ReactNode {
    const other = others.find((o) => o.read_from === target)
    if (!other) return msg
    return <>{msg} <Link to={`/devices/${encodeURIComponent(other.device_id)}#device-snmp`} className="font-medium text-accent underline underline-offset-4" onClick={onLinkClick}>{t('deviceSnmp.error.openOther', { name: other.name || other.read_from })}</Link></>
  }

  function submit(ev: FormEvent) {
    ev.preventDefault(); setError(null)
    const outer = precheck ? precheck() : true
    const e = checkForm()
    setErrors(e)
    if (!outer || Object.keys(e).length) return
    const rf = readFrom.trim() || undefined
    const p = port.trim() ? Number(port.trim()) : undefined
    const body: DeviceSnmpInput = copying ? { copy_from: copy, read_from: rf }
      : version === 'v2c' ? { version, community: community || undefined, port: p, read_from: rf }
      : { version, username: username.trim(), auth, auth_password: authPassword || undefined, priv, priv_password: priv === 'aes128' ? privPassword || undefined : undefined, port: p, read_from: rf }
    save(body).catch((er: unknown) => {
      const msg = errMsg(er)
      const f = er instanceof ApiError ? FIELD_OF[er.code] : undefined
      const field = typeof f === 'function' ? f(version, copying, msg) : f
      if (!field) { setError(msg); return }
      setErrors({ [field]: er instanceof ApiError && er.code === 'read_from_taken' ? taken(msg) : msg })
    })
  }

  const fieldErr = (k: keyof Errors) => (typeof errors[k] === 'string' ? (errors[k] as string) : undefined)
  // a linked error (read_from_taken) is drawn under the field by hand, so the Field gets no string for it
  const rich = (k: keyof Errors) => !!errors[k] && typeof errors[k] !== 'string'
  const richErr = (k: keyof Errors, htmlId: string) => (rich(k) ? <p id={`${htmlId}-error`} className="-mt-2 text-meta text-danger [overflow-wrap:anywhere]">{errors[k]}</p> : null)
  const invalid = (k: keyof Errors) => !!errors[k]
  const secretHint = (keep: boolean, last4: string, fresh: string) => (keep ? (last4 ? t('deviceSnmp.form.keep', { last4 }) : t('deviceSnmp.form.keepShort')) : moved ? t('deviceSnmp.form.again') : fresh)
  return (
    <form onSubmit={submit} className="grid gap-4" noValidate>
      {lead}
      <Field label={t('deviceSnmp.form.readFrom')} htmlFor="snmp-read-from" hint={rich('read_from') ? undefined : ip ? t('deviceSnmp.form.readFromHint', { ip }) : t('deviceSnmp.form.readFromHintNoIp')} info={t('deviceSnmp.form.readFromInfo')} error={fieldErr('read_from')}>
        <Input id="snmp-read-from" value={readFrom} maxLength={15} inputMode="decimal" autoComplete="off" placeholder={ip} className="max-w-60 tabular-nums"
          onChange={(e) => { setReadFrom(e.target.value); set('read_from')(); set('copy')() }} aria-invalid={invalid('read_from') || undefined} aria-describedby={rich('read_from') ? 'snmp-read-from-error' : undefined} />
      </Field>
      {richErr('read_from', 'snmp-read-from')}
      {others.length ? (
        <Field label={t('deviceSnmp.form.copy')} htmlFor="snmp-copy" hint={rich('copy') ? undefined : copying ? ip ? t('deviceSnmp.form.copyHint', { ip }) : t('deviceSnmp.form.copyHintNoIp') : t('deviceSnmp.form.copyNone')} error={fieldErr('copy')}>
          <Select id="snmp-copy" value={copy} onChange={(e) => { setCopy(e.target.value); setErrors({}) }} aria-invalid={invalid('copy') || undefined} aria-describedby={rich('copy') ? 'snmp-copy-error' : undefined}>
            <option value="">{t('deviceSnmp.form.copyType')}</option>
            {others.map((o) => <option key={o.device_id} value={o.device_id}>{t('deviceSnmp.form.copyOption', { name: o.name || o.read_from, ip: o.read_from, version: o.version })}</option>)}
          </Select>
        </Field>
      ) : null}
      {richErr('copy', 'snmp-copy')}
      {copying ? (
        source ? <p className="text-meta text-muted">{t('deviceSnmp.form.copyWhat', { name: source.name || source.read_from, version: source.version, port: source.port })}</p> : null
      ) : (
        <>
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">{t('deviceSnmp.form.version')}</span>
            <Segmented<SnmpVersion> label={t('deviceSnmp.form.version')} value={version} onChange={(v) => { setVersion(v); setErrors({}) }}
              options={[{ value: 'v2c', label: t('deviceSnmp.v2c') }, { value: 'v3', label: t('deviceSnmp.v3') }]} />
            {errors.version ? <p className="text-meta text-danger">{errors.version}</p> : null}
            {version === 'v2c' ? <p className="text-meta text-muted">{t('deviceSnmp.form.v2cClear')}</p> : null}
          </div>
          {version === 'v2c' ? (
            <Field label={t('deviceSnmp.form.community')} htmlFor="snmp-community" hint={secretHint(keepCommunity, (cur?.secret_last4 ?? ''), t('deviceSnmp.form.communityHint'))} error={fieldErr('community')}>
              <Input id="snmp-community" type="password" value={community} maxLength={64} autoComplete="off" onChange={(e) => { setCommunity(e.target.value); set('community')() }} aria-invalid={invalid('community') || undefined} />
            </Field>
          ) : (
            <>
              <Field label={t('deviceSnmp.form.user')} htmlFor="snmp-user" hint={t('deviceSnmp.form.userHint')} error={fieldErr('username')}>
                <Input id="snmp-user" value={username} maxLength={64} autoComplete="off" onChange={(e) => { setUsername(e.target.value); set('username')() }} aria-invalid={invalid('username') || undefined} />
              </Field>
              <div className="grid gap-4 sm:grid-cols-[minmax(0,12rem)_1fr]">
                <Field label={t('deviceSnmp.form.auth')} htmlFor="snmp-auth" error={fieldErr('auth')}>
                  <Select id="snmp-auth" value={auth} onChange={(e) => { setAuth(e.target.value as SnmpAuth); set('auth')() }}>
                    {(['sha256', 'sha'] as const).map((a) => <option key={a} value={a}>{t(`deviceSnmp.authName.${a}`)}</option>)}
                  </Select>
                </Field>
                <Field label={t('deviceSnmp.form.authPassword')} htmlFor="snmp-auth-pw" hint={secretHint(keepAuth, (cur?.secret_last4 ?? ''), t('deviceSnmp.form.passwordHint'))} error={fieldErr('auth_password')}>
                  <Input id="snmp-auth-pw" type="password" value={authPassword} maxLength={64} autoComplete="new-password" onChange={(e) => { setAuthPassword(e.target.value); set('auth_password')() }} aria-invalid={invalid('auth_password') || undefined} />
                </Field>
              </div>
              <div className="grid gap-4 sm:grid-cols-[minmax(0,12rem)_1fr]">
                <Field label={t('deviceSnmp.form.priv')} htmlFor="snmp-priv" error={fieldErr('priv')}>
                  <Select id="snmp-priv" value={priv} onChange={(e) => { setPriv(e.target.value as SnmpPriv); set('priv')() }}>
                    {(['aes128', 'none'] as const).map((p) => <option key={p} value={p}>{t(`deviceSnmp.privName.${p}`)}</option>)}
                  </Select>
                </Field>
                {priv === 'aes128' ? (
                  <Field label={t('deviceSnmp.form.privPassword')} htmlFor="snmp-priv-pw" hint={secretHint(keepPriv, (cur?.priv_last4 ?? ''), t('deviceSnmp.form.passwordHint'))} error={fieldErr('priv_password')}>
                    <Input id="snmp-priv-pw" type="password" value={privPassword} maxLength={64} autoComplete="new-password" onChange={(e) => { setPrivPassword(e.target.value); set('priv_password')() }} aria-invalid={invalid('priv_password') || undefined} />
                  </Field>
                ) : null}
              </div>
            </>
          )}
          <Field label={t('deviceSnmp.form.port')} htmlFor="snmp-port" hint={t('deviceSnmp.form.portHint')} error={fieldErr('port')}>
            <Input id="snmp-port" value={port} maxLength={5} inputMode="numeric" autoComplete="off" placeholder={String(SNMP_PORT)} className="max-w-40 tabular-nums"
              onChange={(e) => { setPort(e.target.value); set('port')() }} aria-invalid={invalid('port') || undefined} />
          </Field>
        </>
      )}
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      <p className="text-meta text-muted" data-testid="snmp-consent">{t(`deviceSnmp.form.${switchOff ? 'consentOff' : 'consentOn'}${target ? '' : 'NoIp'}`, { ip: target })}</p>
      <DialogFooter>
        <Button onClick={onCancel}>{t('common:cancel')}</Button>
        <Button type="submit" variant="primary" busy={saving} busyLabel={t('common:busy.saving')}>{submitLabel ?? (setUp ? t('deviceSnmp.form.save') : t('deviceSnmp.form.create'))}</Button>
      </DialogFooter>
    </form>
  )
}

/** What the box changed by itself in SNMP settings (the one-time move of the old shared credentials onto devices), until an admin
 *  dismisses them. Drawn where an admin looks for SNMP: the Devices page and the Settings › Scanning SNMP card. */
export function SnmpNotices({ className }: { className?: string }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const on = useModuleEnabled('sensor-active') === true
  const q = useSnmp(admin && on)
  const dismiss = useDismissSnmpNotices()
  const notices = q.data?.notices ?? []
  if (!admin || !on || !notices.length) return null
  return (
    <Notice tone="accent" role="note" className={className} title={t('deviceSnmp.notices.title', { count: notices.length })}
      actions={<Button size="sm" busy={dismiss.isPending} busyLabel={t('common:busy.saving')} onClick={() => dismiss.mutate(undefined, { onError: (e) => toast.error(errMsg(e)) })}>{t('deviceSnmp.notices.dismiss')}</Button>}>
      <ul className="grid gap-1">
        {notices.map((n) => <li key={n.id}><time dateTime={n.at} className="text-caption">{fmtDateTime(n.at)}</time> · {n.text}</li>)}
      </ul>
    </Notice>
  )
}

/** The Settings › Scanning SNMP card: the notices, and every device with SNMP set up with its state, each a link to its SNMP card. */
export function SnmpDevices() {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const on = useModuleEnabled('sensor-active') === true
  const q = useSnmp(admin && on)
  if (!admin || !on) return null
  const devices = q.data?.devices ?? []
  return (
    <div className="grid min-w-0 gap-2">
      <SnmpNotices className="mb-0" />
      {q.data && !q.data.ready ? <Notice tone="warn" role="status" className="mb-0" title={t('deviceSnmp.notReady')}>{q.data.message}</Notice> : null}
      {devices.length ? (
        <>
          <p className="text-meta text-muted">{t('deviceSnmp.list.title', { count: devices.length })}</p>
          <ul aria-label={t('deviceSnmp.list.label')} className="grid gap-1.5">
            {devices.map((r) => (
              <li key={r.device_id} className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                <Link to={`/devices/${encodeURIComponent(r.device_id)}#device-snmp`} className="font-medium text-accent underline-offset-4 hover:underline [overflow-wrap:anywhere]">{r.name || r.read_from}</Link>
                <span className="text-meta text-muted tabular-nums">{t('deviceSnmp.list.at', { ip: r.read_from, version: r.version })}</span>
                <SnmpStateLabel state={r.state} />
                {r.blocked ? <span className="text-meta text-warn">{t('deviceSnmp.list.blocked')}</span> : null}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  )
}
