import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { Notice, Section } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useSnmp, useSnmpActions } from './api'
import { kindLabel } from '@/lib/deviceTypes'
import { errMsg } from './kinds'
import type { SnmpCredential, SnmpCredentialInput, SnmpTestResult } from './types'
import { CIDR_RE_UI, IPV4_RE_UI, isPrivateCidr, LOCAL_RANGE_NAMES, SNMP_MAX } from './validate'

type Version = SnmpCredentialInput['version']
type Auth = NonNullable<SnmpCredentialInput['auth']>
type Priv = NonNullable<SnmpCredentialInput['priv']>

const SCOPE_MAX = 16
// Browser-side checks so mistakes show early; the server checks the same rules again (SYS-2, contract.ts SnmpCredentialInput).
// eslint-disable-next-line no-control-regex
const NAME_RE = /^[^<>\u0000-\u001f\u007f]{1,64}$/
const PRINTABLE_RE = /^[\x20-\x7e]{1,64}$/
const USER_RE = /^[A-Za-z0-9._@-]{1,64}$/
/** The SNMP port (RFC 3417): a credential without a port of its own is sent there. */
const SNMP_PORT = 161
const PORT_RE = /^[0-9]{1,5}$/

/** Scope text: one entry per line or separated by commas (or spaces); duplicates dropped. */
const parseScope = (text: string) => [...new Set(text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean))]

type Errors = Partial<Record<'name' | 'community' | 'username' | 'auth_password' | 'priv_password' | 'port' | 'scope', string>>

function SecretMask({ last4 }: { last4: string }) {
  const { t } = useTranslation('inventory')
  return <span className="whitespace-nowrap font-mono text-meta">{t('agents.tokenMask', { last4 })}</span>
}

/** Add or edit a credential. scope pre-fills the scope (a device page's address, D-598); widen: the scope given reaches a new address, so
 *  the saved secrets cannot be kept (the server answers secret_required otherwise, D-512) and the form asks for them again.
 *  `onSaved` gets the saved credential (the Add a device dialog selects it, #849). */
export function CredentialDialog({ current, scope, widen = false, onClose, onSaved }: { current: SnmpCredential | null; scope?: string; widen?: boolean; onClose: () => void; onSaved?: (c: SnmpCredential) => void }) {
  const { t } = useTranslation('inventory')
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={current ? t('snmp.form.editTitle', { name: current.name }) : t('snmp.form.addTitle')} description={t('snmp.form.body')} info={t('snmp.form.bodyInfo')}>
        <CredentialForm current={current} scope={scope} widen={widen} onCancel={onClose} onSaved={(c) => { onSaved?.(c); onClose() }} />
      </DialogContent>
    </Dialog>
  )
}

/** The credential form itself, inline in the Add a device dialog (#849) or inside CredentialDialog. */
export function CredentialForm({ current, scope, widen = false, onCancel, onSaved, idPrefix = 'snmp' }: { current: SnmpCredential | null; scope?: string; widen?: boolean; onCancel: () => void; onSaved: (c: SnmpCredential) => void; idPrefix?: string }) {
  const { t } = useTranslation('inventory')
  const { create, update } = useSnmpActions()
  const [name, setName] = useState(current?.name ?? '')
  const [version, setVersion] = useState<Version>(current?.version ?? 'v2c')
  const [community, setCommunity] = useState('')
  const [username, setUsername] = useState(current?.username ?? '')
  const [auth, setAuth] = useState<Auth>(current?.auth ?? 'sha256')
  const [authPassword, setAuthPassword] = useState('')
  const [priv, setPriv] = useState<Priv>(current?.priv ?? 'aes128')
  const [privPassword, setPrivPassword] = useState('')
  const [port, setPort] = useState(current && current.port !== SNMP_PORT ? String(current.port) : '')
  const [scopeText, setScopeText] = useState(scope ?? current?.scope.join('\n') ?? '')
  const [errors, setErrors] = useState<Errors>({})
  const [error, setError] = useState<string | null>(null)
  // A blank secret keeps the saved one, but only when there is a saved one of that kind (same version; privacy already on) that this
  // box can open: one not restored (#868, restore without the key) is typed again (the server answers 409 secret_lost otherwise).
  const sameVersion = !widen && !current?.secret_lost && current?.version === version
  const keepCommunity = sameVersion && version === 'v2c'
  const keepAuth = sameVersion && version === 'v3'
  const keepPriv = keepAuth && current?.priv === 'aes128'
  const pending = create.isPending || update.isPending

  function check(): Errors {
    const e: Errors = {}
    const pw = (v: string, keep: boolean) => (!v ? (keep ? undefined : t('snmp.error.passwordRequired')) : v.length < 8 ? t('snmp.error.passwordShort') : PRINTABLE_RE.test(v) ? undefined : t('snmp.error.password'))
    if (!NAME_RE.test(name.trim())) e.name = t('snmp.error.name')
    if (version === 'v2c') {
      if (!community) { if (!keepCommunity) e.community = t('snmp.error.communityRequired') } else if (!PRINTABLE_RE.test(community)) e.community = t('snmp.error.community')
    } else {
      if (!username.trim()) e.username = t('snmp.error.userRequired')
      else if (!USER_RE.test(username.trim())) e.username = t('snmp.error.user')
      e.auth_password = pw(authPassword, keepAuth)
      if (priv === 'aes128') e.priv_password = pw(privPassword, keepPriv)
    }
    const p = port.trim()
    if (p && (!PORT_RE.test(p) || Number(p) < 1 || Number(p) > 65535)) e.port = t('snmp.error.port')
    const scope = parseScope(scopeText)
    if (scope.length === 0) e.scope = t('snmp.error.scopeRequired') // D-512 (review M3): a credential names its devices
    else if (scope.length > SCOPE_MAX) e.scope = t('snmp.error.scopeTooMany')
    else {
      for (const s of scope) {
        const cidr = IPV4_RE_UI.test(s) ? `${s}/32` : CIDR_RE_UI.test(s) ? s : null
        if (!cidr) { e.scope = t('snmp.error.scopeBad', { entry: s.slice(0, 40) }); break }
        if (!isPrivateCidr(cidr)) { e.scope = t('snmp.error.scopeNotLocal', { entry: s, ranges: LOCAL_RANGE_NAMES }); break }
      }
    }
    return Object.fromEntries(Object.entries(e).filter(([, v]) => v)) as Errors
  }

  function submit(ev: FormEvent) {
    ev.preventDefault(); setError(null)
    const e = check()
    setErrors(e)
    if (Object.keys(e).length) return
    const common = { name: name.trim(), version, port: port.trim() ? Number(port.trim()) : undefined, scope: parseScope(scopeText) }
    const input: SnmpCredentialInput = version === 'v2c'
      ? { ...common, community: community || undefined }
      : { ...common, username: username.trim(), auth, auth_password: authPassword || undefined, priv, priv_password: priv === 'aes128' ? privPassword || undefined : undefined }
    const done = (c: SnmpCredential) => { toast.success(t(current ? 'snmp.form.saved' : 'snmp.form.added', { name: c.name })); onSaved(c) }
    const fail = (er: unknown) => setError(errMsg(er))
    if (current) update.mutate({ id: current.id, ...input }, { onSuccess: done, onError: fail })
    else create.mutate(input, { onSuccess: done, onError: fail })
  }

  const hint = (keep: boolean) => (keep ? t('snmp.form.keep') : t('snmp.form.passwordHint'))
  const described = (id: string, err?: string) => (err ? `${id}-error` : `${id}-hint`)
  return (
        <form onSubmit={submit} className="grid gap-4" noValidate>
          <Field label={t('snmp.form.name')} htmlFor={`${idPrefix}-name`} hint={t('snmp.form.nameHint')} error={errors.name}>
            <Input id={`${idPrefix}-name`} value={name} maxLength={64} autoComplete="off" onChange={(e) => setName(e.target.value)} aria-invalid={!!errors.name} aria-describedby={described(`${idPrefix}-name`, errors.name)} />
          </Field>
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">{t('snmp.form.version')}</span>
            <Segmented<Version> label={t('snmp.form.version')} value={version} onChange={(v) => { setVersion(v); setErrors({}) }}
              options={[{ value: 'v2c', label: t('snmp.version.v2c') }, { value: 'v3', label: t('snmp.version.v3') }]} />
          </div>
          {version === 'v2c' ? (
            <Field label={t('snmp.form.community')} htmlFor={`${idPrefix}-community`} hint={keepCommunity ? t('snmp.form.keep') : t('snmp.form.communityHint')} error={errors.community}>
              <Input id={`${idPrefix}-community`} type="password" value={community} maxLength={64} autoComplete="off" onChange={(e) => setCommunity(e.target.value)} aria-invalid={!!errors.community} aria-describedby={described(`${idPrefix}-community`, errors.community)} />
            </Field>
          ) : (
            <>
              <Field label={t('snmp.form.user')} htmlFor={`${idPrefix}-user`} hint={t('snmp.form.userHint')} error={errors.username}>
                <Input id={`${idPrefix}-user`} value={username} maxLength={64} autoComplete="off" onChange={(e) => setUsername(e.target.value)} aria-invalid={!!errors.username} aria-describedby={described(`${idPrefix}-user`, errors.username)} />
              </Field>
              <div className="grid gap-4 sm:grid-cols-[minmax(0,12rem)_1fr]">
                <Field label={t('snmp.form.auth')} htmlFor={`${idPrefix}-auth`}>
                  <Select id={`${idPrefix}-auth`} value={auth} onChange={(e) => setAuth(e.target.value as Auth)}>
                    {(['sha256', 'sha'] as const).map((a) => <option key={a} value={a}>{t(`snmp.authName.${a}`)}</option>)}
                  </Select>
                </Field>
                <Field label={t('snmp.form.authPassword')} htmlFor={`${idPrefix}-authpw`} hint={hint(keepAuth)} error={errors.auth_password}>
                  <Input id={`${idPrefix}-authpw`} type="password" value={authPassword} maxLength={64} autoComplete="new-password" onChange={(e) => setAuthPassword(e.target.value)} aria-invalid={!!errors.auth_password} aria-describedby={described(`${idPrefix}-authpw`, errors.auth_password)} />
                </Field>
              </div>
              <div className="grid gap-4 sm:grid-cols-[minmax(0,12rem)_1fr]">
                <Field label={t('snmp.form.priv')} htmlFor={`${idPrefix}-priv`}>
                  <Select id={`${idPrefix}-priv`} value={priv} onChange={(e) => setPriv(e.target.value as Priv)}>
                    {(['aes128', 'none'] as const).map((p) => <option key={p} value={p}>{t(`snmp.privName.${p}`)}</option>)}
                  </Select>
                </Field>
                {priv === 'aes128' ? (
                  <Field label={t('snmp.form.privPassword')} htmlFor={`${idPrefix}-privpw`} hint={hint(keepPriv)} error={errors.priv_password}>
                    <Input id={`${idPrefix}-privpw`} type="password" value={privPassword} maxLength={64} autoComplete="new-password" onChange={(e) => setPrivPassword(e.target.value)} aria-invalid={!!errors.priv_password} aria-describedby={described(`${idPrefix}-privpw`, errors.priv_password)} />
                  </Field>
                ) : null}
              </div>
            </>
          )}
          <Field label={t('snmp.form.port')} htmlFor={`${idPrefix}-port`} hint={t('snmp.form.portHint')} error={errors.port}>
            <Input id={`${idPrefix}-port`} value={port} maxLength={5} inputMode="numeric" autoComplete="off" placeholder={String(SNMP_PORT)} onChange={(e) => setPort(e.target.value)} aria-invalid={!!errors.port} aria-describedby={described(`${idPrefix}-port`, errors.port)} className="max-w-40 tabular-nums" />
          </Field>
          <Field label={t('snmp.form.scope')} htmlFor={`${idPrefix}-scope`} hint={t('snmp.form.scopeHint')} info={t('snmp.form.scopeHintInfo')} error={errors.scope}>
            <Textarea id={`${idPrefix}-scope`} rows={3} value={scopeText} placeholder={'192.168.10.0/24\n192.168.20.5'} spellCheck={false} onChange={(e) => setScopeText(e.target.value)} aria-invalid={!!errors.scope} aria-describedby={described(`${idPrefix}-scope`, errors.scope)} className="font-mono text-meta" />
          </Field>
          <p className="text-caption text-muted">{t('snmp.form.insecure')}</p>
          {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
          <DialogFooter>
            <Button onClick={onCancel}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" disabled={pending}>{current ? t('snmp.form.save') : t('snmp.form.create')}</Button>
          </DialogFooter>
        </form>
  )
}

/** What one SNMP read answered, or why not; also on the device page (DeviceSources). port: the UDP port the read went to, when the
 *  caller knows it (a Test names it; the failure text from the server always does). */
export function SnmpAnswer({ r, ip, port }: { r: SnmpTestResult; ip: string; port?: number }) {
  const { t } = useTranslation('inventory')
  const a = r.answer
  const device = r.device_id ? <Link to={`/devices/${encodeURIComponent(r.device_id)}`} className="font-medium text-accent underline-offset-4 hover:underline">{t('snmp.run.openDevice')}</Link> : null
  if (!r.ok || !a) {
    return (
      <Notice tone="danger" role="alert" className="mb-0" title={t('snmp.run.notRead', { ip })} actions={device}>{r.message}</Notice>
    )
  }
  const rows: [string, string][] = ([
    ['sysName', a.sys_name], ['vendor', [a.vendor, a.product].filter(Boolean).join(' ')], ['model', a.model], ['os', a.os],
    ['kind', a.kind ? kindLabel(a.kind) : ''], ['serial', a.serial], ['firmware', a.firmware], ['objectId', a.sys_object_id],
  ] as [string, string][]).filter(([, v]) => v)
  return (
    <div role="status" className="grid min-w-0 gap-2 rounded-md border border-ok/40 bg-ok-soft px-3 py-2 text-sm">
      <p className="font-medium">{port ? t('snmp.run.answeredOn', { ip, port }) : t('snmp.run.answered', { ip })}</p>
      <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-[max-content_1fr]">
        {rows.map(([k, v]) => <div key={k} className="contents"><dt className="text-meta text-muted">{t(`snmp.run.${k}`)}</dt><dd className="[overflow-wrap:anywhere]">{v}</dd></div>)}
      </dl>
      {a.sys_descr ? (
        <div className="grid min-w-0 gap-1">
          <p className="text-meta text-muted">{t('snmp.run.descr')}</p>
          <pre tabIndex={0} className="max-h-40 overflow-auto whitespace-pre-wrap rounded-md border border-rule bg-surface p-2 font-mono text-caption leading-5 [overflow-wrap:anywhere]">{a.sys_descr}</pre>
        </div>
      ) : null}
      <p className="text-meta">{t('snmp.run.recorded')}{device ? <> {device}</> : null}</p>
    </div>
  )
}

/** Test one credential against one device now (≤ 15 s on the server): what it said, or the plain reason why not. */
function TestPanel({ cred, onClose }: { cred: SnmpCredential; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const { test } = useSnmpActions()
  const [ip, setIp] = useState('')
  const [ipErr, setIpErr] = useState<string | null>(null)
  const [result, setResult] = useState<{ ip: string; r: SnmpTestResult } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const id = `snmp-test-${cred.id}`
  function submit(e: FormEvent) {
    e.preventDefault(); setResult(null); setError(null)
    const v = ip.trim()
    if (!IPV4_RE_UI.test(v)) { setIpErr(t('snmp.run.ipBad')); return }
    setIpErr(null)
    test.mutate({ id: cred.id, ip: v }, { onSuccess: (r) => setResult({ ip: v, r }), onError: (er) => setError(errMsg(er)) })
  }
  return (
    <div className="grid min-w-0 gap-3 border-t border-rule pt-3">
      <form onSubmit={submit} noValidate className="grid max-w-md gap-2">
        <Field label={t('snmp.run.ip')} htmlFor={id} hint={t('snmp.run.ipHint')} error={ipErr ?? undefined}>
          <Input id={id} value={ip} maxLength={15} inputMode="decimal" autoComplete="off" placeholder="192.168.10.3" onChange={(e) => setIp(e.target.value)} aria-invalid={!!ipErr} aria-describedby={ipErr ? `${id}-error` : `${id}-hint`} />
        </Field>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" variant="primary" size="sm" disabled={test.isPending}>{test.isPending ? t('snmp.run.running') : t('snmp.run.submit')}</Button>
          <Button size="sm" onClick={onClose}>{t('snmp.run.close')}</Button>
        </div>
      </form>
      {test.isPending ? <p role="status" aria-live="polite" className="text-meta text-muted">{t('snmp.run.pending', { ip: ip.trim() })}</p> : null}
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      {result && !test.isPending ? <SnmpAnswer r={result.r} ip={result.ip} port={cred.port} /> : null}
    </div>
  )
}

function CredentialRow({ c, index, onEdit, onDelete }: { c: SnmpCredential; index: number; onEdit: () => void; onDelete: () => void }) {
  const { t } = useTranslation('inventory')
  const [testing, setTesting] = useState(false)
  return (
    <li className="grid min-w-0 gap-3 rounded-md border border-rule bg-surface p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="text-meta tabular-nums text-muted">{index + 1}.</span>
          <h3 className="text-sm font-semibold [overflow-wrap:anywhere]">{c.name}</h3>
          <Chip tone="off">{t(`snmp.version.${c.version}`)}</Chip>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => setTesting(true)} aria-label={t('snmp.testFor', { name: c.name })}>{t('snmp.test')}</Button>
          <Button size="sm" onClick={onEdit} aria-label={t('snmp.editFor', { name: c.name })}>{t('snmp.edit')}</Button>
          <Button size="sm" onClick={onDelete} aria-label={t('snmp.deleteFor', { name: c.name })}>{t('snmp.delete')}</Button>
        </div>
      </div>
      {c.secret_lost ? <Notice tone="danger" role="alert" className="mb-0" title={t('snmp.secretLost')}>{t('snmp.secretLostBody')}</Notice> : null}
      {c.moved_out.map((m) => (
        <Notice key={m.device_id} tone="warn" role="status" className="mb-0" title={t('snmp.movedOut', { name: m.name, ip: m.ip })}
          actions={<Link to={`/devices/${encodeURIComponent(m.device_id)}`} className="text-meta underline">{t('snmp.movedOutDevice')}</Link>}>{m.message}</Notice>
      ))}
      <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
        {c.version === 'v2c' ? (
          <><dt className="text-meta text-muted">{t('snmp.form.community')}</dt><dd><SecretMask last4={c.secret_last4} /></dd></>
        ) : (
          <>
            <dt className="text-meta text-muted">{t('snmp.form.user')}</dt><dd className="[overflow-wrap:anywhere]">{c.username}</dd>
            <dt className="text-meta text-muted">{t('snmp.form.auth')}</dt><dd>{c.auth ? t(`snmp.authName.${c.auth}`) : '—'}, <SecretMask last4={c.secret_last4} /></dd>
            <dt className="text-meta text-muted">{t('snmp.privLabel')}</dt>
            <dd>{c.priv === 'aes128' ? <>{t('snmp.privName.aes128')}, <SecretMask last4={c.priv_last4} /></> : t('snmp.privName.none')}</dd>
          </>
        )}
        {c.port !== SNMP_PORT ? <><dt className="text-meta text-muted">{t('snmp.portLabel')}</dt><dd className="tabular-nums">{t('snmp.portValue', { port: c.port })}</dd></> : null}
        <dt className="text-meta text-muted">{t('snmp.scopeLabel')}</dt>
        <dd className="[overflow-wrap:anywhere]">{c.scope.join(', ')}</dd>
        <dt className="text-meta text-muted">{t('snmp.answersLabel')}</dt>
        <dd>{c.last_answer_at
          ? <><time dateTime={c.last_answer_at} title={fmtDateTime(c.last_answer_at)}>{t('snmp.lastAnswered', { when: fmtRelative(c.last_answer_at) })}</time>, {t('snmp.answeredBy', { count: c.answered })}</>
          : <span className="text-muted">{t('snmp.never')}</span>}</dd>
      </dl>
      {testing ? <TestPanel cred={c} onClose={() => setTesting(false)} /> : null}
    </li>
  )
}

/** S-INV-1, D-512: SNMP credentials for the read-only GETs of active discovery. Exists only while sensor-active is on (its routes answer 404 otherwise). */
export function SnmpSection() {
  const { t } = useTranslation('inventory')
  const on = useModuleEnabled('sensor-active') === true
  const q = useSnmp(on)
  const { remove } = useSnmpActions()
  // A device page's "Add SNMP for <ip>" opens the add form with that address as the scope (D-598, issue #829).
  const [params, setParams] = useSearchParams()
  const forIp = params.get('snmp_ip') ?? ''
  const [editing, setEditing] = useState<SnmpCredential | 'new' | null>(null)
  const close = () => {
    setEditing(null)
    if (forIp) { const p = new URLSearchParams(params); p.delete('snmp_ip'); setParams(p, { replace: true }) }
  }
  const [deleting, setDeleting] = useState<SnmpCredential | null>(null)
  if (!on) return null
  const full = (q.data?.credentials.length ?? 0) >= SNMP_MAX
  // ?snmp_ip= opens the add form once the list is read and has room (review #831 L8); at 8 credentials the button says why not.
  const autoAdd = !editing && IPV4_RE_UI.test(forIp) && !!q.data && !full
  return (
    <Section id="snmp" title={t('snmp.title')} description={t('snmp.description')} info={<><p>{t('snmp.descriptionInfo')}</p><p>{t('snmp.descriptionInfo2')}</p></>} stories={['S-INV-1']}
      actions={<Button onClick={() => setEditing('new')} disabled={!q.data || full} title={full ? t('snmp.max') : undefined}><Plus />{t('snmp.add')}</Button>}>
      <QueryState query={q}>
        {(d) => (
          <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
            {d.ready ? null : <Notice tone="warn" role="status" className="mb-0 max-w-3xl" title={d.message ?? t('snmp.notReady')} />}
            {d.credentials.length ? (
              <>
                <p className="text-meta text-muted">{t('snmp.order')}{full ? ` ${t('snmp.max')}` : ''}</p>
                <ol aria-label={t('snmp.caption')} className="grid gap-3">
                  {d.credentials.map((c, i) => <CredentialRow key={c.id} c={c} index={i} onEdit={() => setEditing(c)} onDelete={() => setDeleting(c)} />)}
                </ol>
              </>
            ) : <EmptyState title={t('snmp.empty')} info={t('snmp.emptyBodyInfo')}>{t('snmp.emptyBody')}</EmptyState>}
          </div>
        )}
      </QueryState>
      {editing || autoAdd ? <CredentialDialog key={!editing || editing === 'new' ? 'new' : editing.id} current={!editing || editing === 'new' ? null : editing}
        scope={(!editing || editing === 'new') && IPV4_RE_UI.test(forIp) ? forIp : undefined} onClose={close} /> : null}
      <Dialog open={!!deleting} onOpenChange={(o) => { if (!o) setDeleting(null) }}>
        <DialogContent title={t('snmp.deleteTitle', { name: deleting?.name ?? '' })} description={t('snmp.deleteBody')}>
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button variant="danger" disabled={remove.isPending} onClick={() => deleting && remove.mutate(deleting.id, { onSuccess: () => { toast.success(t('snmp.deleted', { name: deleting.name })); setDeleting(null) }, onError: (e) => toast.error(errMsg(e)) })}>{t('snmp.deleteConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Section>
  )
}
