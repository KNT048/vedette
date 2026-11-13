import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { Section } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useSnmp, useSnmpActions } from './api'
import { errMsg } from './kinds'
import type { SnmpCredential, SnmpCredentialInput, SnmpTestResult } from './types'
import { CIDR_RE_UI, IPV4_RE_UI, isPrivateCidr, LOCAL_RANGE_NAMES } from './validate'

type Version = SnmpCredentialInput['version']
type Auth = NonNullable<SnmpCredentialInput['auth']>
type Priv = NonNullable<SnmpCredentialInput['priv']>

/** At most 8 credentials (409 too_many on the server). */
const SNMP_MAX = 8
const SCOPE_MAX = 16
// Browser-side checks so mistakes show early; the server checks the same rules again (SYS-2, contract.ts SnmpCredentialInput).
// eslint-disable-next-line no-control-regex
const NAME_RE = /^[^<>\u0000-\u001f\u007f]{1,64}$/
const PRINTABLE_RE = /^[\x20-\x7e]{1,64}$/
const USER_RE = /^[A-Za-z0-9._@-]{1,64}$/

/** Scope text: one entry per line or separated by commas (or spaces); duplicates dropped. */
const parseScope = (text: string) => [...new Set(text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean))]

type Errors = Partial<Record<'name' | 'community' | 'username' | 'auth_password' | 'priv_password' | 'scope', string>>

function SecretMask({ last4 }: { last4: string }) {
  const { t } = useTranslation('inventory')
  return <span className="whitespace-nowrap font-mono text-[13px]">{t('agents.tokenMask', { last4 })}</span>
}

function CredentialDialog({ current, onClose }: { current: SnmpCredential | null; onClose: () => void }) {
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
  const [scopeText, setScopeText] = useState(current?.scope.join('\n') ?? '')
  const [errors, setErrors] = useState<Errors>({})
  const [error, setError] = useState<string | null>(null)
  // A blank secret keeps the saved one, but only when there is a saved one of that kind (same version; privacy already on).
  const sameVersion = current?.version === version
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
    const scope = parseScope(scopeText)
    if (scope.length > SCOPE_MAX) e.scope = t('snmp.error.scopeTooMany')
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
    const input: SnmpCredentialInput = version === 'v2c'
      ? { name: name.trim(), version, community: community || undefined, scope: parseScope(scopeText) }
      : { name: name.trim(), version, username: username.trim(), auth, auth_password: authPassword || undefined, priv, priv_password: priv === 'aes128' ? privPassword || undefined : undefined, scope: parseScope(scopeText) }
    const done = (c: SnmpCredential) => { toast.success(t(current ? 'snmp.form.saved' : 'snmp.form.added', { name: c.name })); onClose() }
    const fail = (er: unknown) => setError(errMsg(er))
    if (current) update.mutate({ id: current.id, ...input }, { onSuccess: done, onError: fail })
    else create.mutate(input, { onSuccess: done, onError: fail })
  }

  const hint = (keep: boolean) => (keep ? t('snmp.form.keep') : t('snmp.form.passwordHint'))
  const described = (id: string, err?: string) => (err ? `${id}-error` : `${id}-hint`)
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={current ? t('snmp.form.editTitle', { name: current.name }) : t('snmp.form.addTitle')} description={t('snmp.form.body')}>
        <form onSubmit={submit} className="grid gap-4" noValidate>
          <Field label={t('snmp.form.name')} htmlFor="snmp-name" hint={t('snmp.form.nameHint')} error={errors.name}>
            <Input id="snmp-name" value={name} maxLength={64} autoComplete="off" onChange={(e) => setName(e.target.value)} aria-invalid={!!errors.name} aria-describedby={described('snmp-name', errors.name)} />
          </Field>
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">{t('snmp.form.version')}</span>
            <Segmented<Version> label={t('snmp.form.version')} value={version} onChange={(v) => { setVersion(v); setErrors({}) }}
              options={[{ value: 'v2c', label: t('snmp.version.v2c') }, { value: 'v3', label: t('snmp.version.v3') }]} />
          </div>
          {version === 'v2c' ? (
            <Field label={t('snmp.form.community')} htmlFor="snmp-community" hint={keepCommunity ? t('snmp.form.keep') : t('snmp.form.communityHint')} error={errors.community}>
              <Input id="snmp-community" type="password" value={community} maxLength={64} autoComplete="off" onChange={(e) => setCommunity(e.target.value)} aria-invalid={!!errors.community} aria-describedby={described('snmp-community', errors.community)} />
            </Field>
          ) : (
            <>
              <Field label={t('snmp.form.user')} htmlFor="snmp-user" hint={t('snmp.form.userHint')} error={errors.username}>
                <Input id="snmp-user" value={username} maxLength={64} autoComplete="off" onChange={(e) => setUsername(e.target.value)} aria-invalid={!!errors.username} aria-describedby={described('snmp-user', errors.username)} />
              </Field>
              <div className="grid gap-4 sm:grid-cols-[minmax(0,12rem)_1fr]">
                <Field label={t('snmp.form.auth')} htmlFor="snmp-auth">
                  <Select id="snmp-auth" value={auth} onChange={(e) => setAuth(e.target.value as Auth)}>
                    {(['sha256', 'sha'] as const).map((a) => <option key={a} value={a}>{t(`snmp.authName.${a}`)}</option>)}
                  </Select>
                </Field>
                <Field label={t('snmp.form.authPassword')} htmlFor="snmp-authpw" hint={hint(keepAuth)} error={errors.auth_password}>
                  <Input id="snmp-authpw" type="password" value={authPassword} maxLength={64} autoComplete="new-password" onChange={(e) => setAuthPassword(e.target.value)} aria-invalid={!!errors.auth_password} aria-describedby={described('snmp-authpw', errors.auth_password)} />
                </Field>
              </div>
              <div className="grid gap-4 sm:grid-cols-[minmax(0,12rem)_1fr]">
                <Field label={t('snmp.form.priv')} htmlFor="snmp-priv">
                  <Select id="snmp-priv" value={priv} onChange={(e) => setPriv(e.target.value as Priv)}>
                    {(['aes128', 'none'] as const).map((p) => <option key={p} value={p}>{t(`snmp.privName.${p}`)}</option>)}
                  </Select>
                </Field>
                {priv === 'aes128' ? (
                  <Field label={t('snmp.form.privPassword')} htmlFor="snmp-privpw" hint={hint(keepPriv)} error={errors.priv_password}>
                    <Input id="snmp-privpw" type="password" value={privPassword} maxLength={64} autoComplete="new-password" onChange={(e) => setPrivPassword(e.target.value)} aria-invalid={!!errors.priv_password} aria-describedby={described('snmp-privpw', errors.priv_password)} />
                  </Field>
                ) : null}
              </div>
            </>
          )}
          <Field label={t('snmp.form.scope')} htmlFor="snmp-scope" hint={t('snmp.form.scopeHint')} error={errors.scope}>
            <Textarea id="snmp-scope" rows={3} value={scopeText} placeholder={'192.168.10.0/24\n192.168.20.5'} spellCheck={false} onChange={(e) => setScopeText(e.target.value)} aria-invalid={!!errors.scope} aria-describedby={described('snmp-scope', errors.scope)} className="font-mono text-[13px]" />
          </Field>
          <p className="text-[12px] text-muted">{t('snmp.form.insecure')}</p>
          {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={pending}>{current ? t('snmp.form.save') : t('snmp.form.create')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function Answer({ r, ip }: { r: SnmpTestResult; ip: string }) {
  const { t } = useTranslation('inventory')
  const a = r.answer
  const device = r.device_id ? <Link to={`/devices/${encodeURIComponent(r.device_id)}`} className="font-medium text-accent underline-offset-4 hover:underline">{t('snmp.run.openDevice')}</Link> : null
  if (!r.ok || !a) {
    return (
      <div role="alert" className="grid gap-1 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">
        <p className="font-medium text-danger">{t('snmp.run.notRead', { ip })}</p>
        <p>{r.message}</p>
        {device ? <p>{device}</p> : null}
      </div>
    )
  }
  const rows: [string, string][] = ([
    ['sysName', a.sys_name], ['vendor', [a.vendor, a.product].filter(Boolean).join(' ')], ['model', a.model], ['os', a.os],
    ['kind', a.kind ? t(`kind.${a.kind}`, { defaultValue: a.kind }) : ''], ['serial', a.serial], ['firmware', a.firmware], ['objectId', a.sys_object_id],
  ] as [string, string][]).filter(([, v]) => v)
  return (
    <div role="status" className="grid min-w-0 gap-2 rounded-md border border-ok/40 bg-ok-soft px-3 py-2 text-sm">
      <p className="font-medium">{t('snmp.run.answered', { ip })}</p>
      <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-[max-content_1fr]">
        {rows.map(([k, v]) => <div key={k} className="contents"><dt className="text-[13px] text-muted">{t(`snmp.run.${k}`)}</dt><dd className="[overflow-wrap:anywhere]">{v}</dd></div>)}
      </dl>
      {a.sys_descr ? (
        <div className="grid min-w-0 gap-1">
          <p className="text-[13px] text-muted">{t('snmp.run.descr')}</p>
          <pre tabIndex={0} className="max-h-40 overflow-auto whitespace-pre-wrap rounded-md border border-rule bg-surface p-2 font-mono text-[12px] leading-5 [overflow-wrap:anywhere]">{a.sys_descr}</pre>
        </div>
      ) : null}
      <p className="text-[13px]">{t('snmp.run.recorded')}{device ? <> {device}</> : null}</p>
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
      {test.isPending ? <p role="status" aria-live="polite" className="text-[13px] text-muted">{t('snmp.run.pending', { ip: ip.trim() })}</p> : null}
      {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
      {result && !test.isPending ? <Answer r={result.r} ip={result.ip} /> : null}
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
          <span className="text-[13px] tabular-nums text-muted">{index + 1}.</span>
          <h3 className="text-sm font-semibold [overflow-wrap:anywhere]">{c.name}</h3>
          <Chip tone="off">{t(`snmp.version.${c.version}`)}</Chip>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => setTesting(true)} aria-label={t('snmp.testFor', { name: c.name })}>{t('snmp.test')}</Button>
          <Button size="sm" onClick={onEdit} aria-label={t('snmp.editFor', { name: c.name })}>{t('snmp.edit')}</Button>
          <Button size="sm" onClick={onDelete} aria-label={t('snmp.deleteFor', { name: c.name })}>{t('snmp.delete')}</Button>
        </div>
      </div>
      <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
        {c.version === 'v2c' ? (
          <><dt className="text-[13px] text-muted">{t('snmp.form.community')}</dt><dd><SecretMask last4={c.secret_last4} /></dd></>
        ) : (
          <>
            <dt className="text-[13px] text-muted">{t('snmp.form.user')}</dt><dd className="[overflow-wrap:anywhere]">{c.username}</dd>
            <dt className="text-[13px] text-muted">{t('snmp.form.auth')}</dt><dd>{c.auth ? t(`snmp.authName.${c.auth}`) : '—'}, <SecretMask last4={c.secret_last4} /></dd>
            <dt className="text-[13px] text-muted">{t('snmp.privLabel')}</dt>
            <dd>{c.priv === 'aes128' ? <>{t('snmp.privName.aes128')}, <SecretMask last4={c.priv_last4} /></> : t('snmp.privName.none')}</dd>
          </>
        )}
        <dt className="text-[13px] text-muted">{t('snmp.scopeLabel')}</dt>
        <dd className="[overflow-wrap:anywhere]">{c.scope.length ? c.scope.join(', ') : <span className="text-muted">{t('snmp.scopeAll')}</span>}</dd>
        <dt className="text-[13px] text-muted">{t('snmp.answersLabel')}</dt>
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
  const [editing, setEditing] = useState<SnmpCredential | 'new' | null>(null)
  const [deleting, setDeleting] = useState<SnmpCredential | null>(null)
  if (!on) return null
  const full = (q.data?.credentials.length ?? 0) >= SNMP_MAX
  return (
    <Section id="snmp" title={t('snmp.title')} description={t('snmp.description')} stories={['S-INV-1']}
      actions={<Button onClick={() => setEditing('new')} disabled={!q.data || full} title={full ? t('snmp.max') : undefined}><Plus />{t('snmp.add')}</Button>}>
      <QueryState query={q}>
        {(d) => (
          <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
            {d.ready ? null : <p role="status" className="max-w-3xl rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm">{d.message ?? t('snmp.notReady')}</p>}
            {d.credentials.length ? (
              <>
                <p className="text-[13px] text-muted">{t('snmp.order')}{full ? ` ${t('snmp.max')}` : ''}</p>
                <ol aria-label={t('snmp.caption')} className="grid gap-3">
                  {d.credentials.map((c, i) => <CredentialRow key={c.id} c={c} index={i} onEdit={() => setEditing(c)} onDelete={() => setDeleting(c)} />)}
                </ol>
              </>
            ) : <EmptyState title={t('snmp.empty')}>{t('snmp.emptyBody')}</EmptyState>}
          </div>
        )}
      </QueryState>
      {editing ? <CredentialDialog key={editing === 'new' ? 'new' : editing.id} current={editing === 'new' ? null : editing} onClose={() => setEditing(null)} /> : null}
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
