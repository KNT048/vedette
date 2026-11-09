import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus, Trash2 } from 'lucide-react'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { QueryState, Loading, ErrorState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useMe, type Role } from '@/lib/session'
import { useOidc, useOidcMutations, useToggleModule, useUserMutations, useUsers } from './api'
import { errMsg } from './parts'
import { EMAIL_RE } from './util'
import type { AdminUser, OidcConfig } from './types'

const ROLES: Role[] = ['viewer', 'operator', 'admin']

function AddDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (o: boolean) => void; onCreated: (u: AdminUser, temp: string) => void }) {
  const { t } = useTranslation('core')
  const m = useUserMutations()
  const [v, setV] = useState({ name: '', email: '', role: 'viewer' as Role })
  const [err, setErr] = useState<{ email?: string; name?: string; form?: string }>({})
  async function submit(e: React.FormEvent) {
    e.preventDefault()
    const next: typeof err = {}
    if (!v.name.trim()) next.name = t('users.add.nameError')
    if (!EMAIL_RE.test(v.email.trim())) next.email = t('users.add.emailError')
    setErr(next)
    if (next.name || next.email) return
    try {
      const r = await m.create.mutateAsync({ ...v, name: v.name.trim(), email: v.email.trim() })
      setV({ name: '', email: '', role: 'viewer' })
      onOpenChange(false)
      onCreated(r.user, r.temp_password)
    } catch (e2) { setErr({ form: errMsg(e2, t) }) }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('users.add.title')} description={t('users.add.body')}>
        <form onSubmit={(e) => void submit(e)} className="grid gap-4" noValidate>
          <Field label={t('users.add.name')} htmlFor="u-name" error={err.name}><Input id="u-name" value={v.name} aria-invalid={!!err.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
          <Field label={t('users.add.email')} htmlFor="u-email" error={err.email}><Input id="u-email" type="email" value={v.email} aria-invalid={!!err.email} onChange={(e) => setV({ ...v, email: e.target.value })} /></Field>
          <Field label={t('users.add.role')} htmlFor="u-role" hint={t(`users.roleHint.${v.role}`)}>
            <Select id="u-role" value={v.role} onChange={(e) => setV({ ...v, role: e.target.value as Role })}>{ROLES.map((r) => <option key={r} value={r}>{t(`common:role.${r}`)}</option>)}</Select>
          </Field>
          {err.form ? <p role="alert" className="text-[13px] text-danger">{err.form}</p> : null}
          <DialogFooter><Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button><Button type="submit" variant="primary" disabled={m.create.isPending}>{t('users.add.submit')}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function OidcPanel() {
  const { t } = useTranslation('core')
  const on = useModuleEnabled('auth-oidc')
  const toggle = useToggleModule()
  const q = useOidc()
  if (on === undefined) return <Loading />
  async function enable(v: boolean) {
    try { await toggle.mutateAsync({ id: 'auth-oidc', enabled: v }); toast.success(v ? t('oidc.enabledToast') : t('oidc.disabledToast')) } catch (e) { toast.error(errMsg(e, t)) }
  }
  if (!on) {
    return (
      <div className="rounded-md border border-dashed border-rule bg-surface px-5 py-4">
        <p className="text-sm">{t('oidc.off')}</p>
        <Button className="mt-3" onClick={() => void enable(true)} disabled={toggle.isPending}>{t('oidc.enable')}</Button>
      </div>
    )
  }
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  return <OidcForm cfg={q.data} onDisable={() => void enable(false)} />
}

function OidcForm({ cfg, onDisable }: { cfg: OidcConfig; onDisable: () => void }) {
  const { t } = useTranslation('core')
  const m = useOidcMutations()
  const [v, setV] = useState({ issuer: cfg.issuer, client_id: cfg.client_id, client_secret: '', default_role: cfg.default_role, role_map: cfg.role_map })
  const [error, setError] = useState<string | null>(null)
  async function save(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    try { await m.save.mutateAsync(v); setV((x) => ({ ...x, client_secret: '' })); toast.success(t('common:saved')) } catch (err) { setError(errMsg(err, t)) }
  }
  async function test() {
    try { await m.test.mutateAsync(); toast.success(t('oidc.testOk')) } catch (err) { toast.error(errMsg(err, t)) }
  }
  const setMap = (i: number, patch: Partial<{ group: string; role: Role }>) => setV({ ...v, role_map: v.role_map.map((r, k) => (k === i ? { ...r, ...patch } : r)) })
  return (
    <form onSubmit={(e) => void save(e)} className="grid max-w-xl gap-4" noValidate>
      <CodeBlock label={t('oidc.redirect')} code={`${location.origin}/api/v1/auth/oidc/callback`} />
      <Field label={t('oidc.issuer')} hint={t('oidc.issuerHint')} htmlFor="oidc-issuer" error={error ?? undefined}><Input id="oidc-issuer" value={v.issuer} aria-invalid={!!error} onChange={(e) => setV({ ...v, issuer: e.target.value })} placeholder="https://sso.acme.example/realms/main" /></Field>
      <Field label={t('oidc.clientId')} htmlFor="oidc-client"><Input id="oidc-client" value={v.client_id} onChange={(e) => setV({ ...v, client_id: e.target.value })} /></Field>
      <Field label={t('oidc.secret')} hint={cfg.secret_last4 ? t('oidc.secretSaved', { last4: cfg.secret_last4 }) : t('oidc.secretHint')} htmlFor="oidc-secret"><Input id="oidc-secret" type="password" autoComplete="off" value={v.client_secret} onChange={(e) => setV({ ...v, client_secret: e.target.value })} /></Field>
      <Field label={t('oidc.defaultRole')} hint={t('oidc.defaultRoleHint')} htmlFor="oidc-default">
        <Select id="oidc-default" value={v.default_role} onChange={(e) => setV({ ...v, default_role: e.target.value as Role })}>{ROLES.map((r) => <option key={r} value={r}>{t(`common:role.${r}`)}</option>)}</Select>
      </Field>
      <fieldset className="grid gap-2">
        <legend className="text-sm font-medium">{t('oidc.map')}</legend>
        <p className="text-[13px] text-muted">{t('oidc.mapHint')}</p>
        {v.role_map.map((r, i) => (
          <div key={i} className="flex flex-wrap items-center gap-2">
            <Input className="max-w-56" aria-label={t('oidc.group', { n: i + 1 })} value={r.group} onChange={(e) => setMap(i, { group: e.target.value })} placeholder="vedette-admins" />
            <Select className="w-40" aria-label={t('oidc.mapRole', { n: i + 1 })} value={r.role} onChange={(e) => setMap(i, { role: e.target.value as Role })}>{ROLES.map((x) => <option key={x} value={x}>{t(`common:role.${x}`)}</option>)}</Select>
            <Button variant="ghost" size="icon" aria-label={t('oidc.mapRemove', { n: i + 1 })} onClick={() => setV({ ...v, role_map: v.role_map.filter((_, k) => k !== i) })}><Trash2 /></Button>
          </div>
        ))}
        <div><Button size="sm" onClick={() => setV({ ...v, role_map: [...v.role_map, { group: '', role: 'viewer' }] })}><Plus />{t('oidc.mapAdd')}</Button></div>
      </fieldset>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="primary" disabled={m.save.isPending}>{t('common:save')}</Button>
        <Button onClick={() => void test()} disabled={m.test.isPending || !cfg.issuer} title={cfg.issuer ? undefined : t('oidc.saveFirst')}>{t('oidc.test')}</Button>
        <Button variant="ghost" onClick={onDisable}>{t('oidc.disable')}</Button>
      </div>
    </form>
  )
}

export default function UsersSection() {
  const { t } = useTranslation('core')
  const me = useMe().data
  const q = useUsers()
  const m = useUserMutations()
  const [adding, setAdding] = useState(false)
  const [temp, setTemp] = useState<{ email: string; password: string; kind: 'create' | 'reset' } | null>(null)
  const [askReset, setAskReset] = useState<AdminUser | null>(null)
  const [askReset2fa, setAskReset2fa] = useState<AdminUser | null>(null)

  async function patch(u: AdminUser, p: { role?: Role; disabled?: boolean }) {
    try { await m.patch.mutateAsync({ id: u.id, ...p }); toast.success(t('common:saved')) } catch (e) { toast.error(errMsg(e, t)) }
  }
  async function reset(u: AdminUser) {
    try { const r = await m.reset.mutateAsync(u.id); setAskReset(null); setTemp({ email: u.email, password: r.temp_password, kind: 'reset' }) } catch (e) { setAskReset(null); toast.error(errMsg(e, t)) }
  }

  async function reset2fa(u: AdminUser) {
    try { await m.reset2fa.mutateAsync(u.id); setAskReset2fa(null); toast.success(t('users.resetTwofaDone')) } catch (e) { setAskReset2fa(null); toast.error(errMsg(e, t)) }
  }

  return (
    <>
      <PageHeader
        title={q.data ? t('users.title', { count: q.data.items.filter((u) => !u.disabled).length }) : t('settings.users')}
        meta={t('users.meta')} stories={['S-CORE-3']}
        actions={<Button variant="primary" onClick={() => setAdding(true)}><Plus />{t('users.add.open')}</Button>}
      />
      <QueryState query={q}>
        {({ items }) => {
          const isMe = (u: AdminUser) => u.id === me?.id
          const roleSelect = (u: AdminUser) => (
            <Select className="h-8 w-36" aria-label={t('users.roleOf', { name: u.name })} value={u.role} onChange={(e) => void patch(u, { role: e.target.value as Role })}>{ROLES.map((r) => <option key={r} value={r}>{t(`common:role.${r}`)}</option>)}</Select>
          )
          const actions = (u: AdminUser) => (
            <div className="flex flex-wrap gap-1.5">
              <Button size="sm" onClick={() => setAskReset(u)} aria-label={t('users.resetOf', { name: u.name })}>{t('users.reset')}</Button>
              <Button size="sm" disabled={isMe(u) && !u.disabled} title={isMe(u) && !u.disabled ? t('users.selfDisable') : undefined} onClick={() => void patch(u, { disabled: !u.disabled })} aria-label={t(u.disabled ? 'users.enableOf' : 'users.disableOf', { name: u.name })}>{u.disabled ? t('users.enable') : t('users.disable')}</Button>
              {u.twofa ? <Button size="sm" disabled={isMe(u)} title={isMe(u) ? t('users.resetTwofaSelf') : undefined} onClick={() => setAskReset2fa(u)} aria-label={t('users.resetTwofaOf', { name: u.name })}>{t('users.resetTwofa')}</Button> : null}
            </div>
          )
          const nameCell = (u: AdminUser) => <div className="grid"><span className="font-medium">{u.name}{isMe(u) ? <span className="ml-2 text-[12px] font-normal text-muted">{t('users.you')}</span> : null}</span><span className="break-all text-[13px] text-muted">{u.email}</span></div>
          const twofa = (u: AdminUser) => (u.twofa_method ? <Chip tone="ok">{t(`users.method.${u.twofa_method}`)}</Chip> : <Chip tone="off">{t('users.twofaOff')}</Chip>)
          const stateChip = (u: AdminUser) => (u.disabled ? <Chip tone="off">{t('users.disabled')}</Chip> : <Chip tone="ok">{t('users.active')}</Chip>)
          const columns: ColumnDef<AdminUser>[] = [
            { id: 'name', header: t('users.col.name'), accessorFn: (u) => u.name, cell: ({ row }) => nameCell(row.original) },
            { id: 'role', header: t('users.col.role'), accessorFn: (u) => u.role, cell: ({ row }) => roleSelect(row.original) },
            { id: 'twofa', header: t('users.col.twofa'), accessorFn: (u) => u.twofa_method ?? '', cell: ({ row }) => twofa(row.original) },
            { id: 'last', header: t('users.col.last'), accessorFn: (u) => u.last_login ?? '', cell: ({ row }) => (row.original.last_login ? fmtRelative(row.original.last_login) : t('users.never')) },
            { id: 'state', header: t('users.col.state'), accessorFn: (u) => Number(!!u.disabled), cell: ({ row }) => stateChip(row.original) },
            { id: 'actions', header: t('users.col.actions'), enableSorting: false, accessorFn: () => '', cell: ({ row }) => actions(row.original) },
          ]
          return (
            <DataTable data={items} columns={columns} caption={t('users.caption')} filterPlaceholder={t('users.filter')}
              mobileRow={(u) => (
                <div className="grid gap-2">
                  <div className="flex items-start justify-between gap-3">{nameCell(u)}{stateChip(u)}</div>
                  <div className="flex flex-wrap items-center gap-2">{roleSelect(u)}{twofa(u)}<span className="text-[12px] text-muted">{u.last_login ? fmtRelative(u.last_login) : t('users.never')}</span></div>
                  {actions(u)}
                </div>
              )} />
          )
        }}
      </QueryState>

      <div className="mt-8">
        <Section title={t('oidc.title')} description={t('oidc.desc')} stories={['S-CORE-3']}><OidcPanel /></Section>
      </div>

      <AddDialog open={adding} onOpenChange={setAdding} onCreated={(u, p) => setTemp({ email: u.email, password: p, kind: 'create' })} />

      <Dialog open={!!askReset} onOpenChange={(o) => !o && setAskReset(null)}>
        <DialogContent title={t('users.resetAsk.title', { name: askReset?.name ?? '' })} description={t('users.resetAsk.body')}>
          <DialogFooter><Button onClick={() => setAskReset(null)}>{t('common:cancel')}</Button><Button variant="danger" disabled={m.reset.isPending} onClick={() => askReset && void reset(askReset)}>{t('users.resetAsk.confirm')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!askReset2fa} onOpenChange={(o) => !o && setAskReset2fa(null)}>
        <DialogContent title={t('users.resetTwofaAsk.title', { name: askReset2fa?.name ?? '' })} description={t('users.resetTwofaAsk.body')}>
          <DialogFooter><Button onClick={() => setAskReset2fa(null)}>{t('common:cancel')}</Button><Button variant="danger" disabled={m.reset2fa.isPending} onClick={() => askReset2fa && void reset2fa(askReset2fa)}>{t('users.resetTwofaAsk.confirm')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!temp} onOpenChange={(o) => !o && setTemp(null)}>
        <DialogContent title={temp?.kind === 'reset' ? t('users.temp.titleReset') : t('users.temp.titleCreate')} description={t('users.temp.body', { email: temp?.email ?? '' })}>
          {temp ? <CodeBlock label={t('users.temp.label')} code={temp.password} /> : null}
          <DialogFooter><Button variant="primary" onClick={() => setTemp(null)}>{t('users.temp.done')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
