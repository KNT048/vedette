import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { useNetwork, useNetworkActions } from './api'
import { errMsg, ReadOnlyNote, useGate } from './parts'
import { SpanCard } from './SpanCard'
import { SpanGuides } from './SpanGuides'
import type { IfaceRole, Management, NetInterface, NetworkState, NtpConfig } from './types'

function useSecondsLeft(iso: string | null) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!iso) return
    const id = setInterval(() => setNow(Date.now()), 500)
    return () => clearInterval(id)
  }, [iso])
  return iso ? Math.min(120, Math.max(0, Math.ceil((new Date(iso).getTime() - now) / 1000))) : 0
}
const mmss = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
const list = (v: string) => v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

function Interfaces({ d }: { d: NetworkState }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const { roles } = useNetworkActions()
  const [error, setError] = useState<string | null>(null)
  function setRole(name: string, role: IfaceRole) {
    setError(null)
    roles.mutate(Object.fromEntries(d.interfaces.map((i) => [i.name, i.name === name ? role : i.role])), { onError: (e) => setError(errMsg(e, t)), onSuccess: () => toast.success(t('network.interfaces.saved')) })
  }
  const roleControl = (row: { original: NetInterface }) => row.original.role === 'management'
      ? <span title={t('network.interfaces.mgmtLocked')}><Chip tone="accent">{t('network.role.management')}</Chip></span>
      : (
        <Select aria-label={t('network.interfaces.roleOf', { name: row.original.name })} value={row.original.role} disabled={gate.disabled || roles.isPending} title={gate.title} className="w-44" onChange={(e) => setRole(row.original.name, e.target.value as IfaceRole)}>
          {(['management', 'span', 'unused'] as const).map((r) => <option key={r} value={r}>{t(`network.role.${r}`)}</option>)}
        </Select>
      )
  const columns: ColumnDef<NetInterface>[] = [
    { id: 'name', header: t('network.interfaces.col.name'), accessorFn: (i) => i.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: 'role', header: t('network.interfaces.col.role'), accessorFn: (i) => i.role, cell: ({ row }) => roleControl(row) },
    { id: 'link', header: t('network.interfaces.col.link'), accessorFn: (i) => i.link, cell: ({ row }) => row.original.link ? <Chip tone="ok">{t('network.interfaces.up')}</Chip> : <Chip tone="off">{t('network.interfaces.down')}</Chip> },
    { id: 'speed', header: t('network.interfaces.col.speed'), accessorFn: (i) => i.speed ?? '', cell: ({ row }) => row.original.speed ?? <span className="text-muted">–</span> },
    { id: 'mac', header: t('network.interfaces.col.mac'), accessorFn: (i) => i.mac, cell: ({ row }) => <span className="font-mono text-[12.5px]">{row.original.mac}</span> },
    { id: 'address', header: t('network.interfaces.col.address'), accessorFn: (i) => i.address ?? '', cell: ({ row }) => row.original.address ?? <span className="text-muted">{row.original.role === 'span' ? t('network.interfaces.noIp') : '–'}</span> },
  ]
  return (
    <Section id="interfaces" title={t('network.interfaces.title')} description={t('network.interfaces.desc')} stories={['S-CORE-8']}>
      <DataTable caption={t('network.interfaces.caption')} data={d.interfaces} columns={columns}
        mobileRow={(i) => (
          <div className="grid gap-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium">{i.name}</span>
              {i.link ? <Chip tone="ok">{t('network.interfaces.up')}</Chip> : <Chip tone="off">{t('network.interfaces.down')}</Chip>}
            </div>
            <div>{roleControl({ original: i })}</div>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-[13px]">
              <dt className="text-muted">{t('network.interfaces.col.address')}</dt><dd className="break-all">{i.address ?? (i.role === 'span' ? t('network.interfaces.noIp') : '–')}</dd>
              <dt className="text-muted">{t('network.interfaces.col.mac')}</dt><dd className="break-all font-mono text-[12.5px]">{i.mac}</dd>
              <dt className="text-muted">{t('network.interfaces.col.speed')}</dt><dd>{i.speed ?? '–'}</dd>
            </dl>
          </div>
        )} />
      {error ? <p role="alert" className="mt-3 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
    </Section>
  )
}

function Pending({ d }: { d: NetworkState }) {
  const { t } = useTranslation('core')
  const { confirm, revert } = useNetworkActions()
  const left = useSecondsLeft(d.pending?.expires_at ?? null)
  const [error, setError] = useState<string | null>(null)
  const settled = useRef(false)
  // A pending change that disappears without us confirming or cancelling it timed out: the box went back.
  const had = useRef(false)
  useEffect(() => {
    if (d.pending) { had.current = true; settled.current = false; return }
    if (had.current && !settled.current) toast.warning(t('network.management.reverted'))
    had.current = false
  }, [d.pending, t])
  if (!d.pending) return null
  const ip = d.management.address ?? '?'
  return (
    <div role="status" className="mb-4 grid gap-3 rounded-md border border-warn/50 bg-warn-soft px-4 py-3">
      <p className="text-sm font-medium">{t('network.pending.title', { ip })}</p>
      <p className="text-sm">{t('network.pending.body', { ip, old: d.pending.previous_address ?? 'DHCP' })}</p>
      <p className="text-sm" aria-live="off">{t('network.pending.left')}: <strong className="tabular-nums">{mmss(left)}</strong></p>
      {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" disabled={confirm.isPending} onClick={() => { settled.current = true; setError(null); confirm.mutate(undefined, { onSuccess: () => toast.success(t('network.pending.confirmed')), onError: (e) => setError(errMsg(e, t)) }) }}>{t('network.pending.confirm')}</Button>
        <Button disabled={revert.isPending} onClick={() => { settled.current = true; setError(null); revert.mutate(undefined, { onError: (e) => setError(errMsg(e, t)) }) }}>{t('network.pending.revert')}</Button>
      </div>
    </div>
  )
}

function ManagementForm({ d }: { d: NetworkState }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const { management } = useNetworkActions()
  const m = d.management
  const [mode, setMode] = useState<Management['mode']>(m.mode)
  const [address, setAddress] = useState(m.mode === 'static' ? (m.address ?? '') : '')
  const [prefix, setPrefix] = useState(m.mode === 'static' ? String(m.prefix ?? 24) : '24')
  const [gateway, setGateway] = useState(m.mode === 'static' ? (m.gateway ?? '') : '')
  const [dns, setDns] = useState(m.mode === 'static' ? m.dns.join(', ') : '')
  const [error, setError] = useState<string | null>(null)
  const [ask, setAsk] = useState<string | null>(null)
  const locked = gate.disabled || !!d.pending
  const pick = (v: Management['mode']) => {
    setMode(v); setError(null)
    // Fields of the other option do not carry over.
    if (v === 'dhcp') { setAddress(''); setPrefix('24'); setGateway(''); setDns('') }
  }
  const send = (confirm: boolean) => {
    setError(null)
    const body = mode === 'dhcp' ? { mode, confirm } : { mode, address: address.trim(), prefix: Number(prefix), gateway: gateway.trim(), dns: list(dns), confirm }
    management.mutate(body, {
      onSuccess: () => { setAsk(null); toast.success(t('network.management.saved')) },
      onError: (e) => {
        if (e instanceof ApiError && e.code === 'confirm_required') { setAsk(String(e.details.new_ip ?? address)); return }
        setAsk(null); setError(errMsg(e, t))
      },
    })
  }
  return (
    <>
      <form className="grid max-w-xl gap-4" noValidate onSubmit={(e) => { e.preventDefault(); send(false) }}>
        <Field label={t('network.management.mode')} htmlFor="mgmt-mode">
          <Select id="mgmt-mode" value={mode} disabled={locked} onChange={(e) => pick(e.target.value as Management['mode'])}>
            <option value="static">{t('network.management.static')}</option>
            <option value="dhcp">{t('network.management.dhcp')}</option>
          </Select>
        </Field>
        {mode === 'dhcp' ? (
          <p className="max-w-lg rounded-md border border-rule bg-sunken px-3 py-2 text-[13px]">{t('network.management.dhcpNote')}{m.mode === 'dhcp' && m.address ? ` ${t('network.management.dhcpNow', { ip: m.address })}` : ''}</p>
        ) : (
          <>
            <div className="grid grid-cols-[minmax(0,1fr)_96px] gap-3">
              <Field label={t('network.management.address')} htmlFor="mgmt-address"><Input id="mgmt-address" inputMode="decimal" autoComplete="off" value={address} disabled={locked} placeholder="192.168.10.250" onChange={(e) => setAddress(e.target.value)} /></Field>
              <Field label={t('network.management.prefix')} htmlFor="mgmt-prefix"><Input id="mgmt-prefix" type="number" min={8} max={30} value={prefix} disabled={locked} onChange={(e) => setPrefix(e.target.value)} /></Field>
            </div>
            <Field label={t('network.management.gateway')} htmlFor="mgmt-gateway"><Input id="mgmt-gateway" inputMode="decimal" autoComplete="off" value={gateway} disabled={locked} placeholder="192.168.10.1" onChange={(e) => setGateway(e.target.value)} /></Field>
            <Field label={t('network.management.dns')} htmlFor="mgmt-dns" hint={t('network.management.dnsHint')}><Input id="mgmt-dns" autoComplete="off" value={dns} disabled={locked} placeholder="192.168.10.1" onChange={(e) => setDns(e.target.value)} /></Field>
          </>
        )}
        {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
        <div><Button type="submit" variant="primary" disabled={locked || management.isPending} title={gate.title}>{t('network.management.save')}</Button></div>
      </form>
      {ask ? (
        <Dialog open onOpenChange={(o) => { if (!o) setAsk(null) }}>
          <DialogContent title={t('network.confirm.title')} description={t('network.confirm.body', { ip: ask })}>
            <p className="text-sm">{t('network.confirm.lose', { ip: ask })}</p>
            <DialogFooter>
              <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
              <Button variant="primary" disabled={management.isPending} onClick={() => send(true)}>{t('network.confirm.go')}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  )
}

function NtpForm({ d }: { d: NetworkState }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const { ntp } = useNetworkActions()
  const [mode, setMode] = useState<NtpConfig['mode']>(d.ntp.mode)
  const [servers, setServers] = useState(d.ntp.servers.join(', '))
  const [error, setError] = useState<string | null>(null)
  return (
    <form className="grid max-w-xl gap-4" noValidate onSubmit={(e) => {
      e.preventDefault(); setError(null)
      ntp.mutate(mode === 'default' ? { mode, servers: [] } : { mode, servers: list(servers) }, { onSuccess: () => toast.success(t('network.ntp.saved')), onError: (er) => setError(errMsg(er, t)) })
    }}>
      <Field label={t('network.ntp.mode')} htmlFor="ntp-mode">
        <Select id="ntp-mode" value={mode} disabled={gate.disabled} onChange={(e) => { setMode(e.target.value as NtpConfig['mode']); setError(null); if (e.target.value === 'default') setServers('') }}>
          <option value="default">{t('network.ntp.default', { pool: d.default_ntp })}</option>
          <option value="custom">{t('network.ntp.custom')}</option>
        </Select>
      </Field>
      {mode === 'custom'
        ? <Field label={t('network.ntp.servers')} htmlFor="ntp-servers" hint={t('network.ntp.serversHint')}><Input id="ntp-servers" autoComplete="off" value={servers} disabled={gate.disabled} placeholder="ntp.company.lan" onChange={(e) => setServers(e.target.value)} /></Field>
        : <p className="text-[13px] text-muted">{t('network.ntp.defaultNote')}</p>}
      {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
      <div><Button type="submit" variant="primary" disabled={gate.disabled || ntp.isPending} title={gate.title}>{t('common:save')}</Button></div>
    </form>
  )
}

function Body({ d }: { d: NetworkState }) {
  const { t } = useTranslation('core')
  return (
    <>
      <ReadOnlyNote role="admin" />
      <p className="mb-6 max-w-3xl rounded-md border border-rule bg-sunken px-4 py-2.5 text-[13px]">{t('network.helper')}</p>
      <Interfaces d={d} />
      <Section id="management" title={t('network.management.title')} description={t('network.management.desc')} stories={['S-CORE-8']}>
        <Pending d={d} />
        <ManagementForm key={JSON.stringify(d.management) + String(!!d.pending)} d={d} />
      </Section>
      <SpanCard key={JSON.stringify(d.span)} d={d} />
      <SpanGuides spanPort={d.span.interface ?? d.interfaces.find((i) => i.role === 'span')?.name ?? 'eth1'} />
      <Section id="decoys" title={t('network.decoys.title')} description={t('network.decoys.desc')} stories={['S-CORE-8']}>
        {d.decoy_ips.length
          ? <ul aria-label={t('network.decoys.title')} className="flex flex-wrap gap-2">{d.decoy_ips.map((ip) => <li key={ip} className="rounded-md border border-rule bg-surface px-2.5 py-1 font-mono text-[12.5px]">{ip}</li>)}</ul>
          : <p className="text-sm text-muted">{t('network.decoys.none')}</p>}
        <p className="mt-3 text-sm"><Link to="/honeypot" className="text-accent underline-offset-4 hover:underline">{t('network.decoys.link')}</Link></p>
      </Section>
      <Section id="ntp" title={t('network.ntp.title')} description={t('network.ntp.desc')} stories={['S-CORE-8']}>
        <NtpForm key={JSON.stringify(d.ntp)} d={d} />
        <p className="mt-3 text-[13px] text-muted">{t('network.ntp.privacy')} <Link to="/settings/privacy" className="text-accent underline-offset-4 hover:underline">{t('network.ntp.privacyLink')}</Link></p>
      </Section>
    </>
  )
}

export default function NetworkSection() {
  const { t } = useTranslation('core')
  const q = useNetwork()
  return (
    <>
      <PageHeader title={t('settings.network')} meta={t('network.meta')} stories={['S-CORE-8', 'S-INV-1', 'S-LOG-4']} />
      <QueryState query={q}>{(d) => <Body d={d} />}</QueryState>
    </>
  )
}
