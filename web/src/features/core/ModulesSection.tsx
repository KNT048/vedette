import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice, PageHeader } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip } from '@/components/common/StatusChip'
import { InfoTip } from '@/components/common/InfoTip'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { useModules, type ModuleId, type ModuleState } from '@/lib/modules'
import { notOffered, scopeOf } from '@/lib/v1'
import { ScopeBadge, ScopeLine } from '@/components/common/V1Scope'
import { fmtDate } from '@/lib/format'
import { useOidc, useToggleModule, useUsers } from './api'
import { Slot } from '@/components/common/Slot'
import { errMsg, ReadOnlyNote, useGate } from './parts'

type Confirm = { kind: 'disable'; mod: ModuleId; affected: ModuleId[] } | { kind: 'deps'; mod: ModuleId; missing: ModuleId[] } | null

/** Turning off the notify module while email-code users remain: they would not be able to sign in. Only fetched when the dialog shows, and only an admin can read the user list. */
function EmailCodeWarning() {
  const { t } = useTranslation('core')
  const count = (useUsers().data?.items ?? []).filter((u) => !u.disabled && u.twofa_method === 'email').length
  return count > 0 ? <Notice tone="danger" role="alert" className="mb-0" title={t('modules.disable.emailCodes', { count })} info={t('modules.disable.emailCodesInfo')} /> : null
}

/** Turning SSO off here locks out the people who only sign in through it, as on the Users page; in v1 it never comes back. */
function SsoUsersWarning() {
  const { t } = useTranslation('core')
  const n = useOidc(true).data?.sso_users ?? 0
  return n > 0 ? <Notice tone="danger" role="alert" className="mb-0" title={t('modules.disable.ssoUsers', { count: n })} /> : null
}

export default function ModulesSection() {
  const { t, i18n } = useTranslation('core')
  const gate = useGate('admin')
  const q = useModules()
  const install = q.data?.install
  const toggle = useToggleModule()
  const [confirm, setConfirm] = useState<Confirm>(null)
  const name = (id: ModuleId) => t(`modules.${id}.name`, { ns: 'common' })
  // #819: a module this build does not offer is not listed unless this box has it on; then it is listed
  // read-only, and its switch can only turn it off.
  const listed = q.data?.modules.filter((m) => scopeOf(m.id, m.enabled) !== 'hidden')

  async function run(id: ModuleId, enabled: boolean, withDependencies = false) {
    try {
      const r = await toggle.mutateAsync({ id, enabled, withDependencies })
      if (r.kind === 'missing') { setConfirm({ kind: 'deps', mod: id, missing: r.missing }); return }
      setConfirm(null)
      toast.success(enabled ? t('modules.enabledToast', { name: name(id) }) : t('modules.disabledToast', { name: name(id), count: r.affected.length }))
    } catch (err) { setConfirm(null); toast.error(errMsg(err, t)) }
  }

  function onSwitch(all: ModuleState[], m: ModuleState, next: boolean) {
    if (next && notOffered(m.id)) return // Only the way out
    if (next) { void run(m.id, true); return }
    setConfirm({ kind: 'disable', mod: m.id, affected: all.filter((x) => x.enabled && x.depends.includes(m.id)).map((x) => x.id) })
  }

  return (
    <>
      <PageHeader title={listed ? t('modules.title', { on: listed.filter((m) => m.enabled).length, total: listed.length }) : t('settings.modules')} meta={t('modules.meta')} info={t('modules.metaInfo')} stories={['S-CORE-1']} />
      <ReadOnlyNote role="admin" />
      <QueryState query={q}>
        {(d) => {
          const modules = d.modules.filter((m) => scopeOf(m.id, m.enabled) !== 'hidden')
          const about = (m: ModuleState) => (
            <div className="grid max-w-md"><div className="flex items-center gap-1 font-medium">{name(m.id)}{i18n.exists(`modules.${m.id}.summaryInfo`, { ns: 'common' }) ? <InfoTip topic={name(m.id)}>{t(`modules.${m.id}.summaryInfo`, { ns: 'common' })}</InfoTip> : null}{' '}<ScopeBadge scope={scopeOf(m.id, m.enabled)} className="ml-1.5" /></div><span className="text-meta text-muted">{t(`modules.${m.id}.${m.id === 'sensor-active' && install === 'container' ? 'summaryContainer' : 'summary'}`, { ns: 'common' })}</span>{m.available ? null : <span className="text-meta text-warn">{t('modules.notHereWhy')}</span>}<ScopeLine scope={scopeOf(m.id, m.enabled)} /></div>
          )
          const state = (m: ModuleState) => !m.available ? <Chip tone="off">{t('modules.notHere')}</Chip>
            : m.enabled ? <Chip tone="ok">{m.tier === 'core' ? t('modules.always') : t('modules.on')}</Chip> : <Chip tone="off">{t('modules.off')}</Chip>
          // #842 §0: `module-<id>` is the deep-link target of every "turn on <module>" link (/settings/modules#module-<id>): it lands on the switch.
          const toggleOf = (m: ModuleState) => {
            const locked = m.tier === 'core'
            const notHere = !m.available && !m.enabled // A module this install cannot run cannot be turned on; one left on can be turned off
            return <Switch id={`module-${m.id}`} checked={m.enabled} disabled={locked || notHere || gate.disabled || toggle.isPending} title={locked ? t('modules.coreLocked') : notHere ? t('modules.notHereWhy') : gate.title} aria-label={t(m.enabled ? 'modules.toggleOff' : 'modules.toggle', { name: name(m.id) })} onCheckedChange={(v) => onSwitch(modules, m, v)} />
          }
          const columns: ColumnDef<ModuleState>[] = [
            { id: 'name', header: t('modules.col.module'), accessorFn: (m) => name(m.id), cell: ({ row }) => about(row.original) },
            { id: 'depends', header: t('modules.col.needs'), enableSorting: false, accessorFn: (m) => m.depends.join(','), cell: ({ row }) => (row.original.depends.length ? <span className="text-meta">{row.original.depends.map(name).join(', ')}</span> : <span className="text-muted">–</span>) },
            { id: 'state', header: t('modules.col.state'), accessorFn: (m) => Number(m.enabled), cell: ({ row }) => state(row.original) },
            { id: 'since', header: t('modules.col.since'), accessorFn: (m) => m.enabled_at ?? '', cell: ({ row }) => fmtDate(row.original.enabled_at) },
            { id: 'switch', header: t('modules.col.switch'), enableSorting: false, accessorFn: () => '', cell: ({ row }) => toggleOf(row.original) },
          ]
          // Phones (UI.md §5: over 3 columns): the module, what it needs, its state and its switch in one row.
          const mobileRow = (m: ModuleState) => (
            <div className="grid gap-2">
              <div className="flex items-start justify-between gap-3">{about(m)}<div className="shrink-0 pt-0.5">{toggleOf(m)}</div></div>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-meta text-muted">{state(m)}{m.depends.length ? <span>{t('modules.col.needs')}: {m.depends.map(name).join(', ')}</span> : null}</div>
            </div>
          )
          return <DataTable urlKey="modules" data={modules} columns={columns} mobileRow={mobileRow} caption={t('modules.caption')} pageSize={30} filterPlaceholder={t('modules.filter')} />
        }}
      </QueryState>

      <Dialog open={confirm?.kind === 'deps'} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent title={t('modules.deps.title')} description={confirm?.kind === 'deps' ? t('modules.deps.body', { name: name(confirm.mod) }) : undefined}>
          {confirm?.kind === 'deps' ? <ul className="list-disc pl-5 text-sm">{confirm.missing.map((id) => <li key={id}>{name(id)}</li>)}</ul> : null}
          <DialogFooter>
            <Button onClick={() => setConfirm(null)}>{t('common:cancel')}</Button>
            <Button variant="primary" busy={toggle.isPending} busyLabel={t('common:busy.turningOn')} onClick={() => confirm?.kind === 'deps' && void run(confirm.mod, true, true)}>{t('modules.deps.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirm?.kind === 'disable'} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent title={confirm?.kind === 'disable' ? t('modules.disable.title', { name: name(confirm.mod) }) : ''} description={t('modules.disable.keep')}
          info={confirm?.kind === 'disable' && notOffered(confirm.mod) ? t('modules.disable.notOffered') : t('modules.disable.reenable')}>
          {confirm?.kind === 'disable' ? (
            confirm.affected.length ? (
              <div className="grid gap-2 text-sm">
                <p>{t('modules.disable.affected')}</p>
                <ul className="list-disc pl-5">{confirm.affected.map((id) => <li key={id}>{name(id)}</li>)}</ul>
              </div>
            ) : <p className="text-sm text-muted">{t('modules.disable.none')}</p>
          ) : null}
          {confirm?.kind === 'disable' && confirm.mod === 'notify' ? <EmailCodeWarning /> : null}
          {confirm?.kind === 'disable' && confirm.mod === 'auth-oidc' ? <SsoUsersWarning /> : null}
          {/* what a module says stays in force once it is off (response: CONTRACT "when a module is turned off") */}
          {confirm?.kind === 'disable' ? <Slot name="modules.disable" props={{ module: confirm.mod, onClose: () => setConfirm(null) }} /> : null}
          <DialogFooter>
            <Button onClick={() => setConfirm(null)}>{t('common:cancel')}</Button>
            <Button variant="danger" busy={toggle.isPending} busyLabel={t('common:busy.turningOff')} onClick={() => confirm?.kind === 'disable' && void run(confirm.mod, false)}>{t('modules.disable.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
