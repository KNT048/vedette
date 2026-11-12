import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { useModules, type ModuleId, type ModuleState } from '@/lib/modules'
import { fmtDate } from '@/lib/format'
import { useToggleModule, useUsers } from './api'
import { errMsg, ReadOnlyNote, useGate } from './parts'

type Confirm = { kind: 'disable'; mod: ModuleId; affected: ModuleId[] } | { kind: 'deps'; mod: ModuleId; missing: ModuleId[] } | null

/** Tắt module notify khi còn người dùng mã email: họ sẽ không đăng nhập được (D-35). Chỉ mở khi hộp thoại hiện, và chỉ quản trị đọc được danh sách người dùng. */
function EmailCodeWarning() {
  const { t } = useTranslation('core')
  const count = (useUsers().data?.items ?? []).filter((u) => !u.disabled && u.twofa_method === 'email').length
  return count > 0 ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{t('modules.disable.emailCodes', { count })}</p> : null
}

export default function ModulesSection() {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const q = useModules()
  const toggle = useToggleModule()
  const [confirm, setConfirm] = useState<Confirm>(null)
  const name = (id: ModuleId) => t(`modules.${id}.name`, { ns: 'common' })

  async function run(id: ModuleId, enabled: boolean, withDependencies = false) {
    try {
      const r = await toggle.mutateAsync({ id, enabled, withDependencies })
      if (r.kind === 'missing') { setConfirm({ kind: 'deps', mod: id, missing: r.missing }); return }
      setConfirm(null)
      toast.success(enabled ? t('modules.enabledToast', { name: name(id) }) : t('modules.disabledToast', { name: name(id), count: r.affected.length }))
    } catch (err) { setConfirm(null); toast.error(errMsg(err, t)) }
  }

  function onSwitch(all: ModuleState[], m: ModuleState, next: boolean) {
    if (next) { void run(m.id, true); return }
    setConfirm({ kind: 'disable', mod: m.id, affected: all.filter((x) => x.enabled && x.depends.includes(m.id)).map((x) => x.id) })
  }

  return (
    <>
      <PageHeader title={q.data ? t('modules.title', { on: q.data.modules.filter((m) => m.enabled).length, total: q.data.modules.length }) : t('settings.modules')} meta={t('modules.meta')} stories={['S-CORE-1']} />
      <ReadOnlyNote role="admin" />
      <QueryState query={q}>
        {({ modules }) => {
          const columns: ColumnDef<ModuleState>[] = [
            { id: 'name', header: t('modules.col.module'), accessorFn: (m) => name(m.id), cell: ({ row }) => (
              <div className="grid max-w-md"><span className="font-medium">{name(row.original.id)}</span><span className="text-[13px] text-muted">{t(`modules.${row.original.id}.${row.original.id === 'sensor-active' && install === 'container' ? 'summaryContainer' : 'summary'}`, { ns: 'common' })}</span>{row.original.available ? null : <span className="text-[13px] text-warn">{t('modules.notHereWhy')}</span>}</div>
            ) },
            { id: 'depends', header: t('modules.col.needs'), enableSorting: false, accessorFn: (m) => m.depends.join(','), cell: ({ row }) => (row.original.depends.length ? <span className="text-[13px]">{row.original.depends.map(name).join(', ')}</span> : <span className="text-muted">–</span>) },
            { id: 'state', header: t('modules.col.state'), accessorFn: (m) => Number(m.enabled), cell: ({ row }) => {
              const m = row.original
              if (!m.available) return <Chip tone="off">{t('modules.notHere')}</Chip>
              return m.enabled ? <Chip tone="ok">{m.tier === 'core' ? t('modules.always') : t('modules.on')}</Chip> : <Chip tone="off">{t('modules.off')}</Chip>
            } },
            { id: 'since', header: t('modules.col.since'), accessorFn: (m) => m.enabled_at ?? '', cell: ({ row }) => fmtDate(row.original.enabled_at) },
            { id: 'switch', header: t('modules.col.switch'), enableSorting: false, accessorFn: () => '', cell: ({ row }) => {
              const m = row.original
              const locked = m.tier === 'core'
              const notHere = !m.available && !m.enabled // D-381: a module this install cannot run cannot be turned on; one left on can be turned off
              return <Switch checked={m.enabled} disabled={locked || notHere || gate.disabled || toggle.isPending} title={locked ? t('modules.coreLocked') : notHere ? t('modules.notHereWhy') : gate.title} aria-label={t(m.enabled ? 'modules.toggleOff' : 'modules.toggle', { name: name(m.id) })} onCheckedChange={(v) => onSwitch(modules, m, v)} />
            } },
          ]
          return <DataTable data={modules} columns={columns} caption={t('modules.caption')} pageSize={30} filterPlaceholder={t('modules.filter')} />
        }}
      </QueryState>

      <Dialog open={confirm?.kind === 'deps'} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent title={t('modules.deps.title')} description={confirm?.kind === 'deps' ? t('modules.deps.body', { name: name(confirm.mod) }) : undefined}>
          {confirm?.kind === 'deps' ? <ul className="list-disc pl-5 text-sm">{confirm.missing.map((id) => <li key={id}>{name(id)}</li>)}</ul> : null}
          <DialogFooter>
            <Button onClick={() => setConfirm(null)}>{t('common:cancel')}</Button>
            <Button variant="primary" disabled={toggle.isPending} onClick={() => confirm?.kind === 'deps' && void run(confirm.mod, true, true)}>{t('modules.deps.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirm?.kind === 'disable'} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent title={confirm?.kind === 'disable' ? t('modules.disable.title', { name: name(confirm.mod) }) : ''} description={t('modules.disable.keep')}>
          {confirm?.kind === 'disable' ? (
            confirm.affected.length ? (
              <div className="grid gap-2 text-sm">
                <p>{t('modules.disable.affected')}</p>
                <ul className="list-disc pl-5">{confirm.affected.map((id) => <li key={id}>{name(id)}</li>)}</ul>
              </div>
            ) : <p className="text-sm text-muted">{t('modules.disable.none')}</p>
          ) : null}
          {confirm?.kind === 'disable' && confirm.mod === 'notify' ? <EmailCodeWarning /> : null}
          <p className="text-[13px] text-muted">{t('modules.disable.reenable')}</p>
          <DialogFooter>
            <Button onClick={() => setConfirm(null)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={toggle.isPending} onClick={() => confirm?.kind === 'disable' && void run(confirm.mod, false)}>{t('modules.disable.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
