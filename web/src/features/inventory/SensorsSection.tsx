import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ModuleOff, QueryState, RequireModule } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtRelative } from '@/lib/format'
import { useSensorActions, useSensors } from './api'
import { errMsg } from './kinds'
import type { Sensor, SensorStatus } from './types'

const TONE: Record<SensorStatus, Tone> = { online: 'ok', offline: 'warn' }

function ConfigDialog({ sensor, onClose }: { sensor: Sensor | null; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const { update } = useSensorActions()
  const [iface, setIface] = useState(sensor?.interface ?? '')
  const [span, setSpan] = useState(sensor?.span ?? false)
  const [error, setError] = useState<string | null>(null)
  if (!sensor) return null
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('sensors.configTitle', { name: sensor.name })} description={t('sensors.configBody')}>
        <form className="grid gap-4" noValidate onSubmit={(e) => {
          e.preventDefault(); setError(null)
          update.mutate({ id: sensor.id, interface: iface, span }, { onSuccess: () => { toast.success(t('sensors.configSaved')); onClose() }, onError: (er) => setError(errMsg(er)) })
        }}>
          <Field label={t('sensors.interface')} htmlFor="sensor-iface" hint={t('sensors.interfaceHint')}>
            <Select id="sensor-iface" value={iface} onChange={(e) => setIface(e.target.value)} aria-describedby="sensor-iface-hint">
              {sensor.interfaces.map((i) => <option key={i} value={i}>{i}</option>)}
            </Select>
          </Field>
          <div className="grid gap-1.5">
            <div className="flex items-center gap-3">
              <Switch id="sensor-span" checked={span} onCheckedChange={setSpan} />
              <Label htmlFor="sensor-span">{t('sensors.span')}</Label>
            </div>
            <p className="max-w-lg text-[13px] text-muted">{t('sensors.spanHint')}</p>
          </div>
          {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={update.isPending}>{t('common:save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Cảm biến của chính hộp này: chọn cổng mạng nghe và chế độ SPAN/TAP (chỉ đọc metadata, không lưu nội dung gói tin, D-43). Chỉ nghe, không chặn traffic. Nhiều site chưa hỗ trợ. */
export function SensorsSection() {
  const { t } = useTranslation('inventory')
  const q = useSensors()
  const [config, setConfig] = useState<Sensor | null>(null)
  const columns: ColumnDef<Sensor>[] = [
    { id: 'name', header: t('sensors.col.name'), accessorFn: (s) => s.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: 'iface', header: t('sensors.col.interface'), accessorFn: (s) => s.interface ?? '', cell: ({ row }) => row.original.interface ? <span>{row.original.interface}{row.original.span ? <span className="ml-2 text-[12px] text-muted">{t('sensors.spanOn')}</span> : null}</span> : <span className="text-muted">–</span> },
    { id: 'status', header: t('sensors.col.status'), accessorFn: (s) => s.status, cell: ({ row }) => (
      <div className="grid gap-0.5">
        <Chip tone={TONE[row.original.status]}>{t(`sensors.status.${row.original.status}`)}</Chip>
        {row.original.last_seen ? <span className="text-[12px] text-muted">{t('sensors.lastSeen', { when: fmtRelative(row.original.last_seen) })}</span> : null}
      </div>
    ) },
    { id: 'seen', header: t('sensors.col.devices'), accessorFn: (s) => s.devices_seen },
    { id: 'version', header: t('sensors.col.version'), accessorFn: (s) => s.version ?? '', cell: ({ getValue }) => (getValue() as string) || <span className="text-muted">–</span> },
    { id: 'actions', header: () => <span className="sr-only">{t('sensors.col.actions')}</span>, enableSorting: false, cell: ({ row }) => (
      <Button size="sm" onClick={() => setConfig(row.original)} aria-label={t('sensors.configure', { name: row.original.name })}>{t('sensors.config')}</Button>
    ) },
  ]
  return (
    <Section id="sensors" title={t('sensors.title')} description={t('sensors.description')} stories={['S-INV-1']}>
      <RequireModule module="sensor-passive" fallback={<ModuleOff module="sensor-passive">{t('sensors.off')}</ModuleOff>}>
        <QueryState query={q}>
          {(d) => <DataTable caption={t('sensors.caption')} data={d.sensors} columns={columns} />}
        </QueryState>
      </RequireModule>
      {config ? <ConfigDialog key={config.id} sensor={config} onClose={() => setConfig(null)} /> : null}
    </Section>
  )
}
