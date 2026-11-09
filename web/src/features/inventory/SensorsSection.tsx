import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ModuleOff, QueryState, RequireModule } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { fmtRelative } from '@/lib/format'
import { useSensors } from './api'
import type { Sensor, SensorStatus } from './types'

const TONE: Record<SensorStatus, Tone> = { online: 'ok', offline: 'warn' }
const VERDICT_TONE: Record<Sensor['span_status']['verdict'], Tone> = { ok: 'ok', off: 'off', own_only: 'warn', no_traffic: 'warn', no_link: 'warn' }

/** SPAN is set in Settings → Box network (D-56). This dialog only shows what the sensor hears now and links there. */
function StatusDialog({ sensor, onClose }: { sensor: Sensor | null; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  if (!sensor) return null
  const st = sensor.span_status
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('sensors.configTitle', { name: sensor.name })} description={t('sensors.configBody')}>
        <div className="grid gap-4">
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <div><dt className="text-[13px] text-muted">{t('sensors.interface')}</dt><dd className="font-medium">{sensor.interface ?? '–'}{sensor.span ? <span className="ml-2 text-[12px] font-normal text-muted">{t('sensors.spanOn')}</span> : null}</dd></div>
            <div>
              <dt className="text-[13px] text-muted">{t('sensors.spanStatus')}</dt>
              <dd className="grid gap-1"><Chip tone={VERDICT_TONE[st.verdict]}>{t(`sensors.verdict.${st.verdict}`)}</Chip>{st.verdict === 'ok' || st.verdict === 'own_only' ? <span className="text-[12px] text-muted">{t('sensors.rate', { pps: st.packets_per_s, macs: st.other_macs })}</span> : null}</dd>
            </div>
          </dl>
          <p className="max-w-lg text-[13px] text-muted">{t('sensors.spanHint')}</p>
          <Link to="/settings/network" className="text-sm font-medium text-accent underline-offset-4 hover:underline" onClick={onClose}>{t('sensors.spanLink')}</Link>
          <DialogFooter><DialogClose asChild><Button>{t('common:close')}</Button></DialogClose></DialogFooter>
        </div>
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
    <Section id="sensors" title={t('sensors.title')} description={t('sensors.description')} stories={['S-INV-1', 'S-CORE-8']}>
      <RequireModule module="sensor-passive" fallback={<ModuleOff module="sensor-passive">{t('sensors.off')}</ModuleOff>}>
        <QueryState query={q}>
          {(d) => <DataTable caption={t('sensors.caption')} data={d.sensors} columns={columns} />}
        </QueryState>
      </RequireModule>
      {config ? <StatusDialog key={config.id} sensor={config} onClose={() => setConfig(null)} /> : null}
    </Section>
  )
}
