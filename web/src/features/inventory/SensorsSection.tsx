import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ModuleOff, QueryState, RequireModule } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Label, Select } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { fmtRelative } from '@/lib/format'
import { useInstallKind } from '@/lib/modules'
import { useSensorCard, useSensors } from './api'
import { errMsg } from './kinds'
import type { Sensor, SensorStatus } from './types'

const TONE: Record<SensorStatus, Tone> = { online: 'ok', offline: 'warn', never_connected: 'off' }
const VERDICT_TONE: Record<Sensor['span_status']['verdict'], Tone> = { ok: 'ok', off: 'off', own_only: 'warn', no_traffic: 'warn', no_link: 'warn' }

/** What the sensor hears now: the card it listens on and the health of the mirrored traffic. */
function Hearing({ sensor }: { sensor: Sensor }) {
  const { t } = useTranslation('inventory')
  const st = sensor.span_status
  return (
    <dl className="grid gap-3 text-sm sm:grid-cols-2">
      {sensor.capture_error ? <div className="sm:col-span-2"><dt className="text-[13px] text-muted">{t('sensors.capture.label')}</dt><dd className="text-warn">{t('sensors.capture.notCapturing')}: {t(`sensors.capture.${sensor.capture_error}`)}</dd></div> : null}
      <div><dt className="text-[13px] text-muted">{t('sensors.interface')}</dt><dd className="font-medium">{sensor.interface ?? '–'}{sensor.span ? <span className="ml-2 text-[12px] font-normal text-muted">{t('sensors.spanOn')}</span> : null}</dd></div>
      <div>
        <dt className="text-[13px] text-muted">{t('sensors.spanStatus')}</dt>
        <dd className="grid gap-1"><Chip tone={VERDICT_TONE[st.verdict]}>{t(`sensors.verdict.${st.verdict}`)}</Chip>{st.verdict === 'ok' || st.verdict === 'own_only' ? <span className="text-[12px] text-muted">{t('sensors.rate', { pps: st.packets_per_s, macs: st.other_macs })}</span> : null}</dd>
      </div>
    </dl>
  )
}

/** Appliance: SPAN is set in Settings → Box network (D-56). This dialog only shows what the sensor hears now and links there. */
function StatusDialog({ sensor, onClose }: { sensor: Sensor; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('sensors.configTitle', { name: sensor.name })} description={t('sensors.configBody')}>
        <div className="grid gap-4">
          <Hearing sensor={sensor} />
          <p className="max-w-lg text-[13px] text-muted">{t('sensors.spanHint')}</p>
          <Link to="/settings/network" className="text-sm font-medium text-accent underline-offset-4 hover:underline" onClick={onClose}>{t('sensors.spanLink')}</Link>
          <DialogFooter><DialogClose asChild><Button>{t('common:close')}</Button></DialogClose></DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  )
}

/** Container-only install (S-CORE-8 G6, D-387, D-393): no host to ask, so the card is chosen among the cards the sensor reported
 *  in its heartbeat, with or without an address, and SPAN is a separate tick; the customer prepares the card on the machine.
 *  "Automatic" is the default card (D-380); `chosen` tells a stored choice from it. No card yet: say how to start the sensor, no Save. */
function CardDialog({ sensor, onClose }: { sensor: Sensor; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const save = useSensorCard(sensor.id)
  const current = sensor.chosen ? (sensor.interface ?? '') : ''
  const [card, setCard] = useState(current)
  const [span, setSpan] = useState(sensor.chosen && sensor.span)
  const [error, setError] = useState<string | null>(null)
  // The saved card may be missing from the last heartbeat (unplugged, renamed): keep it as an option so it can be changed.
  const cards = current && !sensor.interfaces.includes(current) ? [current, ...sensor.interfaces] : sensor.interfaces
  // What "Automatic" gives now: known only while nothing is chosen (then `interface` is the default card, D-380).
  const autoLabel = sensor.chosen ? t('sensors.card.autoChosen') : sensor.interface ? t('sensors.card.auto', { name: sensor.interface }) : t('sensors.card.autoNone')
  const unchanged = card === current && (card !== '' && span) === (sensor.chosen && sensor.span)
  // A 400 bad_interface is about the choice: it goes next to the SPAN tick when SPAN was asked for (a SPAN card has no address), else
  // next to the card. Anything else (module off, the box busy, no network) is not about a field and stays under the form.
  const [errorAt, setErrorAt] = useState<'card' | 'span' | 'form'>('form')
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('sensors.configTitle', { name: sensor.name })} description={t('sensors.card.body')}>
        <div className="grid gap-4">
          <Hearing sensor={sensor} />
          {cards.length === 0 ? (
            <>
              <p role="status" className="rounded-md border border-rule bg-surface px-3 py-2 text-sm">{t('sensors.card.none')}</p>
              <DialogFooter><DialogClose asChild><Button>{t('common:close')}</Button></DialogClose></DialogFooter>
            </>
          ) : (
            <form className="grid gap-4" noValidate onSubmit={(e) => {
              e.preventDefault(); setError(null)
              const asked = { interface: card || null, span: card !== '' && span }
              save.mutate(asked, { onSuccess: () => { toast.success(t('sensors.card.saved')); onClose() }, onError: (er) => { setErrorAt(er instanceof ApiError && er.code === 'bad_interface' ? (asked.span ? 'span' : 'card') : 'form'); setError(errMsg(er)) } })
            }}>
              {!sensor.interface ? <p role="status" className="rounded-md border border-rule bg-surface px-3 py-2 text-sm">{t('sensors.card.notListening')}</p> : null}
              <div className="grid gap-1">
                <Field label={t('sensors.card.label')} htmlFor="sensor-card" hint={t('sensors.card.hint')} className="max-w-sm">
                  <Select id="sensor-card" value={card} onChange={(e) => { setCard(e.target.value); setSpan(false); setError(null) }}
                    aria-invalid={error && errorAt === 'card' ? true : undefined} aria-describedby={error && errorAt === 'card' ? 'sensor-card-error sensor-card-hint' : 'sensor-card-hint'}>
                    <option value="">{autoLabel}</option>
                    {cards.map((n) => <option key={n} value={n}>{sensor.interfaces.includes(n) ? n : t('sensors.card.notReported', { name: n })}</option>)}
                  </Select>
                </Field>
                {error && errorAt === 'card' ? <p role="alert" id="sensor-card-error" className="max-w-lg text-[13px] text-danger [overflow-wrap:anywhere]">{error}</p> : null}
              </div>
              <div className="grid gap-1">
                <div className="flex items-center gap-2">
                  <Checkbox id="sensor-span" checked={card !== '' && span} disabled={card === ''} onCheckedChange={(v) => { setSpan(v === true); setError(null) }}
                    aria-invalid={error && errorAt === 'span' ? true : undefined} aria-describedby={error && errorAt === 'span' ? 'sensor-span-error sensor-span-hint' : 'sensor-span-hint'} />
                  <Label htmlFor="sensor-span" className="font-normal">{t('sensors.card.span')}</Label>
                </div>
                {error && errorAt === 'span' ? <p role="alert" id="sensor-span-error" className="max-w-lg text-[13px] text-danger [overflow-wrap:anywhere]">{error}</p> : null}
                {/* "Automatic" is whatever card the sensor takes by itself: SPAN is a property of one named card, so the tick waits for one (D-393). */}
                <p id="sensor-span-hint" className="max-w-lg text-[13px] text-muted">{t(card === '' ? 'sensors.card.spanNeedsCard' : 'sensors.card.spanHint')}</p>
              </div>
              <p className="max-w-lg text-[13px] text-muted">{t('sensors.spanHint')}</p>
              {error && errorAt === 'form' ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
              <DialogFooter>
                <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
                <Button type="submit" variant="primary" disabled={unchanged || save.isPending}>{t('common:save')}</Button>
              </DialogFooter>
            </form>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}

/** Cảm biến của chính hộp này: chọn cổng mạng nghe và chế độ SPAN/TAP (chỉ đọc metadata, không lưu nội dung gói tin, D-43). Chỉ nghe, không chặn traffic. Nhiều site chưa hỗ trợ. */
export function SensorsSection() {
  const { t } = useTranslation('inventory')
  const q = useSensors()
  const install = useInstallKind()
  const [configId, setConfigId] = useState<string | null>(null)
  const config = q.data?.sensors.find((s) => s.id === configId) // live: a heartbeat that arrives while the dialog is open shows in it
  const columns: ColumnDef<Sensor>[] = [
    { id: 'name', header: t('sensors.col.name'), accessorFn: (s) => s.name, cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { id: 'iface', header: t('sensors.col.interface'), accessorFn: (s) => s.interface ?? '', cell: ({ row }) => row.original.interface ? <span>{row.original.interface}{row.original.span ? <span className="ml-2 text-[12px] text-muted">{t('sensors.spanOn')}</span> : null}</span> : <span className="text-muted">–</span> },
    { id: 'status', header: t('sensors.col.status'), accessorFn: (s) => s.status, cell: ({ row }) => (
      <div className="grid gap-0.5">
        {row.original.capture_error
          ? <><Chip tone="warn">{t('sensors.capture.notCapturing')}</Chip><span className="max-w-xs text-[12px] text-warn">{t(`sensors.capture.${row.original.capture_error}`)}</span></>
          : <Chip tone={TONE[row.original.status]}>{t(`sensors.status.${row.original.status}`)}</Chip>}
        {row.original.last_seen ? <span className="text-[12px] text-muted">{t('sensors.lastSeen', { when: fmtRelative(row.original.last_seen) })}</span> : null}
        {row.original.status === 'never_connected' && install === 'container' ? <span className="text-[12px] text-muted">{t('sensors.startHint')}</span> : null}
      </div>
    ) },
    { id: 'seen', header: t('sensors.col.devices'), accessorFn: (s) => s.devices_seen },
    { id: 'version', header: t('sensors.col.version'), accessorFn: (s) => s.version ?? '', cell: ({ getValue }) => (getValue() as string) || <span className="text-muted">–</span> },
    { id: 'actions', header: () => <span className="sr-only">{t('sensors.col.actions')}</span>, enableSorting: false, cell: ({ row }) => (
      <Button size="sm" disabled={!install} onClick={() => setConfigId(row.original.id)} aria-label={t('sensors.configure', { name: row.original.name })}>{t('sensors.config')}</Button>
    ) },
  ]
  return (
    <Section id="sensors" title={t('sensors.title')} description={install ? t(install === 'container' ? 'sensors.descriptionContainer' : 'sensors.description') : undefined} stories={['S-INV-1', 'S-CORE-8']}>
      <RequireModule module="sensor-passive" fallback={<ModuleOff module="sensor-passive">{t('sensors.off')}</ModuleOff>}>
        <QueryState query={q}>
          {(d) => <DataTable caption={t('sensors.caption')} data={d.sensors} columns={columns} />}
        </QueryState>
      </RequireModule>
      {config ? (install === 'container'
        // Keyed on the stored choice: a change saved elsewhere while the dialog is open starts the form again from it.
        ? <CardDialog key={`${config.id}:${config.chosen ? config.interface : ''}:${config.span}`} sensor={config} onClose={() => setConfigId(null)} />
        : <StatusDialog key={config.id} sensor={config} onClose={() => setConfigId(null)} />) : null}
    </Section>
  )
}
