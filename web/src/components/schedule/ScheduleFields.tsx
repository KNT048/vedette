import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ChevronDown } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { displayTimeZone, fmtWeekdayDateTimeIn } from '@/lib/format'
import { TIMEZONES } from '@/features/core/util'
import { useSchedulePreview } from './api'
import { clockIn, DAYS, daysText, intervalProblem, intervalText, toSave, unitsFor, zoneOf, type Draft, type Unit } from './rule'
import { WindowFields } from './WindowFields'
import type { Freq, Schedule, WindowMode } from './types'

/** The organization's zone: the one a saved "org" rule is read in, else the one the app writes dates in. */
export const orgZoneOf = (s: Schedule) => (s.rule.tz === 'org' ? s.zone : displayTimeZone() ?? Intl.DateTimeFormat().resolvedOptions().timeZone)

/** "Sun 23 Nov 2026, 23:00", in the rule's zone; its name added when it is not the zone the app writes dates in. */
export function fmtInZone(iso: string, zone: string) {
  const s = fmtWeekdayDateTimeIn(iso, zone)
  return zone === (displayTimeZone() ?? Intl.DateTimeFormat().resolvedOptions().timeZone) ? s : `${s} (${zone})`
}

/** The field a 400 names (`error.field` of the box), with its message. */
export function fieldError(e: unknown): { field: string; message: string } | null {
  // the box names a field of the rule as "rule.<field>": the form's fields are the rule's own
  return e instanceof ApiError && e.status === 400 ? { field: String(e.details.field ?? '').replace(/^rule\./, ''), message: e.message } : null
}

const ADVANCED: ReadonlySet<string> = new Set(['tz', 'window', 'window_days', 'window_from', 'window_to', 'paused_until'])

/**
 * The fields of one schedule, for a dialog: on/off, how often (only what its owner allows, with the owner's reason), and behind one
 * click the time zone, the window and a pause. The next three start times come from the box as the fields change; a rule it refuses
 * shows its message at the field it names. `error` is the answer of a save (it wins until the person changes something).
 */
export function ScheduleFields({ schedule: s, draft: d, onChange, error, idPrefix, disabled, onOff = true }: {
  schedule: Schedule; draft: Draft; onChange: (d: Draft) => void; error?: unknown; idPrefix: string; disabled?: boolean
  /** false where the item has its own on/off (a feed): the fields show without a second switch. */
  onOff?: boolean
}) {
  const { t } = useTranslation('schedule')
  const l = s.limits
  const orgZone = orgZoneOf(s)
  const zone = zoneOf(d.tz, orgZone)
  const body = toSave(d, orgZone)
  const on = d.enabled || !onOff
  // an interval the owner does not allow is said here, in plain words, and nothing is asked of the box for it
  const local = on ? intervalProblem(d, l) : null
  // a window of chosen days with no day ticked never starts: said here, and nothing is asked of the box for it
  const noDay = on && d.window === 'custom' && d.windowDays.length === 0
  const preview = useSchedulePreview({ owner_key: s.owner_key, rule: body.rule, paused_until: body.paused_until ?? null }, on && !local && !noDay)
  const err = (local ? { field: 'every_minutes', message: intervalText(local, l, t) } : null) ?? (noDay ? { field: 'window_days', message: t('fields.windowNoDay') } : null)
    ?? fieldError(error) ?? (on ? fieldError(preview.error) : null)
  const at = (f: string) => (err && err.field === f ? err.message : undefined)
  const [more, setMore] = useState(() => d.tz !== 'org' || d.window === 'custom' || d.resumeOn !== '' || (!!err && ADVANCED.has(err.field)))
  const set = (p: Partial<Draft>) => onChange({ ...d, ...p })
  const id = (n: string) => `${idPrefix}-${n}`
  const units = unitsFor(l)
  const reason = l.reason || undefined
  const freqs = l.freqs
  const windows = l.windows
  const unlisted = err && !['freq', 'every_minutes', 'at_time', 'weekdays', 'month_day', 'once_at', ...ADVANCED].includes(err.field) ? err.message : undefined
  const atField = (optional = false) => (
    <Field label={optional ? t('fields.atOptional') : t('fields.at')} htmlFor={id('at')} error={at('at_time')} className="w-40">
      <Input id={id('at')} type="time" value={d.at} disabled={disabled} onChange={(e) => set({ at: e.target.value })} />
    </Field>
  )

  return (
    <div className="grid gap-4">
      {onOff ? (
        <div className="flex items-center gap-3">
          <Switch id={id('on')} checked={d.enabled} disabled={disabled} onCheckedChange={(v) => set({ enabled: v })} />
          <Label htmlFor={id('on')}>{t('fields.on')}</Label>
        </div>
      ) : null}
      {on ? (
        <>
          {freqs.length > 1 ? (
            <Field label={t('fields.repeat')} htmlFor={id('freq')} hint={reason} error={at('freq')} className="max-w-xs">
              <Select id={id('freq')} value={d.freq} disabled={disabled} onChange={(e) => set({ freq: e.target.value as Freq, at: d.at || (e.target.value === 'interval' ? '' : '02:00') })}>
                {freqs.map((f) => <option key={f} value={f}>{t(`freq.${f}`)}</option>)}
              </Select>
            </Field>
          ) : null}
          {d.freq === 'interval' ? (
            <div className="flex flex-wrap items-start gap-3">
              <Field label={t('fields.every')} htmlFor={id('every')} hint={freqs.length > 1 ? undefined : reason} error={at('every_minutes')} className="w-28">
                <Input id={id('every')} type="number" inputMode="numeric" min={1} value={d.every} disabled={disabled} onChange={(e) => set({ every: e.target.value })} />
              </Field>
              <Field label={t('fields.unit')} htmlFor={id('unit')} className="w-32">
                <Select id={id('unit')} value={d.unit} disabled={disabled || units.length < 2} onChange={(e) => set({ unit: e.target.value as Unit })}>
                  {units.map((u) => <option key={u} value={u}>{t(`unit.${u}`, { count: Number(d.every) || 0 })}</option>)}
                </Select>
              </Field>
              {d.unit === 'days' ? atField(true) : null}
            </div>
          ) : null}
          {d.freq === 'daily' ? atField() : null}
          {d.freq === 'weekly' ? (
            <div className="grid gap-3">
              <fieldset className="m-0 grid gap-2 border-0 p-0" aria-describedby={at('weekdays') ? id('weekdays-error') : undefined}>
                <legend className="mb-1 text-sm font-medium">{t('fields.weekdays')}</legend>
                <div className="flex flex-wrap gap-x-4 gap-y-2">
                  {DAYS.map((n) => (
                    <span key={n} className="inline-flex items-center gap-2 text-sm">
                      <Checkbox id={id(`wd-${n}`)} checked={d.weekdays.includes(n)} disabled={disabled}
                        onCheckedChange={(v) => set({ weekdays: v === true ? [...d.weekdays, n].sort() : d.weekdays.filter((x) => x !== n) })} />
                      <Label htmlFor={id(`wd-${n}`)} className="font-normal">{t(`days.long.${n}`)}</Label>
                    </span>
                  ))}
                </div>
                {at('weekdays') ? <p id={id('weekdays-error')} className="text-meta text-danger">{at('weekdays')}</p> : null}
              </fieldset>
              {atField()}
            </div>
          ) : null}
          {d.freq === 'monthly' ? (
            <div className="flex flex-wrap items-start gap-3">
              <Field label={t('fields.monthDay')} htmlFor={id('mday')} error={at('month_day')} className="w-40">
                <Select id={id('mday')} value={d.monthDay} disabled={disabled} onChange={(e) => set({ monthDay: Number(e.target.value) })}>
                  {Array.from({ length: 31 }, (_, i) => i + 1).map((n) => <option key={n} value={n}>{n}</option>)}
                  <option value={0}>{t('fields.lastDay')}</option>
                </Select>
              </Field>
              {atField()}
            </div>
          ) : null}
          {d.freq === 'once' ? (
            <Field label={t('fields.onceAt')} htmlFor={id('once')} error={at('once_at')} className="w-60">
              <Input id={id('once')} type="datetime-local" value={d.onceAt} disabled={disabled} onChange={(e) => set({ onceAt: e.target.value })} />
            </Field>
          ) : null}

          <div className="grid gap-3">
            <Button variant="ghost" size="sm" className="w-fit" aria-expanded={more} aria-controls={id('more')} onClick={() => setMore(!more)}>
              <ChevronDown className={more ? 'rotate-180' : ''} aria-hidden />{t('fields.more')}
            </Button>
            {more ? (
              <div id={id('more')} className="grid gap-4 border-l-2 border-rule pl-4">
                <Field label={t('fields.tz')} htmlFor={id('tz')} error={at('tz')} className="max-w-sm">
                  <Select id={id('tz')} value={d.tz} disabled={disabled} onChange={(e) => set({ tz: e.target.value })}>
                    <option value="org">{t('fields.tzOrg', { zone: orgZone })}</option>
                    {TIMEZONES.map((z) => <option key={z} value={z}>{z}</option>)}
                  </Select>
                </Field>
                {windows.length > 1 || d.window !== windows[0] ? (
                  <Field label={t('fields.window')} htmlFor={id('window')} error={at('window')} className="max-w-sm">
                    <Select id={id('window')} value={d.window} disabled={disabled} onChange={(e) => {
                      const w = e.target.value as WindowMode
                      // chosen days start as every day (then the person narrows them), never as none
                      set(w === 'custom' && d.windowDays.length === 0 ? { window: w, windowDays: [...DAYS] } : { window: w })
                    }}>
                      {windows.map((w) => <option key={w} value={w}>{t(`windowMode.${w}`)}</option>)}
                    </Select>
                  </Field>
                ) : null}
                {d.window === 'global' ? <Link to="/settings/scanning?tab=safety#window" className="w-fit text-meta text-accent underline-offset-4 hover:underline">{t('fields.scanWindowLink')}</Link> : null}
                {d.window === 'custom' ? (
                  <div className="grid gap-1.5">
                    <WindowFields idPrefix={id('win')} disabled={disabled} value={{ days: d.windowDays, from: d.windowFrom, to: d.windowTo }}
                      onChange={(w) => set({ windowDays: w.days, windowFrom: w.from, windowTo: w.to })} />
                    {at('window_days') ?? at('window_from') ?? at('window_to') ? <p className="text-meta text-danger">{at('window_days') ?? at('window_from') ?? at('window_to')}</p> : null}
                  </div>
                ) : null}
                <Field label={t('fields.resumeOn')} htmlFor={id('resume')} hint={t('fields.resumeOnHint')} error={at('paused_until')} className="w-48">
                  <Input id={id('resume')} type="date" value={d.resumeOn} disabled={disabled} onChange={(e) => set({ resumeOn: e.target.value })} />
                </Field>
              </div>
            ) : null}
          </div>

          {unlisted ? <p role="alert" className="text-meta text-danger">{unlisted}</p> : null}
          {!err && preview.data ? (
            <div className="grid gap-1" aria-live="polite">
              {/* the zone the times are in is named here, not only behind "Time zone, window, pause" */}
              <p className="text-sm font-medium">{t('preview.titleIn', { zone: preview.data.zone || zone })}</p>
              {preview.data.upcoming.length ? (
                <ol className="grid gap-0.5 text-sm">{preview.data.upcoming.map((u) => {
                  // a start the window moved off the asked time says so and why
                  const z = preview.data.zone || zone
                  const moved = body.rule.at_time && body.rule.window !== 'none' && clockIn(u, z) !== body.rule.at_time
                  const win = body.rule.window === 'global' ? t('preview.scanWindow') : t('preview.customWindow', { days: daysText(body.rule.window_days ?? [], t), from: body.rule.window_from, to: body.rule.window_to })
                  return <li key={u}>{fmtWeekdayDateTimeIn(u, z)}{moved ? <span className="text-meta text-muted">{` · ${t('preview.moved', { at: body.rule.at_time, window: win })}`}</span> : null}</li>
                })}</ol>
              ) : <p className="text-sm text-muted">{t('preview.none')}</p>}
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  )
}
