// The editor's pure helpers: a wall-clock time in a zone and back, the units an owner allows, the rule the form sends (fields its
// frequency does not use are null) and the one-line description of a rule.
import { describe, expect, it } from 'vitest'
import i18n from '@/lib/i18n'
import { describeRule, isoToZoned, split, toDraft, toRule, unitsFor, zonedToIso } from './rule'
import type { Schedule, ScheduleRule } from './types'

const t = i18n.getFixedT('en', 'schedule')
const rule = (r: Partial<ScheduleRule>): ScheduleRule => ({ freq: 'daily', every_minutes: null, at_time: null, weekdays: null, month_day: null, once_at: null, window: 'none', window_days: null, window_from: null, window_to: null, ...r })
const limits = { freqs: ['interval', 'daily', 'weekly', 'monthly', 'once'] as ScheduleRule['freq'][], min_every_minutes: 1, max_every_minutes: 527040, windows: ['global', 'none', 'custom'] as ScheduleRule['window'][], reason: '' }
const schedule = (r: Partial<ScheduleRule>): Schedule => ({
  owner_key: 'scan.vuln', module: 'scan', saved: true, enabled: true, paused_until: null, rule: rule(r), zone: 'Europe/Berlin', next_due_at: null, upcoming: [],
  waiting_for: null, last_due_at: null, last_run_id: null, last_skip_reason: null, last_skip_at: null, updated_by: null, updated_at: null, limits, edit_role: 'admin',
})

describe('schedule rule helpers', () => {
  it('reads a wall-clock time in a zone, across summer time', () => {
    expect(zonedToIso('2026-07-01T02:30', 'Europe/Berlin')).toBe('2026-07-01T00:30:00.000Z')
    expect(zonedToIso('2026-12-01T02:30', 'Europe/Berlin')).toBe('2026-12-01T01:30:00.000Z')
    expect(zonedToIso('2026-12-01T02:30', 'Asia/Ho_Chi_Minh')).toBe('2026-11-30T19:30:00.000Z')
    expect(isoToZoned('2026-11-30T19:30:00.000Z', 'Asia/Ho_Chi_Minh')).toBe('2026-12-01T02:30')
    expect(zonedToIso('tomorrow', 'UTC')).toBeNull()
  })

  it('offers only the units the owner limits leave', () => {
    expect(unitsFor(limits)).toEqual(['minutes', 'hours', 'days'])
    expect(unitsFor({ ...limits, min_every_minutes: 60 })).toEqual(['hours', 'days'])
    expect(unitsFor({ ...limits, min_every_minutes: 5, max_every_minutes: 1440 })).toEqual(['minutes', 'hours', 'days'])
    expect(unitsFor({ ...limits, max_every_minutes: 30 })).toEqual(['minutes'])
    expect(split(4320, ['minutes', 'hours', 'days'])).toEqual({ every: 3, unit: 'days' })
    expect(split(90, ['minutes', 'hours', 'days'])).toEqual({ every: 90, unit: 'minutes' })
    expect(split(120, ['hours', 'days'])).toEqual({ every: 2, unit: 'hours' })
  })

  it('sends only the fields its frequency uses, and no zone: every schedule follows the box\'s', () => {
    const d = toDraft(schedule({ freq: 'weekly', at_time: '23:00', weekdays: [7], window: 'global' }), 'Europe/Berlin')
    expect(toRule({ ...d, freq: 'interval', every: '3', unit: 'days', at: '02:30', window: 'custom', windowDays: [5, 1], windowFrom: '00:00', windowTo: '00:00' }, 'Europe/Berlin'))
      .toEqual(rule({ freq: 'interval', every_minutes: 4320, at_time: '02:30', window: 'custom', window_days: [1, 5], window_from: '00:00', window_to: '00:00' }))
    expect(toRule({ ...d, freq: 'interval', every: '6', unit: 'hours', at: '02:30' }, 'Europe/Berlin')).toEqual(rule({ freq: 'interval', every_minutes: 360, window: 'global' }))
    expect(toRule({ ...d, freq: 'monthly', monthDay: 0 }, 'Europe/Berlin')).toEqual(rule({ freq: 'monthly', month_day: 0, at_time: '23:00', window: 'global' }))
    expect(toRule({ ...d, freq: 'once', onceAt: '2026-12-24T18:00' }, 'Europe/Berlin')).toEqual(rule({ freq: 'once', once_at: '2026-12-24T17:00:00.000Z', window: 'global' }))
  })

  it('says a rule in one line', () => {
    const when = (iso: string) => iso.slice(0, 10)
    expect(describeRule(rule({ freq: 'interval', every_minutes: 360 }), t, when)).toBe('Every 6 hours')
    expect(describeRule(rule({ freq: 'interval', every_minutes: 4320, at_time: '02:30', window: 'custom', window_days: [1, 2, 3, 4, 5], window_from: '00:00', window_to: '00:00' }), t, when))
      .toBe('Every 3 days at 02:30, only Mon–Fri, all day')
    expect(describeRule(rule({ freq: 'weekly', at_time: '08:00', weekdays: [1, 4], window: 'global' }), t, when)).toBe('Weekly on Mon, Thu at 08:00, in the scan window')
    // a zone an earlier version stored is not said: the box reads every rule in its own zone
    expect(describeRule(rule({ freq: 'monthly', month_day: 0, at_time: '08:00', tz: 'Europe/Berlin' }), t, when)).toBe('Monthly on the last day at 08:00')
    expect(describeRule(rule({ freq: 'once', once_at: '2026-12-24T17:00:00Z' }), t, when)).toBe('Once, 2026-12-24')
  })
})
