import { afterEach, describe, expect, it } from 'vitest'
import { dayOf, fmtDate, fmtDateTime, fmtDayMonth, fmtEnd, fmtMonthYear, fmtTime, fmtWhen, isNever, rawProductLine, setDisplayTimeZone } from './format'

describe('isNever', () => {
  it('treats empty and Go zero time as never', () => {
    expect(isNever(null)).toBe(true)
    expect(isNever('0001-01-01T00:00:00Z')).toBe(true)
    expect(isNever('2026-11-12T08:00:00Z')).toBe(false)
  })
})

describe('one date format', () => {
  it('writes the month as a word, never 12/11/2026', () => {
    expect(fmtDate('2026-11-12')).toBe('12 Nov 2026')
    expect(fmtDateTime(new Date(2026, 10, 12, 20, 51).toISOString())).toBe('12 Nov 2026, 20:51')
  })
})

describe('rawProductLine', () => {
  it('hides the vendor/product line when it only repeats the display name', () => {
    expect(rawProductLine('OpenBSD OpenSSH', 'OpenBSD', 'OpenSSH')).toBeNull()
    expect(rawProductLine('openbsd openssh ', 'OpenBSD', 'OpenSSH')).toBeNull()
    expect(rawProductLine('QNAP NAS (QTS)', 'QNAP', 'QTS')).toBe('QNAP QTS')
  })
})

describe("the organization's time zone", () => {
  afterEach(() => setDisplayTimeZone(null))

  it('writes a moment in it, on every page alike', () => {
    setDisplayTimeZone('Asia/Ho_Chi_Minh')
    // An agent's list at 21:11 UTC on 14 Nov is 04:11 on 15 Nov in the organization's zone (UTC+7): the box sends that day too.
    expect(fmtDateTime('2026-11-14T21:11:00Z')).toBe('15 Nov 2026, 04:11')
    expect(fmtDate('2026-11-14T21:11:00Z')).toBe('15 Nov 2026')
    expect(fmtTime('2026-11-14T21:11:09Z', true)).toBe('04:11:09')
    expect(dayOf('2026-11-14T21:11:00Z')).toBe('2026-11-15')
    expect(fmtDayMonth('2026-11-14T21:11:00Z')).toBe('15 Nov')
    setDisplayTimeZone('America/New_York')
    expect(fmtDateTime('2026-11-14T21:11:00Z')).toBe('14 Nov 2026, 16:11')
  })

  it('never moves a calendar day', () => {
    for (const z of ['Asia/Ho_Chi_Minh', 'America/Los_Angeles', 'Pacific/Kiritimati']) {
      setDisplayTimeZone(z)
      expect(fmtDate('2026-11-14')).toBe('14 Nov 2026')
      expect(fmtMonthYear('2027-06-30')).toBe('June 2027')
      expect(dayOf('2026-11-14')).toBe('2026-11-14')
    }
  })

  it("says the hour alone on the organization's today, and the end of a span on its day", () => {
    setDisplayTimeZone('Asia/Ho_Chi_Minh')
    const now = new Date('2026-11-17T05:00:00Z') // 12:00 there
    expect(fmtWhen('2026-11-16T17:30:00Z', now)).toBe('00:30') // today there, yesterday in UTC
    expect(fmtWhen('2026-11-16T16:30:00Z', now)).toBe('16 Nov 2026, 23:30')
    expect(fmtEnd('2026-11-17T14:01:00Z', '2026-11-17T15:43:00Z')).toBe('22:43')
    expect(fmtEnd('2026-11-17T14:01:00Z', '2026-11-17T17:12:00Z')).toBe('18 Nov 2026, 00:12')
  })

  it("keeps the browser's zone for an unknown name", () => {
    setDisplayTimeZone('Mars/Olympus_Mons')
    expect(fmtDate('2026-11-14')).toBe('14 Nov 2026')
  })
})
