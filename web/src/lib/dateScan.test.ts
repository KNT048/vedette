import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

// The guard of the whole class: every date or time the GUI shows is written by lib/format, in the organization's time zone
// (Settings › General), so a page never shows another day than the box's own sentences for the same moment. Anything else
// that turns a moment into text reads the browser's zone (or UTC) instead.
const src = join(import.meta.dirname, '..')
const own = new Set([
  'lib/format.ts',
  'features/exposure/data.ts', // the GUI mock's scan data (mocks.ts reads it), never shown by the real box
  'features/exposure/contract.ts', // the example days of the API description
  'features/findings/accept.ts', // calendar arithmetic of the "Accept risk until" date input, on the person's own calendar
  'features/core/logExport.ts', // the GUI mock of the log export, naming the file by the UTC day as the box does
])
// Lines that cut a UTC day on purpose: a calendar day built from UTC numbers, or a cut-off compared with UTC calendar days.
const allowed = [/Date\.UTC\(/, /yearAgo|365 \* 86_400_000/]
const patterns: [string, RegExp][] = [
  ['Intl.DateTimeFormat', /Intl\.DateTimeFormat\(/],
  ['toLocale…String', /\.toLocale(Date|Time)?String\((?!'en-US'\))/],
  ['clock or day parts of a Date', /\.get(Hours|Minutes|Date)\(\)/],
  ['UTC day of a moment', /toISOString\(\)\.slice\(0, ?10\)/],
]

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) return n === 'mocks' || n === 'test' ? [] : files(p)
    return /\.tsx?$/.test(n) && !/\.test\.tsx?$/.test(n) && !/mocks?\.ts$|Mock\.ts$/.test(n) ? [p] : []
  })
}

describe('dates on screen', () => {
  it('are written by lib/format only', () => {
    const found: Record<string, string[]> = {}
    for (const f of files(src)) {
      const rel = relative(src, f)
      if (own.has(rel)) continue
      readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
        for (const [cause, re] of patterns) {
          // Listing the zone names (Settings › General) and checking one is valid are not dates on screen.
          if (re.test(line) && !/supportedValuesOf|resolvedOptions|timeZone: z\b/.test(line) && !allowed.some((x) => x.test(line))) (found[cause] ??= []).push(`${rel}:${i + 1}`)
        }
      })
    }
    expect(found).toEqual({})
  })
})
