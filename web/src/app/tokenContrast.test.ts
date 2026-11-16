// docs/UI.md §1: every token pair the components use reaches WCAG AA (text 4.5:1, edges, indicators and focus 3:1) in the light
// theme, the dark theme and the dark-by-system fallback. jsdom computes no colours, so this reads the tokens of index.css.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const css = readFileSync(resolve(process.cwd(), 'src/index.css'), 'utf8') // vitest runs from web/

function tokens(block: string): Record<string, string> {
  return Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})/g)].map((m) => [m[1]!, m[2]!]))
}
const THEMES = {
  light: tokens(/:root\s*\{([^}]*)\}/.exec(css)![1]!),
  dark: tokens(/\[data-theme="dark"\]\s*\{([^}]*)\}/.exec(css)![1]!),
  'dark by system': tokens(/:root:not\(\[data-theme="light"\]\)\s*\{([^}]*)\}/.exec(css)![1]!),
}

function lum(hex: string) {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!
}
const ratio = (a: string, b: string) => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x)
  return (hi! + 0.05) / (lo! + 0.05)
}

// [foreground, background, minimum]; '#fff' is the literal white of solid chips in the light theme.
const TEXT = 4.5
const UI = 3
const PAIRS: [string, string, number][] = [
  ...['paper', 'surface', 'sunken'].flatMap((bg) => [['ink', bg, TEXT], ['muted', bg, TEXT]] as [string, string, number][]),
  ['accent', 'surface', TEXT], ['accent', 'paper', TEXT], ['accent-ink', 'accent', TEXT],
  ['ink', 'accent-soft', TEXT], ['accent', 'accent-soft', TEXT],
  ...['danger', 'warn', 'ok', 'off', 'accent'].flatMap((t) => [['muted', `${t}-soft`, TEXT], [t, `${t}-soft`, TEXT], [t, 'surface', TEXT]] as [string, string, number][]),
  ['paper', 'danger', TEXT],
  ['control', 'surface', UI], ['control', 'paper', UI], ['control', 'sunken', UI],
  ['surface', 'accent', UI], ['surface', 'control', UI], // switch thumb on its two tracks
  ['focus', 'paper', UI], ['focus', 'surface', UI], ['focus', 'accent-soft', UI],
]

describe('token contrast (docs/UI.md §1)', () => {
  for (const [theme, t] of Object.entries(THEMES)) {
    it(`${theme}: every listed pair reaches its minimum`, () => {
      const low = PAIRS.filter(([fg, bg, min]) => {
        expect(t[fg], `--${fg} in ${theme}`).toBeDefined()
        expect(t[bg], `--${bg} in ${theme}`).toBeDefined()
        return ratio(t[fg]!, t[bg]!) < min
      }).map(([fg, bg, min]) => `${fg} on ${bg}: ${ratio(t[fg]!, t[bg]!).toFixed(2)} < ${min}`)
      expect(low).toEqual([])
    })
  }
  // The dashed chip (docs/UI.md §7): warn text on warn-soft at 60 % over surface.
  const mix = (fg: string, bg: string, a: number) => '#' + [1, 3, 5].map((i) => Math.round(parseInt(fg.slice(i, i + 2), 16) * a + parseInt(bg.slice(i, i + 2), 16) * (1 - a)).toString(16).padStart(2, '0')).join('')
  for (const [theme, t] of Object.entries(THEMES)) {
    it(`${theme}: the dashed chip, warn on warn-soft/60 over surface`, () => {
      expect(ratio(t.warn!, mix(t['warn-soft']!, t.surface!, 0.6))).toBeGreaterThanOrEqual(TEXT)
    })
  }
  it('light: white on the solid danger chip', () => {
    expect(ratio('#ffffff', THEMES.light.danger!)).toBeGreaterThanOrEqual(TEXT)
  })
})
