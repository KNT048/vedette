// The toast (sonner, App.tsx) paints its title in --ink and its description in --muted on --surface. jsdom computes no colours, so this
// reads the tokens of index.css and checks WCAG AA (4.5:1) in the light theme, the dark theme and the dark-by-system fallback.
// The axe `color-contrast` hit on `div[data-title=""]` seen in e2e-real was sonner's 400 ms opacity fade-in, not a token pair
// (see expectAccessible in e2e-real/ui.ts, which waits for the toast to leave).
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const css = readFileSync(resolve(process.cwd(), 'src/index.css'), 'utf8') // vitest runs from web/

function tokens(block: string): Record<string, string> {
  return Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})/g)].map((m) => [m[1]!, m[2]!]))
}
const light = tokens(/:root\s*\{([^}]*)\}/.exec(css)![1]!)
const dark = tokens(/\[data-theme="dark"\]\s*\{([^}]*)\}/.exec(css)![1]!)
const system = tokens(/:root:not\(\[data-theme="light"\]\)\s*\{([^}]*)\}/.exec(css)![1]!)

function lum(hex: string) {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!
}
const ratio = (a: string, b: string) => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x)
  return (hi! + 0.05) / (lo! + 0.05)
}

describe('toast text contrast', () => {
  for (const [theme, t] of [['light', light], ['dark', dark], ['dark by system', system]] as const) {
    it(`${theme}: title (ink) and description (muted) on the toast surface reach 4.5:1`, () => {
      expect(ratio(t.ink!, t.surface!)).toBeGreaterThanOrEqual(4.5)
      expect(ratio(t.muted!, t.surface!)).toBeGreaterThanOrEqual(4.5)
    })
  }
})
