// The brand placement (#826): the logo, not a typed "Vedette", on the sign-in page and in the sidebar; the inline geometry matches the
// brand files in docs/brand, so a re-run of scripts/brand/outline.py that changes them also has to change Logo.tsx.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { render, screen, within } from '@testing-library/react'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { LOGO, Logo, SIGNAL } from './Logo'

const FILES = { horizontal: 'logo-horizontal', stacked: 'logo-stacked', mark: 'mark' } as const

describe('Logo geometry', () => {
  for (const [variant, file] of Object.entries(FILES) as [keyof typeof FILES, string][]) {
    it(`${variant} matches docs/brand/${file}.svg`, () => {
      const svg = readFileSync(resolve(process.cwd(), `../docs/brand/${file}.svg`), 'utf8') // vitest runs from web/
      const g = LOGO[variant]
      expect(svg).toContain(`viewBox="${g.viewBox}"`)
      expect(svg).toContain(`<path d="${g.sight}" fill="none" stroke="#1d5a45" stroke-width="${g.stroke}"`)
      expect(svg).toContain(`<circle cx="${g.dot[0]}" cy="${g.dot[1]}" r="${g.dot[2]}" fill="${SIGNAL}"/>`)
      if (g.word) expect(svg).toContain(`<path d="${g.word}" fill="#18211d"/>`)
    })
  }

  it('takes the theme colours from tokens, keeps the dot amber, and is either named or hidden', () => {
    const { container } = render(<><Logo /><Logo variant="mark" decorative /></>)
    const [named, hidden] = container.querySelectorAll('svg')
    expect(named).toHaveAttribute('role', 'img')
    expect(named).toHaveAccessibleName('Vedette')
    expect(named!.querySelector('path')).toHaveClass('stroke-accent')
    expect(named!.querySelectorAll('path')[1]).toHaveClass('fill-ink')
    expect(hidden).toHaveAttribute('aria-hidden', 'true')
    expect(hidden!.querySelectorAll('path')).toHaveLength(1)
  })
})

describe('brand placement', () => {
  it('sign-in: the stacked logo is the one h1, named Vedette', async () => {
    renderApp('/login', { role: null })
    const h1 = await screen.findByRole('heading', { level: 1 })
    expect(h1).toHaveAccessibleName('Vedette')
    expect(h1.querySelector('svg')).toHaveAttribute('viewBox', LOGO.stacked.viewBox)
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    await expectNoA11yViolations()
  })

  it('signed in: the sidebar and the phone header show the logo, not the typed name', async () => {
    renderApp('/')
    const nav = await screen.findByRole('navigation', { name: /./ })
    const logos = await screen.findAllByRole('img', { name: 'Vedette' })
    expect(logos).toHaveLength(2) // desktop sidebar + phone header (one is hidden by CSS at each width)
    expect(within(nav).queryByText('Vedette')).toBeNull()
  })
})
