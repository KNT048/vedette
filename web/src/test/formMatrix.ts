// Form matrix (docs/QA.md §2): a form whose selector changes the meaning of other fields is tested once per option.
// For every option: only that option's fields are visible, the other options' fields are absent, and a control that cannot be used in this context is locked.
import { expect } from 'vitest'
import { screen, within } from '@testing-library/react'

/** A field, button or text, found by its label, its button name or its text. */
export type Probe = string | RegExp

export interface MatrixCase {
  /** What the selector is set to. Handed to `pick`. */
  option: string
  /** Fields that must be on screen for this option. */
  shown?: Probe[]
  /** Fields of other options that must NOT be on screen (no leak between options). */
  hidden?: Probe[]
  /** Controls that must be on screen but disabled (an option that cannot be used here). */
  locked?: Probe[]
}

function find(p: Probe, root: HTMLElement): HTMLElement[] {
  const w = within(root)
  return [...w.queryAllByLabelText(p), ...w.queryAllByRole('button', { name: p }), ...w.queryAllByRole('radio', { name: p }), ...w.queryAllByText(p)]
}

/** Runs every case in order through `pick`, then checks the screen. Cases may repeat an option to prove that going back restores the same fields. */
export async function eachOption(cases: MatrixCase[], pick: (option: string) => Promise<void> | void, root: HTMLElement = document.body): Promise<void> {
  for (const c of cases) {
    await pick(c.option)
    for (const p of c.shown ?? []) expect(find(p, root).length, `option "${c.option}": "${String(p)}" should be shown`).toBeGreaterThan(0)
    for (const p of c.hidden ?? []) expect(find(p, root).length, `option "${c.option}": "${String(p)}" should be hidden`).toBe(0)
    for (const p of c.locked ?? []) {
      const el = find(p, root)[0]
      expect(el, `option "${c.option}": "${String(p)}" should be present but locked`).toBeDefined()
      expect(el, `option "${c.option}": "${String(p)}" should be locked`).toBeDisabled()
    }
  }
}

export { screen }
