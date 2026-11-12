// The trigger catalog of the box (modules/response/data/triggers.json) and of the mock (data.ts) are one contract: the form checks
// condition values against the ranges and choices it reads (D-390), so the two must not drift.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { TRIGGERS } from './data'

type F = { key: string; label: string; type: string; choices: string[]; min?: number | null; max?: number | null }
const box = JSON.parse(readFileSync(resolve(__dirname, '../../../../modules/response/data/triggers.json'), 'utf8')) as { triggers: { id: string; fields: F[] }[] }
const shape = (fields: F[]) => fields.map((f) => ({ key: f.key, label: f.label, type: f.type, choices: f.choices, min: f.min ?? null, max: f.max ?? null }))

describe('trigger catalog (D-390)', () => {
  it('the mock has the fields, labels, choices and ranges of the box', () => {
    for (const t of box.triggers) expect(shape(TRIGGERS.find((x) => x.id === t.id)?.fields ?? []), t.id).toEqual(shape(t.fields))
    expect(TRIGGERS.map((t) => t.id).sort()).toEqual(box.triggers.map((t) => t.id).sort())
  })
})
