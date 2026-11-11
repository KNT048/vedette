/// <reference types="node" />
// content/logs/kinds.json is the Go side's copy of the log source kinds (modules/logs validates a source's protocol with it).
// The catalog of this feature is the approved GUI contract: they must say the same, kind for kind, so a kind or a protocol
// cannot be added to one side only.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { CATALOG } from './catalog'
import { KIND_IDS } from './kinds'

const FILE = join(import.meta.dirname, '../../../../content/logs/kinds.json')
const kinds = JSON.parse(readFileSync(FILE, 'utf8')) as { id: string; protos: string[]; reads: string }[]

describe('log source kinds: the GUI catalog and content/logs/kinds.json agree', () => {
  it('the same kinds', () => {
    expect(kinds.map((k) => k.id).sort()).toEqual([...KIND_IDS].sort())
  })
  for (const k of kinds) {
    it(`${k.id}: protocols (first is the default) and how it is read`, () => {
      const e = CATALOG[k.id as keyof typeof CATALOG]
      expect(e).toBeDefined()
      expect(k.protos).toEqual(e.protos)
      expect(k.reads).toBe(e.reads)
    })
  }
})
