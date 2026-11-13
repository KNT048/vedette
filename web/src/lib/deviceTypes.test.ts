import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { actsAs, BEHAVIOUR_KINDS, kindLabel, lookupType, matchesKind } from './deviceTypes'

describe('device types (D-511)', () => {
  it('the 13 kinds behaviour is keyed on are the Go list (content/devicetypes Kinds)', () => {
    const goSrc = readFileSync(join(import.meta.dirname, '../../../content/devicetypes/types.go'), 'utf8')
    const goKinds = /var Kinds = \[\]string\{([^}]*)\}/.exec(goSrc)?.[1]?.split(',').map((s) => s.trim().replace(/"/g, ''))
    expect(goKinds).toEqual([...BEHAVIOUR_KINDS])
  })

  it('a rule keyed on kinds covers a type acting as one, never a type marked no_auto_isolate (as devicetypes.MatchesKind)', () => {
    const tpl = ['camera', 'nvr', 'iot']
    for (const [id, want] of [['camera', true], ['ip_phone', true], ['dvr', true], ['laptop', false], ['pbx', false], ['plc', false], ['medical_device', false], ['bmc', false]] as const) {
      expect(matchesKind(tpl, id), id).toBe(want)
    }
    expect(actsAs('vpn_gateway')).toBe('firewall')
    expect(kindLabel('virtual_machine')).toBe('Virtual machine')
    expect(lookupType('smart switch')).toBe('switch')
  })
})
