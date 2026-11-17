import { describe, expect, it } from 'vitest'
import type { TFunction } from 'i18next'
import { keptBy, notInstalledText } from './notInstalled'

// Inventory INV-41 (6), findings INV-6c: the message after "Not installed" says what happened, and names why a finding stayed open.
const t = ((k: string, o?: { count?: number }) => (o?.count === undefined ? k : `${k}:${o.count}`)) as unknown as TFunction
const at = '2026-11-17T10:00:00.000Z'
const KEPT = 'op said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026. This finding stays open because a person reopened it or accepted its risk after that; close it yourself if the software is not there.'

describe('Not installed: the outcome message', () => {
  it('names each reason a finding stayed open', () => {
    expect(notInstalledText(t, 'OpenSSH', 'router-1', { closed: 2, scanned: 1, reopened: 1, accepted: 1, other: 1 })).toBe(
      'findings:notInstalled.done findings:notInstalled.closed:2 findings:notInstalled.keptScan:1 findings:notInstalled.keptReopened:1 findings:notInstalled.keptAccepted:1 findings:notInstalled.keptOther:1')
    expect(notInstalledText(t, 'OpenSSH', 'router-1', { closed: 0, scanned: 0, reopened: 0, accepted: 0, other: 0 })).toBe('findings:notInstalled.done findings:notInstalled.none')
  })

  it('a finding a person kept open is told by its history: the newest reopen or acceptance; otherwise another source', () => {
    const kept = { ts: at, user: 'system', action: 'no_longer_matches', note: KEPT }
    expect(keptBy({ history: [{ ts: at, user: 'kim@example.com', action: 'reopened' }, kept] })).toBe('reopened')
    expect(keptBy({ history: [{ ts: at, user: 'kim@example.com', action: 'reopened' }, { ts: at, user: 'kim@example.com', action: 'risk_accepted' }, { ts: at, user: 'system', action: 'reopened' }, kept] })).toBe('accepted')
    expect(keptBy({ history: [{ ts: at, user: 'system', action: 'created' }] })).toBe('other')
  })
})
