import { describe, expect, it } from 'vitest'
import { withoutNotRelevant } from './notRelevant'

// findings closed as not relevant are hidden by default wherever findings are listed; "Show not relevant (N)" brings them back.
describe('not relevant is hidden by default', () => {
  it('withoutNotRelevant: hides them and says how many; shown keeps all', () => {
    const rows = [{ status: 'suspected' }, { status: 'not_relevant' }, { status: 'patched' }, { status: 'not_relevant' }] as const
    expect(withoutNotRelevant(rows, false)).toEqual({ rows: [rows[0], rows[2]], hidden: 2, total: 2 })
    expect(withoutNotRelevant(rows, true)).toMatchObject({ hidden: 0, total: 2 })
    expect(withoutNotRelevant(rows, true).rows).toHaveLength(4)
  })

})
