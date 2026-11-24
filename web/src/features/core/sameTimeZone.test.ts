import { describe, expect, it } from 'vitest'
import { sameTimeZone } from './util'

describe('sameTimeZone', () => {
  it('takes two names of one zone for one zone, so the General page does not offer the browser zone it already has', () => {
    expect(sameTimeZone('Asia/Saigon', 'Asia/Ho_Chi_Minh')).toBe(true)
    expect(sameTimeZone('Asia/Ho_Chi_Minh', 'Asia/Ho_Chi_Minh')).toBe(true)
    expect(sameTimeZone('Asia/Ho_Chi_Minh', 'Asia/Bangkok')).toBe(false)
    expect(sameTimeZone('Asia/Ho_Chi_Minh', 'Not/AZone')).toBe(false)
  })
})
