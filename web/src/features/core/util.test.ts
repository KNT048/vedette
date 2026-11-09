import { describe, expect, it } from 'vitest'
import { isBareIp, isPrivateCidr, normaliseCidr } from './util'

describe('normaliseCidr (bước nhập dải mạng ở cài đặt ban đầu)', () => {
  it('địa chỉ trần thiếu tiền tố bị từ chối, không tự đoán /24', () => { expect(normaliseCidr('192.168.18.0')).toBeNull(); expect(isBareIp('192.168.18.0')).toBe(true) })
  it('giữ đúng tiền tố người dùng gõ, kể cả /25', () => { expect(normaliseCidr('192.168.18.128/25')).toEqual({ value: '192.168.18.128/25', note: null }) })
  it('có bit máy thì về địa chỉ mạng và báo network', () => { expect(normaliseCidr('192.168.18.77/24')).toEqual({ value: '192.168.18.0/24', note: 'network' }) })
  it('đã đúng thì giữ nguyên, không ghi chú', () => { expect(normaliseCidr(' 10.20.0.0/16 ')).toEqual({ value: '10.20.0.0/16', note: null }) })
  it.each(['', 'abc', '192.168.1.0/33', '300.1.1.1/24', '192.168.1/24', '1.2.3.4/'])('từ chối "%s"', (x) => { expect(normaliseCidr(x)).toBeNull() })
})

describe('isPrivateCidr', () => {
  it.each(['10.0.0.0/8', '172.16.0.0/12', '172.31.5.0/24', '192.168.0.0/16'])('nhận %s', (x) => { expect(isPrivateCidr(x)).toBe(true) })
  it.each(['8.8.8.0/24', '172.32.0.0/16', '10.0.0.0/0', '10.0.0.0/7', '172.16.0.0/11', '192.168.0.0/15', '0.0.0.0/0'])('từ chối %s', (x) => { expect(isPrivateCidr(x)).toBe(false) })
})
