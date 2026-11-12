import { describe, expect, it } from 'vitest'
import { deviceLabel, guessablePassword, isBareIp, isPrivateCidr, normaliseCidr } from './util'

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

describe('deviceLabel (sessions table)', () => {
  it.each([
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/158.0.8127.18 Safari/537.36', 'Headless Chrome on macOS'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0', 'Edge on Windows'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1', 'Safari on iOS'],
    ['Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0', 'Firefox on Linux'],
    ['Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36', 'Chrome on Android'],
    ['curl/8.7.1', 'curl/8.7.1'],
  ])('%s', (ua, want) => { expect(deviceLabel(ua)).toBe(want) })
})

describe('guessablePassword (mock copy of core/auth, D-389)', () => {
  it.each(['password1234', 'Qwerty123456!', 'P@$$word2024', 'adminadmin12', 'Vedette2026!!', 'aaaaaaaaaaaa', '121212121212', '123456789012', 'lkjhgfdsapoiu', '1234567890!!', 'qwertyuiop2024'])('refuses %s', (p) => { expect(guessablePassword(p, 'u@acme.example')).toBe(true) })
  it('refuses the name of the email', () => { expect(guessablePassword('Someone2026!!', 'someone@acme.example')).toBe(true) })
  it.each(['correct horse battery staple', 'my password is long now', 'vedette-demo', 'lamp river42', 'Master of puppets 1986'])('accepts %s', (p) => { expect(guessablePassword(p, 'u@acme.example')).toBe(false) })
})
