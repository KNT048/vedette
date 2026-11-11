import { afterEach, describe, expect, it, vi } from 'vitest'
import { HttpResponse, http } from 'msw'
import { server } from '@/test/server'
import { dispositionName, download } from './api'

describe('download file name (S-CORE-1, issue #232)', () => {
  it('uses the name the box sends: plain, quoted and RFC 5987', () => {
    expect(dispositionName('attachment; filename=vedette-backup-1.tar.gz', 'x.json')).toBe('vedette-backup-1.tar.gz')
    expect(dispositionName('attachment; filename="a b.tar.gz"', 'x.json')).toBe('a b.tar.gz')
    expect(dispositionName("attachment; filename=\"fallback.txt\"; filename*=UTF-8''v%C3%A9.tar.gz", 'x.json')).toBe('vé.tar.gz')
  })
  it('strips path parts and control characters, and falls back', () => {
    expect(dispositionName('attachment; filename="../../etc/passwd"', 'x.json')).toBe('passwd')
    expect(dispositionName('attachment; filename="C:\\temp\\b.tar.gz"', 'x.json')).toBe('b.tar.gz')
    expect(dispositionName('attachment; filename="a\u0000b\nc.gz"', 'x.json')).toBe('abc.gz')
    expect(dispositionName('attachment; filename=".."', 'x.json')).toBe('x.json')
    expect(dispositionName(null, 'x.json')).toBe('x.json')
    expect(dispositionName('attachment', 'x.json')).toBe('x.json')
  })
  afterEach(() => vi.restoreAllMocks())
  it('saves the file under the name from the header', async () => {
    server.use(http.get('*/api/v1/core/data/backup', () => new HttpResponse('x', { headers: { 'Content-Disposition': 'attachment; filename=vedette-backup-2026-11-11.tar.gz' } })))
    URL.createObjectURL = vi.fn(() => 'blob:x'); URL.revokeObjectURL = vi.fn()
    let saved = ''
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { saved = this.download })
    await download('/core/data/backup', 'vedette-backup-day.json')
    expect(saved).toBe('vedette-backup-2026-11-11.tar.gz')
  })
})
