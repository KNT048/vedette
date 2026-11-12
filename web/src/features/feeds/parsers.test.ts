import { describe, expect, it } from 'vitest'
import { defaultParser } from './defaults'
import { compilePath, jsonPath, normDate, parseCsv, parseFeed, ParserConfigError } from './parsers'
import { SAMPLES } from './samples'
import type { FeedFormat, FeedKind } from './types'

const run = (kind: FeedKind, format: FeedFormat) => parseFeed(SAMPLES[kind][format]!.text, kind, defaultParser(kind, format))

describe('feed parsers (S-FEED-5)', () => {
  it('JSONPath subset', () => {
    const doc = { a: [{ b: 1 }, { b: 2 }], 'x-y': 3 }
    expect(jsonPath(doc, '$.a[*].b')).toEqual([1, 2])
    expect(jsonPath(doc, "$['x-y']")).toEqual([3])
    expect(jsonPath(doc, '$.a[1]')).toEqual([{ b: 2 }])
    expect(() => compilePath('$..b')).toThrow(ParserConfigError)
    expect(() => compilePath('a.b')).toThrow(/start with \$/)
  })

  it('JSON vulnerabilities: counts accepted and rejected rows with reasons', () => {
    const r = run('vulnerabilities', 'json')
    expect(r.accepted).toBe(3)
    expect(r.rejected).toBe(3)
    expect(r.records[2]!.cve).toBe('CVE-2026-18002') // upper-cased
    expect(r.reasons.map((x) => x.reason).join('|')).toMatch(/not a CVE ID.*unrecognised date.*not an http\(s\) address/)
  })

  it('CSV with quotes, comments and DD/MM/YYYY dates', () => {
    expect(parseCsv('# c\na,"b,c"\n1,"x ""y"""\n', ',')).toEqual([['a', 'b,c'], ['1', 'x "y"']])
    const r = run('vulnerabilities', 'csv')
    expect(r.accepted).toBe(3)
    expect(r.records[0]!.date).toBe('2026-11-03')
    expect(r.rejected).toBe(2)
  })

  it('RSS: regex capture pulls the CVE from the title; items without one are rejected', () => {
    const r = run('vulnerabilities', 'rss')
    expect(r.accepted).toBe(3)
    expect(r.records.map((x) => x.cve)).toEqual(['CVE-2026-20311', 'CVE-2026-19844', 'CVE-2026-18002'])
    expect(r.records[0]!.date).toBe('2026-11-03')
    expect(r.reasons[0]!.reason).toBe('cve: regex did not match')
  })

  it('STIX / TAXII: parses indicator patterns, splits OR, rejects unsupported objects', () => {
    const r = run('ioc', 'stix')
    expect(r.records.map((x) => `${x.kind}:${String(x.indicator).slice(0, 14)}`)).toEqual(['ip:185.220.101.47', 'domain:update-dsm-syn', 'ip:45.148.10.95', 'ip:103.75.190.12', 'hash:a3f5c1d9e8b7a6'])
    expect(r.records[0]!.confidence).toBe(0.85)
    expect(r.rejected).toBe(2)
    expect(r.reasons.some((x) => x.reason.startsWith('unsupported pattern object'))).toBe(true)
  })

  it('CSV rejects are numbered by the line of the sample (header, comments, blank lines and multi-line quotes count)', () => {
    const p = defaultParser('ioc', 'csv')
    const r = parseFeed('# feed\r\ndst_ip,note\r\n\r\n8.8.8.8,"two\r\nlines"\r\nnot-an-ip,x\n1.1.1.1,y\n# end\nbad2,z\n', 'ioc', p)
    expect(r.rejects.map((x) => x.row)).toEqual([6, 9])
  })

  it('CSV: an unclosed quote flags that row and the rest is read with quotes literal, on the same line numbers (as modules/feeds)', () => {
    expect(parseCsv('a,b\n1,"x\n2,y\n3,z\n', ',')).toEqual([['a', 'b'], ['1', '"x'], ['2', 'y'], ['3', 'z']])
    const p = defaultParser('ioc', 'csv')
    const r = parseFeed('dst_ip,note\n8.8.8.8,ok\n1.1.1.1,"never closed\n9.9.9.9,y\nnot-an-ip,z\n', 'ioc', p)
    expect(r.accepted).toBe(2) // 8.8.8.8 and 9.9.9.9
    expect(r.rejects).toEqual([{ row: 3, reason: 'a quote is opened on this row and never closed' }, { row: 5, reason: expect.stringContaining('not-an-ip') }])
    // an open quote in the header row is a sample the editor cannot use
    expect(() => parseFeed('"dst_ip,note\n8.8.8.8,ok\n', 'ioc', p)).toThrow(/header row is not usable/)
  })

  it('plain list skips comments and blank lines, detects the kind, rejects junk', () => {
    const r = run('ioc', 'lines')
    expect(r.accepted).toBe(4)
    expect(r.rejected).toBe(1)
    expect(r.records.every((x) => x.kind === 'ip')).toBe(true)
  })

  it('JSON IOC: normalises kind aliases, scores and ip:port; rejects bad values', () => {
    const r = run('ioc', 'json')
    expect(r.records.map((x) => x.kind)).toEqual(['ip', 'domain', 'url', 'hash'])
    expect(r.records[0]!.confidence).toBe(0.92)
    expect(r.rejected).toBe(3)
  })

  it('IDN top-level domains in ASCII form are domains, like the Go parser (hagezi TIF, 2026-11-12)', () => {
    const r = parseFeed('# Syntax: Domains (without subdomains)\ndiscord.xn--q9jyb4c\nxn-----6kcacs9ajdmhcwdcbwwcnbgd13a.xn--p1ai\na.xn--p1ai-\n', 'ioc', defaultParser('ioc', 'lines'))
    expect(r.records.map((x) => `${x.kind}:${String(x.indicator)}`)).toEqual(['domain:discord.xn--q9jyb4c', 'domain:xn-----6kcacs9ajdmhcwdcbwwcnbgd13a.xn--p1ai'])
    expect(r.rejected).toBe(1)
  })

  it('fails closed: size limit, bad JSON and invalid regex are errors, not crashes', () => {
    const p = defaultParser('ioc', 'lines')
    expect(() => parseFeed('x'.repeat(5_000_001), 'ioc', p)).toThrow(/larger than 5 MB/)
    expect(() => parseFeed('{nope', 'ioc', defaultParser('ioc', 'json'))).toThrow(/not valid JSON/)
    p.fields.indicator!.regex = '(['
    expect(() => parseFeed('1.2.3.4', 'ioc', p)).toThrow(/Invalid regular expression/)
  })

  it('row limit stops parsing and flags truncation', () => {
    const text = Array.from({ length: 50_010 }, (_, i) => `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`).join('\n')
    const r = parseFeed(text, 'ioc', defaultParser('ioc', 'lines'))
    expect(r.truncated).toBe(true)
    expect(r.accepted).toBe(50_000)
  })

  it('dates', () => {
    expect(normDate('03/11/2026', 'dmy')).toBe('2026-11-03')
    expect(normDate('11/03/2026', 'mdy')).toBe('2026-11-03')
    expect(normDate('1793700000', 'epoch')).toBe('2026-11-03')
    expect(normDate('Mon, 03 Nov 2026 09:00:00 GMT', 'auto')).toBe('2026-11-03')
    expect(normDate('31/13/2026', 'dmy')).toBeNull()
  })
})
