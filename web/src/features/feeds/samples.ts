// Realistic sample payloads per kind and format, used by the mock "fetch a sample" and by "Fetch now" for custom feeds.
// Each has a few deliberately bad rows so the preview shows counted, reasoned rejections.
import type { FeedFormat, FeedKind } from './types'

const J = (v: unknown) => JSON.stringify(v, null, 2)

export const SAMPLES: Record<FeedKind, Partial<Record<FeedFormat, { label: string; text: string }>>> = {
  vulnerabilities: {
    json: { label: 'Vendor advisory API (JSON)', text: J({ title: 'Example vendor security advisories', count: 6, vulnerabilities: [
      { cveID: 'CVE-2026-20311', vendorProject: 'Synology', product: 'DiskStation Manager', dateAdded: '2026-11-03', shortDescription: 'Authentication bypass in the web interface allows remote access without credentials.', notes: 'https://www.synology.com/en-global/security/advisory/Synology_SA_26_11' },
      { cveID: 'CVE-2026-19844', vendorProject: 'Fortinet', product: 'FortiOS', dateAdded: '2026-11-02', shortDescription: 'Heap overflow in the SSL VPN daemon, exploited in the wild.', notes: 'https://fortiguard.example.com/psirt/FG-IR-26-402' },
      { cveID: 'cve-2026-18002', vendorProject: 'Ubiquiti', product: 'UniFi Network Application', dateAdded: '2026-10-30', shortDescription: 'Path traversal lets an authenticated user read arbitrary files.', notes: 'https://community.example.com/ubnt-sa-26-009' },
      { cveID: 'TBD', vendorProject: 'MikroTik', product: 'RouterOS', dateAdded: '2026-10-29', shortDescription: 'CVE not assigned yet.', notes: '' },
      { cveID: 'CVE-2026-17760', vendorProject: 'QNAP', product: 'QTS', dateAdded: '31/13/2026', shortDescription: 'Command injection in a legacy service.', notes: 'https://www.qnap.com/en/security-advisory/qsa-26-40' },
      { cveID: 'CVE-2026-17511', vendorProject: 'Veeam', product: 'Backup & Replication', dateAdded: '2026-10-27', shortDescription: 'Deserialization of untrusted data in the backup service.', notes: 'javascript:alert(1)' },
    ] }) },
    csv: { label: 'Advisory export (CSV)', text: [
      'cve,vendor,product,published,summary,url',
      'CVE-2026-20311,Synology,DiskStation Manager,03/11/2026,"Authentication bypass, remote",https://www.synology.com/en-global/security/advisory/Synology_SA_26_11',
      'CVE-2026-19844,Fortinet,FortiOS,02/11/2026,Heap overflow in SSL VPN,https://fortiguard.example.com/psirt/FG-IR-26-402',
      'CVE-2026-18002,Ubiquiti,UniFi Network Application,30/10/2026,Path traversal,',
      'n/a,MikroTik,RouterOS,29/10/2026,No CVE yet,',
      'CVE-2026-17760,QNAP,QTS,not a date,Command injection,https://www.qnap.com/en/security-advisory/qsa-26-40',
    ].join('\n') },
    rss: { label: 'Advisory feed (RSS 2.0)', text: `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Security advisories</title><link>https://advisories.example.com</link>
<item><title>CVE-2026-20311: Authentication bypass in DiskStation Manager</title><link>https://advisories.example.com/sa-26-11</link><description>Remote attackers can bypass login on the web interface.</description><category>DiskStation Manager</category><pubDate>Mon, 03 Nov 2026 09:00:00 GMT</pubDate></item>
<item><title>CVE-2026-19844 - Heap overflow in FortiOS SSL VPN</title><link>https://advisories.example.com/fg-402</link><description>Exploited in the wild.</description><category>FortiOS</category><pubDate>Sun, 02 Nov 2026 14:30:00 GMT</pubDate></item>
<item><title>Monthly security bulletin, October</title><link>https://advisories.example.com/bulletin-oct</link><description>Summary of fixes.</description><category>Bulletin</category><pubDate>Fri, 31 Oct 2026 08:00:00 GMT</pubDate></item>
<item><title>CVE-2026-18002: Path traversal in UniFi Network Application</title><link>https://advisories.example.com/ubnt-009</link><description>Authenticated file read.</description><category>UniFi Network Application</category><pubDate>Fri, 30 Oct 2026 10:15:00 GMT</pubDate></item>
</channel></rss>` },
  },
  ioc: {
    json: { label: 'Threat intel API (JSON)', text: J({ query_status: 'ok', data: [
      { ioc: '185.220.101.47', type: 'ip', score: 92, first_seen: '2026-09-12 10:22:01' },
      { ioc: 'update-dsm-synology.com', type: 'domain', score: 88, first_seen: '2026-10-29 03:10:44' },
      { ioc: 'https://cdn-telemetry-sync.net/payload.bin', type: 'url', score: 70, first_seen: '2026-10-02 18:05:00' },
      { ioc: '44d88612fea8a8f36de82e1278abb02f', type: 'md5_hash', score: 95, first_seen: '2026-10-21 07:00:00' },
      { ioc: '999.1.1.1', type: 'ip', score: 40, first_seen: '2026-10-25 11:00:00' },
      { ioc: 'example.org', type: 'mailbox', score: 30, first_seen: '2026-10-26 11:00:00' },
      { ioc: '103.75.190.12', type: 'ip', score: 'high', first_seen: '2026-10-30 12:00:00' },
    ] }) },
    csv: { label: 'Botnet C2 blocklist (CSV)', text: [
      '################################################################',
      '# Example C2 blocklist, generated 2026-11-06 07:00:00 UTC',
      '################################################################',
      'first_seen_utc,dst_ip,dst_port,c2_status,malware',
      '2026-10-02 18:05:00,45.148.10.95,443,online,Cobalt Strike',
      '2026-10-20 07:41:12,103.75.190.12,8080,online,QakBot',
      '2026-10-29 22:00:00,203.0.113.77,447,offline,Emotet',
      '2026-10-30 09:00:00,not-an-ip,447,online,Unknown',
      '2026-10-31 09:00:00,198.51.100.23,443,online,IcedID',
    ].join('\n') },
    rss: { label: 'Phishing reports (Atom)', text: `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Reported phishing hosts</title>
<entry><title>update-dsm-synology.com</title><link href="https://reports.example.com/e/1"/><published>2026-10-29T03:10:44Z</published><summary>Fake NAS update page</summary></entry>
<entry><title>login-m365-secure.net</title><link href="https://reports.example.com/e/2"/><published>2026-10-31T11:00:00Z</published><summary>Credential harvesting</summary></entry>
<entry><title>Weekly summary</title><link href="https://reports.example.com/e/3"/><published>2026-11-01T00:00:00Z</published><summary>Not an indicator</summary></entry>
</feed>` },
    stix: { label: 'TAXII 2.1 collection (STIX 2.1 objects)', text: J({ more: false, objects: [
      { type: 'indicator', spec_version: '2.1', id: 'indicator--8e2e2d2b-17d4-4cbe-9bb8-c9ff4a2a0a01', created: '2026-10-20T07:00:00.000Z', valid_from: '2026-10-20T07:00:00Z', confidence: 85, pattern_type: 'stix', pattern: "[ipv4-addr:value = '185.220.101.47']" },
      { type: 'indicator', spec_version: '2.1', id: 'indicator--8e2e2d2b-17d4-4cbe-9bb8-c9ff4a2a0a02', valid_from: '2026-10-29T03:10:44Z', confidence: 90, pattern_type: 'stix', pattern: "[domain-name:value = 'update-dsm-synology.com']" },
      { type: 'indicator', spec_version: '2.1', id: 'indicator--8e2e2d2b-17d4-4cbe-9bb8-c9ff4a2a0a03', valid_from: '2026-10-21T07:00:00Z', confidence: 60, pattern_type: 'stix', pattern: "[ipv4-addr:value = '45.148.10.95'] OR [ipv4-addr:value = '103.75.190.12']" },
      { type: 'indicator', spec_version: '2.1', id: 'indicator--8e2e2d2b-17d4-4cbe-9bb8-c9ff4a2a0a04', valid_from: '2026-10-22T07:00:00Z', pattern_type: 'stix', pattern: "[file:hashes.'SHA-256' = 'a3f5c1d9e8b7a6f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0918273']" },
      { type: 'indicator', spec_version: '2.1', id: 'indicator--8e2e2d2b-17d4-4cbe-9bb8-c9ff4a2a0a05', valid_from: '2026-10-23T07:00:00Z', pattern_type: 'stix', pattern: "[email-addr:value = 'phish@example.org']" },
      { type: 'malware', spec_version: '2.1', id: 'malware--1b2c3d4e-0000-4000-8000-000000000001', name: 'ExampleLoader', is_family: true },
      { type: 'indicator', spec_version: '2.1', id: 'indicator--8e2e2d2b-17d4-4cbe-9bb8-c9ff4a2a0a06', valid_from: '2026-10-24T07:00:00Z', pattern_type: 'stix', pattern: '[process:name MATCHES "evil"]' },
    ] }) },
    lines: { label: 'Plain list of addresses', text: [
      '# Example blocklist of attacking addresses',
      '# updated 2026-11-06',
      '185.220.101.47\t8',
      '45.148.10.95\t5',
      '',
      '103.75.190.12\t3',
      'this is not an address',
      '198.51.100.23\t2',
    ].join('\n') },
  },
}

export function sampleFor(kind: FeedKind, format: FeedFormat) { return SAMPLES[kind][format] }
