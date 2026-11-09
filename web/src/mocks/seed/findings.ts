// 3 phát hiện mẫu gắn CVE KEV thật (kế hoạch §2.2 P-3). ID cố định: f-1 (NAS, xác nhận), f-2 (WordPress, nghi), f-3 (Windows Server 2016, nghi).
// Module findings sở hữu file này (có thể thêm phát hiện); module khác chỉ đọc qua findingsStore.
import type { Finding } from '@/lib/types'

const D = (days: number, h = 0) => new Date(Date.now() - days * 864e5 - h * 36e5).toISOString()

export function seedFindings(): Finding[] {
  return [
    {
      id: 'f-1', asset_id: 'a-nas02', cve: 'CVE-2022-27593', status: 'confirmed', severity: 'critical', confidence: 0.95, basis: 'scan',
      evidence: {
        summary: 'The nuclei-templates safe scan template for CVE-2022-27593 matched both conditions on the Photo Station of NAS-PHOTOS.',
        template: 'http/cves/2022/CVE-2022-27593.yaml',
        request: 'GET http://192.168.10.21/photo/… HTTP/1.1 (shortened)',
        response: 'HTTP/1.1 200 OK, the response body matches the template signature (shortened)',
        checked_at: D(0, 3),
      },
      first_seen: D(2), last_seen: D(0, 3), resolved_by: null, resolved_at: null, resolution_note: null,
      history: [{ ts: D(2), user: 'system', action: 'created', note: 'Matched product QNAP Photo Station' }, { ts: D(0, 3), user: 'system', action: 'confirmed', note: 'Confirmed by scan match' }],
    },
    {
      id: 'f-2', asset_id: 'a-web01', cve: 'CVE-2026-119977', status: 'suspected', severity: 'high', confidence: 0.5, basis: 'product',
      evidence: { summary: 'WEB01 runs WordPress (read from the generator tag, medium confidence). It is not yet known whether the version is in the affected range.', checked_at: D(0, 6) },
      first_seen: D(3), last_seen: D(0, 6), resolved_by: null, resolved_at: null, resolution_note: null,
      history: [{ ts: D(3), user: 'system', action: 'created', note: 'New KEV entry matches product WordPress Core' }],
    },
    {
      id: 'f-3', asset_id: 'a-srvad', cve: 'CVE-2026-96951', status: 'suspected', severity: 'high', confidence: 0.6, basis: 'version',
      evidence: { summary: 'SRV-AD runs Windows Server 2016 (identified by active scan). There is no installed-patch data to rule it out yet.', checked_at: D(1) },
      first_seen: D(24), last_seen: D(1), resolved_by: null, resolved_at: null, resolution_note: null,
      history: [{ ts: D(24), user: 'system', action: 'created', note: 'KEV entry matches Microsoft Windows' }],
    },
  ]
}
