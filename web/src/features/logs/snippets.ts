export const BOX_PLACEHOLDER = '<VEDETTE_BOX_IP>'
// Mẫu bản ghi chuyển tiếp SIEM (S-LOG-3). Đoạn cấu hình theo loại thiết bị nằm ở catalog.ts.
// CEF (ArcSight, Implementing ArcSight CEF): CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension.
// Syslog dạng RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG.

/** Mẫu một bản ghi theo định dạng SIEM, để người dùng thấy đúng cái sẽ được gửi (S-LOG-3). */
export function siemSample(format: 'syslog' | 'cef' | 'json', boxIp: string | null = null): string {
  const box = boxIp ?? BOX_PLACEHOLDER
  if (format === 'cef') {
    return 'CEF:0|Vedette|Vedette|1.0|finding.confirmed|Exploited vulnerability matches a device|10|src=192.168.10.21 shost=NAS-PHOTOS cs1Label=cve cs1=CVE-2022-27593 cs2Label=product cs2=QNAP Photo Station rt=1793930400000'
  }
  if (format === 'json') {
    return JSON.stringify({ event: 'finding.confirmed', time: '2026-11-06T02:00:00Z', severity: 'critical', device: { id: 'a-nas02', name: 'NAS-PHOTOS', ip: '192.168.10.21' }, cve: 'CVE-2022-27593', product: 'QNAP Photo Station', url: `https://${box}/findings/f-1` }, null, 2)
  }
  return '<130>1 2026-11-06T02:00:00Z vedette-hq vedette - finding.confirmed - severity=critical device=NAS-PHOTOS ip=192.168.10.21 cve=CVE-2022-27593 product="QNAP Photo Station"'
}
