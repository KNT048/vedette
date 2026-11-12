export const BOX_PLACEHOLDER = '<VEDETTE_BOX_IP>'
// Mẫu bản ghi chuyển tiếp SIEM (S-LOG-3). Đoạn cấu hình theo loại thiết bị nằm ở catalog.ts.
// CEF (ArcSight, Implementing ArcSight CEF): CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension.
// Syslog dạng RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG.

/** Mẫu một bản ghi theo định dạng SIEM, để người dùng thấy đúng cái sẽ được gửi (S-LOG-3): đúng từng byte của formatCEF/formatSyslog/formatJSON trong modules/logs (siem_format.go) cho một finding.created, tên hộp "vedette". */
export function siemSample(format: 'syslog' | 'cef' | 'json'): string {
  if (format === 'cef') {
    return 'CEF:0|Vedette|Vedette|1.0|finding.created|Exploited vulnerability matches a device|7|rt=1794218400000 dvchost=vedette externalId=f-1 cs1Label=asset_id cs1=a-nas02 cs2Label=cve cs2=CVE-2022-27593 cs3Label=basis cs3=kev'
  }
  if (format === 'json') {
    return JSON.stringify({ asset_id: 'a-nas02', basis: 'kev', box: 'vedette', cve: 'CVE-2022-27593', event: 'finding.created', id: 'f-1', severity: 'high', time: '2026-11-09T10:00:00.000Z' }, null, 2)
  }
  return '<131>1 2026-11-09T10:00:00.000Z vedette vedette - finding.created [vedette@32473 id="f-1" asset_id="a-nas02" cve="CVE-2022-27593" basis="kev"] finding.created severity=high'
}
