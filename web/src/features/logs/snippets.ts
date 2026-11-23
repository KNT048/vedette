export const BOX_PLACEHOLDER = '<VEDETTE_BOX_IP>'
// SIEM forwarding record samples (S-LOG-3). The config snippets by device type are in catalog.ts.
// CEF (ArcSight, Implementing ArcSight CEF): CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension.
// Syslog in RFC 5424 form: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG.

/** A sample record in the SIEM format, so the user sees exactly what will be sent (S-LOG-3): byte for byte what formatCEF/formatSyslog/formatJSON in modules/logs (siem_format.go) produce for one finding.created, box name "vedette". */
export function siemSample(format: 'syslog' | 'cef' | 'json'): string {
  if (format === 'cef') {
    return 'CEF:0|Vedette|Vedette|1.0|finding.created|Exploited vulnerability matches a device|7|rt=1794218400000 dvchost=vedette externalId=f-1 cs1Label=asset_id cs1=a-nas02 cs2Label=cve cs2=CVE-2022-27593 cs3Label=basis cs3=kev'
  }
  if (format === 'json') {
    return '{"asset_id":"a-nas02","basis":"kev","box":"vedette","cve":"CVE-2022-27593","event":"finding.created","id":"f-1","severity":"high","time":"2026-11-09T10:00:00.000Z"}'
  }
  return '<131>1 2026-11-09T10:00:00.000Z vedette vedette - finding.created [vedette@32473 id="f-1" asset_id="a-nas02" cve="CVE-2022-27593" basis="kev"] finding.created severity=high'
}
