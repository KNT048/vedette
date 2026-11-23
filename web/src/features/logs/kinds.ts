// Log source type codes (contract.ts uses this list as an enum). The guidance for each type is in catalog.ts.
export const KIND_IDS = [
  'fortigate', 'sophos', 'paloalto', 'cisco-asa', 'cisco-ftd', 'cisco-ios', 'meraki', 'mikrotik', 'pfsense', 'opnsense', 'sonicwall', 'watchguard',
  'checkpoint', 'juniper-srx', 'huawei', 'draytek', 'ubiquiti', 'zyxel', 'omada',
  'ivanti', 'netscaler', 'openvpn-as',
  'windows', 'linux-rsyslog', 'linux-journald', 'syslog-ng',
  'synology', 'qnap', 'esxi', 'proxmox',
  'suricata', 'zeek', 'wazuh', 'crowdsec',
  'nginx', 'apache', 'squid', 'pihole', 'bind', 'windows-dns', 'postfix',
  'cisco-switch', 'aruba-cx', 'hpe-procurve', 'hpe-comware', 'unifi',
  'syslog-generic', 'cef-leef',
] as const
export type KindId = (typeof KIND_IDS)[number]
