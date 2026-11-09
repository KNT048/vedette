// Mã loại nguồn log (D-18: contract.ts dùng danh sách này làm enum). Nội dung hướng dẫn từng loại nằm ở catalog.ts.
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
