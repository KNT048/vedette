// Danh mục sản phẩm cho khai tay (S-INV-2). Hai nguồn, gộp một danh sách:
// 1) TOÀN BỘ cặp hãng/sản phẩm từng có trong CISA KEV (src/mocks/fixtures/kev-products.json, sinh bằng `pnpm fixtures`) — mỗi cặp chọn được,
//    khoá khớp là đúng `hãng|sản phẩm` viết thường của KEV nên cảnh báo khớp chính xác. Nguồn: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (CC0).
// 2) Danh sách tuyển chọn: sản phẩm doanh nghiệp nhỏ ở Việt Nam hay dùng, gọi bằng tên thương mại. Mỗi mục trỏ tới khoá KEV thật (kevMatch) nếu KEV có,
//    không thì dùng khoá kiểu CPE `hãng|sản phẩm` (chưa có lỗ hổng bị khai thác nhưng khi có sẽ khớp). Bản thật: sinh từ feeds/cpe-dict (DATA_PIPELINE §3).
// Id ổn định: mục tuyển chọn có id cố định; mục KEV có id `kev:<hãng>:<sản phẩm>` (slug).
import kevProducts from '@/mocks/fixtures/kev-products.json'
import type { AssetKind } from '@/lib/types'

export interface CatalogEntry {
  id: string; display: string; category: string; hint: string; vendor: string; product: string; kind: AssetKind
  kev: string[]; aliases: string[]; version_hint: string; kev_count: number; curated: boolean; order: number
}

interface KevRow { vendor: string; product: string; kev_count: number; last_added: string; ransomware: boolean }
const KEV = kevProducts as KevRow[]
const kevKey = (r: { vendor: string; product: string }) => `${r.vendor}|${r.product}`.toLowerCase()
const kevCountOf = new Map(KEV.map((r) => [kevKey(r), r.kev_count]))

/** Bỏ dấu, hạ chữ thường, mọi ký tự lạ thành khoảng trắng: "Tường lửa FortiGate-60F" → "tuong lua fortigate 60f". */
export const fold = (s: string) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/g, 'd').replace(/[^a-z0-9]+/g, ' ').trim()
const slug = (s: string) => fold(s).replace(/ /g, '-')

const CAT = {
  fw: 'Firewall and router', net: 'Network device', vpn: 'VPN and remote access', nas: 'NAS and storage', virt: 'Virtualization', ms: 'Microsoft',
  web: 'Website and web app', mail: 'Email', dev: 'Developer and IT tools', backup: 'Backup', rs: 'Remote support', cam: 'Camera and recorder', prn: 'Printer',
  os: 'Operating system', db: 'Database', biz: 'Business software', sec: 'Security software', other: 'Other',
} as const

type K = AssetKind
type Cur = [display: string, category: string, kind: K, vendor: string, product: string, aliases: string, hint: string, kevMatch?: string[]]
const c = (...a: Cur): Cur => a

// Thứ tự trong mảng = độ phổ biến (khi chưa gõ gì, hiện theo thứ tự này). Aliases ngăn bằng dấu phẩy, có cả tên gọi tiếng Việt không dấu và số model hay gặp.
const CURATED: Cur[] = [
  // Tường lửa, router
  c('FortiGate', CAT.fw, 'firewall', 'Fortinet', 'FortiOS', 'fortinet, fortios, forti, fg, 40f, 60f, 70f, 80f, 100f, 200f, ssl vpn, firewall, tuong lua', 'For example 7.2.5. See Dashboard, System Information.', ['fortinet|fortios', 'fortinet|multiple products']),
  c('MikroTik RouterOS', CAT.fw, 'router', 'MikroTik', 'RouterOS', 'mikrotik, routeros, hap, rb, ccr, router', 'For example 7.14. Type /system resource print in Terminal.', ['mikrotik|routeros']),
  c('Cisco ASA / Firepower (FTD)', CAT.fw, 'firewall', 'Cisco', 'Adaptive Security Appliance (ASA)', 'cisco, asa, ftd, firepower, 5506, 5508, tuong lua', 'For example 9.16(4). Run show version.', ['cisco|adaptive security appliance', 'cisco|secure firewall', 'cisco|firepower']),
  c('Cisco IOS / IOS XE router or switch', CAT.net, 'router', 'Cisco', 'IOS XE', 'cisco, ios, catalyst, isr, switch, router', 'For example 17.9.4. Run show version.', ['cisco|ios']),
  c('Cisco RV series router (small business)', CAT.fw, 'router', 'Cisco', 'RV Series Routers', 'cisco, rv160, rv260, rv340, rv345, rv320, router', 'For example 1.0.3.55.', ['cisco|rv', 'cisco|small business rv']),
  c('Cisco Meraki', CAT.fw, 'router', 'Cisco', 'Meraki', 'meraki, mx64, mx68, mr, ms', 'Firmware shown in the Meraki dashboard.'),
  c('Palo Alto PAN-OS firewall', CAT.fw, 'firewall', 'Palo Alto Networks', 'PAN-OS', 'palo alto, panos, pan os, globalprotect, pa-220, pa-440, tuong lua', 'For example 10.2.8.', ['palo alto networks|pan-os']),
  c('Sophos XG / XGS firewall', CAT.fw, 'firewall', 'Sophos', 'SFOS', 'sophos, xg, xgs, sfos, cyberoam, firewall, tuong lua', 'For example SFOS 20.0.', ['sophos|sfos', 'sophos|xg firewall', 'sophos|firewall', 'sophos|cyberoamos']),
  c('SonicWall firewall (SonicOS)', CAT.fw, 'firewall', 'SonicWall', 'SonicOS', 'sonicwall, sonicos, tz, nsa, firewall', 'For example 7.0.1.', ['sonicwall|sonicos']),
  c('SonicWall SMA remote access', CAT.vpn, 'server', 'SonicWall', 'SMA 100', 'sonicwall, sma, sma100, sra, ssl vpn', 'For example 10.2.1.', ['sonicwall|sma', 'sonicwall|secure remote access', 'sonicwall|sslvpn']),
  c('WatchGuard Firebox', CAT.fw, 'firewall', 'WatchGuard', 'Firebox', 'watchguard, firebox, fireware, xtm, firewall', 'For example Fireware 12.10.', ['watchguard|firebox']),
  c('Check Point Security Gateway', CAT.fw, 'firewall', 'Check Point', 'Security Gateway', 'check point, checkpoint, quantum, gaia, firewall', 'For example R81.20.', ['check point|']),
  c('Juniper SRX / Junos', CAT.fw, 'firewall', 'Juniper', 'Junos OS', 'juniper, srx, junos, ex, firewall', 'For example 22.4R2.', ['juniper|junos']),
  c('pfSense', CAT.fw, 'firewall', 'Netgate', 'pfSense', 'pfsense, netgate, firewall', 'For example 2.7.2.'),
  c('OPNsense', CAT.fw, 'firewall', 'Deciso', 'OPNsense', 'opnsense, firewall', 'For example 24.1.'),
  c('DrayTek Vigor router', CAT.fw, 'router', 'DrayTek', 'Vigor Routers', 'draytek, vigor, 2960, 2925, 2927, 3900, router', 'For example 4.4.5. See System Status.', ['draytek|vigor']),
  c('TP-Link router (Archer, ER)', CAT.fw, 'router', 'TP-Link', 'Archer', 'tp-link, tplink, archer, ax21, tl-wr841n, er605, er7206, router, wifi', 'Firmware version on the router web page.', ['tp-link|']),
  c('TP-Link Omada', CAT.net, 'ap', 'TP-Link', 'Omada', 'omada, eap, tp-link, tplink, wifi, access point', 'Controller version in Omada settings.'),
  c('Ubiquiti UniFi', CAT.net, 'ap', 'Ubiquiti', 'UniFi OS', 'ubiquiti, unifi, ubnt, uap, u6, udm, dream machine, wifi, access point', 'For example UniFi OS 3.2.', ['ubiquiti|unifi']),
  c('Ubiquiti EdgeRouter / airOS', CAT.fw, 'router', 'Ubiquiti', 'AirOS', 'ubiquiti, edgerouter, edgeos, airos, nanostation, router', 'For example 8.7.11.', ['ubiquiti|airos']),
  c('Zyxel firewall (USG, ATP, USG FLEX)', CAT.fw, 'firewall', 'Zyxel', 'Firewalls', 'zyxel, usg, atp, flex, zywall, firewall, tuong lua', 'For example ZLD 5.37.', ['zyxel|multiple firewalls']),
  c('Zyxel router / DSL modem', CAT.net, 'router', 'Zyxel', 'DSL CPE', 'zyxel, vmg, emg, p660, modem, router', 'Firmware version on the device web page.', ['zyxel|dsl cpe', 'zyxel|emg', 'zyxel|p660']),
  c('Huawei USG / AR router', CAT.fw, 'router', 'Huawei', 'USG', 'huawei, usg, ar, vrp, router, firewall', 'For example VRP V800R021.'),
  c('Ruijie / Reyee device', CAT.net, 'router', 'Ruijie', 'Reyee', 'ruijie, reyee, rg-ew, rg-nbs, wifi, switch, router', 'Firmware version on the device web page.'),
  c('Netgear router or access point', CAT.net, 'router', 'NETGEAR', 'Routers', 'netgear, nighthawk, router, wifi', 'Firmware version on the device web page.', ['netgear|']),
  c('D-Link router, NAS or camera', CAT.net, 'router', 'D-Link', 'Routers', 'd-link, dlink, dir, dns, dcs, router, nas, camera', 'Firmware version on the device web page.', ['d-link|']),
  c('Tenda router', CAT.net, 'router', 'Tenda', 'Routers', 'tenda, ac10, ac15, router, wifi', 'Firmware version on the device web page.', ['tenda|']),
  c('Home or ISP modem (Viettel, VNPT, FPT)', CAT.net, 'router', 'ISP', 'Modem', 'viettel, vnpt, fpt, gpon, onu, modem, router, wifi, nha mang', 'Model and firmware on the device label or web page.'),
  c('Linksys router', CAT.net, 'router', 'Linksys', 'Routers', 'linksys, velop, router, wifi', 'Firmware version on the router web page.'),
  c('Juniper / Aruba / HPE switch', CAT.net, 'switch', 'HPE', 'ProCurve', 'aruba, procurve, hpe, switch', 'Run show version.', ['hewlett packard (hp)|procurve']),
  c('Zyxel GS series switch', CAT.net, 'switch', 'Zyxel', 'GS1900 Series Switches', 'zyxel, gs1900, switch', 'Firmware version on the device web page.', ['zyxel|gs1900']),
  // VPN
  c('Ivanti Connect Secure (Pulse Secure VPN)', CAT.vpn, 'server', 'Ivanti', 'Connect Secure', 'ivanti, pulse, pulse secure, connect secure, vpn, ics', 'For example 22.7R2.', ['ivanti|connect secure', 'ivanti|pulse connect secure', 'pulse secure|']),
  c('Citrix NetScaler (ADC / Gateway)', CAT.vpn, 'server', 'Citrix', 'NetScaler', 'citrix, netscaler, adc, gateway, vpn', 'For example 13.1-49.', ['citrix|netscaler', 'citrix|application delivery controller', 'citrix|sd-wan and netscaler']),
  c('Cisco AnyConnect / Secure Client', CAT.vpn, 'pc', 'Cisco', 'AnyConnect', 'cisco, anyconnect, secure client, vpn', 'For example 4.10.', ['cisco|anyconnect']),
  c('Fortinet FortiClient / SSL VPN', CAT.vpn, 'pc', 'Fortinet', 'FortiClient', 'forticlient, fortinet, ssl vpn, vpn', 'For example 7.2.', ['fortinet|forticlient', 'fortinet|fortios and fortiproxy ssl-vpn']),
  c('OpenVPN Access Server', CAT.vpn, 'server', 'OpenVPN', 'Access Server', 'openvpn, vpn', 'For example 2.13.'),
  c('WireGuard', CAT.vpn, 'server', 'WireGuard', 'WireGuard', 'wireguard, vpn', 'For example 1.0.'),
  c('F5 BIG-IP', CAT.vpn, 'server', 'F5', 'BIG-IP', 'f5, big-ip, bigip, load balancer', 'For example 16.1.4.', ['f5|big-ip']),
  c('Kemp LoadMaster', CAT.vpn, 'server', 'Progress', 'LoadMaster', 'kemp, loadmaster, load balancer', 'For example 7.2.60.', ['progress|loadmaster', 'progress|kemp loadmaster']),
  // NAS
  c('Synology NAS (DSM)', CAT.nas, 'nas', 'Synology', 'DiskStation Manager', 'synology, dsm, diskstation, nas, ds220, ds920, ds923, ds1522, rackstation, may luu tru', 'For example 7.2. Control Panel, Info Center.', ['synology|']),
  c('QNAP NAS (QTS / QuTS hero)', CAT.nas, 'nas', 'QNAP', 'QTS', 'qnap, qts, quts, ts-453, ts-464, nas, may luu tru', 'For example 5.1.5. Control Panel, System Status.', ['qnap|qts', 'qnap|network attached storage', 'qnap|qnap network-attached storage']),
  c('QNAP Photo Station', CAT.nas, 'nas', 'QNAP', 'Photo Station', 'qnap, photo, anh', 'For example 6.0.20. See App Center.', ['qnap|photo station']),
  c('QNAP VioStor NVR', CAT.cam, 'nvr', 'QNAP', 'VioStor NVR', 'qnap, viostor, nvr, camera', 'For example 5.1.', ['qnap|viostor']),
  c('Asustor NAS (ADM)', CAT.nas, 'nas', 'Asustor', 'ADM', 'asustor, adm, nas', 'For example 4.2.'),
  c('TrueNAS', CAT.nas, 'nas', 'iXsystems', 'TrueNAS', 'truenas, freenas, ixsystems, nas', 'For example 13.0.'),
  c('Western Digital My Cloud', CAT.nas, 'nas', 'Western Digital', 'My Cloud', 'wd, western digital, my cloud, nas', 'For example 5.27.', ['western digital|']),
  c('TerraMaster NAS (TOS)', CAT.nas, 'nas', 'TerraMaster', 'TerraMaster OS', 'terramaster, tos, nas', 'For example 5.1.', ['terramaster|']),
  c('Zyxel NAS', CAT.nas, 'nas', 'Zyxel', 'NAS', 'zyxel, nas', 'Firmware version on the device web page.', ['zyxel|multiple network-attached storage']),
  // Ảo hoá
  c('VMware ESXi', CAT.virt, 'server', 'VMware', 'ESXi', 'vmware, esxi, esx, ao hoa, virtualization, hypervisor', 'For example 7.0 U3.', ['vmware|esxi', 'broadcom|vmware esx']),
  c('VMware vCenter Server', CAT.virt, 'server', 'VMware', 'vCenter Server', 'vmware, vcenter, vsphere', 'For example 8.0 U2.', ['vmware|vcenter', 'broadcom|vmware vcenter']),
  c('Proxmox VE', CAT.virt, 'server', 'Proxmox', 'Proxmox VE', 'proxmox, pve, ao hoa, virtualization, hypervisor', 'For example 8.1.'),
  c('Microsoft Hyper-V', CAT.virt, 'server', 'Microsoft', 'Hyper-V', 'hyper-v, hyperv, ao hoa, virtualization', 'Runs on Windows Server. Use the Windows Server version.', ['microsoft|hyper-v']),
  c('Citrix Hypervisor (XenServer)', CAT.virt, 'server', 'Citrix', 'Hypervisor', 'citrix, xenserver, xen, hypervisor', 'For example 8.2 LTSR.'),
  c('Oracle VirtualBox', CAT.virt, 'pc', 'Oracle', 'VirtualBox', 'oracle, virtualbox, vbox', 'For example 7.0.', ['oracle|virtualbox']),
  // Microsoft
  c('Windows 11', CAT.ms, 'pc', 'Microsoft', 'Windows 11', 'windows, win11, may tinh, laptop, pc', 'For example 23H2. Type winver in Run.', ['microsoft|windows']),
  c('Windows 10', CAT.ms, 'pc', 'Microsoft', 'Windows 10', 'windows, win10, may tinh, laptop, pc', 'For example 22H2. Type winver in Run.', ['microsoft|windows']),
  c('Windows Server 2025', CAT.ms, 'server', 'Microsoft', 'Windows Server 2025', 'windows server, 2025, may chu', 'For example 24H2.', ['microsoft|windows']),
  c('Windows Server 2022', CAT.ms, 'server', 'Microsoft', 'Windows Server 2022', 'windows server, 2022, may chu', 'For example 21H2.', ['microsoft|windows']),
  c('Windows Server 2019', CAT.ms, 'server', 'Microsoft', 'Windows Server 2019', 'windows server, 2019, may chu', 'For example 1809.', ['microsoft|windows']),
  c('Windows Server 2016', CAT.ms, 'server', 'Microsoft', 'Windows Server 2016', 'windows server, 2016, may chu', 'For example 1607.', ['microsoft|windows']),
  c('Windows Server 2012 / 2012 R2', CAT.ms, 'server', 'Microsoft', 'Windows Server 2012', 'windows server, 2012, r2, may chu', 'Support ended in October 2023. Plan to upgrade.', ['microsoft|windows']),
  c('Windows 7 / Server 2008 (unsupported)', CAT.ms, 'pc', 'Microsoft', 'Windows 7', 'windows 7, win7, server 2008, xp, cu', 'No longer supported by Microsoft.', ['microsoft|windows']),
  c('Microsoft Exchange Server', CAT.mail, 'server', 'Microsoft', 'Exchange Server', 'exchange, owa, email, mail, may chu thu', 'For example 2019 CU14.', ['microsoft|exchange']),
  c('Microsoft SharePoint Server', CAT.ms, 'server', 'Microsoft', 'SharePoint', 'sharepoint, portal', 'For example 2019.', ['microsoft|sharepoint', 'microsoft|.net framework, sharepoint']),
  c('Microsoft SQL Server', CAT.db, 'server', 'Microsoft', 'SQL Server', 'sql server, mssql, database, csdl', 'For example 2019.', ['microsoft|sql server']),
  c('Microsoft IIS (web server)', CAT.web, 'server', 'Microsoft', 'Internet Information Services (IIS)', 'iis, web server, internet information services', 'Version follows Windows Server.', ['microsoft|internet information services', 'microsoft|http.sys', 'microsoft|http protocol stack']),
  c('Active Directory / domain controller', CAT.ms, 'server', 'Microsoft', 'Active Directory', 'active directory, ad, domain controller, dc, kerberos, ldap', 'Version follows Windows Server.', ['microsoft|active directory', 'microsoft|netlogon', 'microsoft|kerberos']),
  c('Microsoft Office (desktop)', CAT.ms, 'pc', 'Microsoft', 'Office', 'office, word, excel, outlook, powerpoint', 'For example 2021 or Microsoft 365 Apps.', ['microsoft|office', 'microsoft|excel']),
  c('Microsoft Edge / Internet Explorer', CAT.ms, 'pc', 'Microsoft', 'Edge', 'edge, internet explorer, ie, browser', 'For example 120.', ['microsoft|edge', 'microsoft|internet explorer']),
  // Web
  c('WordPress', CAT.web, 'web', 'WordPress', 'WordPress Core', 'wordpress, wp, website, web, plugin', 'For example 6.5.2. Shown at the bottom right of the admin page.', ['wordpress|']),
  c('Joomla', CAT.web, 'web', 'Joomla!', 'Joomla!', 'joomla, website, web', 'For example 5.0.', ['joomla!|joomla!']),
  c('Drupal', CAT.web, 'web', 'Drupal', 'Drupal core', 'drupal, website, web', 'For example 10.2.', ['drupal|']),
  c('Magento / Adobe Commerce', CAT.web, 'web', 'Adobe', 'Commerce and Magento', 'magento, adobe commerce, shop, ban hang, ecommerce', 'For example 2.4.6.', ['adobe|commerce and magento']),
  c('PrestaShop', CAT.web, 'web', 'PrestaShop', 'PrestaShop', 'prestashop, shop, ban hang, ecommerce', 'For example 8.1.'),
  c('WooCommerce', CAT.web, 'web', 'Automattic', 'WooCommerce', 'woocommerce, shop, ban hang, wordpress', 'For example 8.5.'),
  c('Moodle', CAT.web, 'web', 'Moodle', 'Moodle', 'moodle, lms, e-learning, elearning', 'For example 4.3.'),
  c('Apache HTTP Server', CAT.web, 'server', 'Apache', 'HTTP Server', 'apache, httpd, web server', 'For example 2.4.58.', ['apache|http server']),
  c('nginx', CAT.web, 'server', 'F5', 'nginx', 'nginx, web server, reverse proxy', 'For example 1.24.'),
  c('Apache Tomcat', CAT.web, 'server', 'Apache', 'Tomcat', 'tomcat, java, web', 'For example 9.0.85.', ['apache|tomcat']),
  c('Apache Struts', CAT.web, 'web', 'Apache', 'Struts', 'struts, java, web', 'For example 2.5.30.', ['apache|struts']),
  c('PHP', CAT.web, 'web', 'PHP Group', 'PHP', 'php, web', 'For example 8.1.', ['php group|php', 'php|php']),
  c('phpMyAdmin', CAT.web, 'web', 'phpMyAdmin', 'phpMyAdmin', 'phpmyadmin, database, mysql', 'For example 5.2.1.', ['phpmyadmin|']),
  c('cPanel / WHM', CAT.web, 'server', 'cPanel', 'cPanel & WHM', 'cpanel, whm, hosting', 'For example 118.'),
  c('Plesk', CAT.web, 'server', 'Plesk', 'Plesk Obsidian', 'plesk, hosting', 'For example 18.0.'),
  c('Zimbra Collaboration', CAT.mail, 'server', 'Synacor', 'Zimbra Collaboration', 'zimbra, mail, email, webmail', 'For example 10.0.'),
  c('Roundcube Webmail', CAT.mail, 'web', 'Roundcube', 'Roundcube Webmail', 'roundcube, webmail, email', 'For example 1.6.', ['roundcube|']),
  c('Jenkins', CAT.dev, 'server', 'Jenkins', 'Jenkins', 'jenkins, ci, cd', 'For example 2.440.', ['jenkins|jenkins']),
  c('GitLab (self-hosted)', CAT.dev, 'server', 'GitLab', 'GitLab', 'gitlab, git', 'For example 16.9.1. See the Help page.', ['gitlab|']),
  c('Atlassian Jira', CAT.dev, 'server', 'Atlassian', 'Jira Server and Data Center', 'jira, atlassian', 'For example 9.12.', ['atlassian|jira']),
  c('Atlassian Confluence', CAT.dev, 'server', 'Atlassian', 'Confluence', 'confluence, wiki, atlassian', 'For example 8.5.', ['atlassian|confluence']),
  c('Atlassian Bitbucket Server', CAT.dev, 'server', 'Atlassian', 'Bitbucket Server and Data Center', 'bitbucket, atlassian, git', 'For example 8.9.', ['atlassian|bitbucket']),
  c('SolarWinds Orion / Serv-U', CAT.dev, 'server', 'SolarWinds', 'Orion', 'solarwinds, orion, serv-u, monitoring', 'For example 2023.4.', ['solarwinds|']),
  c('Progress MOVEit Transfer', CAT.dev, 'server', 'Progress', 'MOVEit Transfer', 'moveit, file transfer', 'For example 2023.1.', ['progress|moveit']),
  c('Oracle WebLogic Server', CAT.web, 'server', 'Oracle', 'WebLogic Server', 'weblogic, oracle, java', 'For example 14.1.1.', ['oracle|weblogic']),
  c('Oracle Java (JRE / JDK)', CAT.dev, 'pc', 'Oracle', 'Java SE', 'java, jre, jdk, oracle', 'For example 17.0.9.', ['oracle|java']),
  c('MySQL / MariaDB', CAT.db, 'server', 'Oracle', 'MySQL', 'mysql, mariadb, database, csdl', 'For example 8.0.', ['oracle|mysql']),
  c('PostgreSQL', CAT.db, 'server', 'PostgreSQL', 'PostgreSQL', 'postgres, postgresql, database, csdl', 'For example 16.1.'),
  c('Redis', CAT.db, 'server', 'Redis', 'Redis', 'redis, cache, database', 'For example 7.2.'),
  c('Elasticsearch', CAT.db, 'server', 'Elastic', 'Elasticsearch', 'elasticsearch, elk, elastic', 'For example 8.11.'),
  c('Docker Engine', CAT.dev, 'server', 'Docker', 'Docker Engine', 'docker, container', 'For example 25.0.'),
  c('Kubernetes', CAT.dev, 'server', 'Kubernetes', 'Kubernetes', 'kubernetes, k8s, container', 'For example 1.29.'),
  // Sao lưu
  c('Veeam Backup & Replication', CAT.backup, 'server', 'Veeam', 'Backup & Replication', 'veeam, backup, sao luu', 'For example 12.1.', ['veeam|']),
  c('Acronis Cyber Protect / Backup', CAT.backup, 'server', 'Acronis', 'Backup', 'acronis, backup, cyber protect, sao luu', 'For example 15.0.', ['acronis|backup', 'acronis|cyber infrastructure']),
  c('Synology Active Backup', CAT.backup, 'nas', 'Synology', 'Active Backup', 'synology, active backup, backup, sao luu', 'For example 2.7.'),
  c('Veritas Backup Exec', CAT.backup, 'server', 'Veritas', 'Backup Exec', 'veritas, backup exec, backup, sao luu', 'For example 22.', ['veritas|']),
  // Hỗ trợ từ xa
  c('TeamViewer', CAT.rs, 'pc', 'TeamViewer', 'Desktop', 'teamviewer, remote, ho tro tu xa', 'For example 15.50. Help, About TeamViewer.', ['teamviewer|']),
  c('AnyDesk', CAT.rs, 'pc', 'AnyDesk', 'AnyDesk', 'anydesk, remote, ho tro tu xa', 'For example 8.0.'),
  c('ConnectWise ScreenConnect', CAT.rs, 'server', 'ConnectWise', 'ScreenConnect', 'connectwise, screenconnect, remote, ho tro tu xa', 'For example 23.9.', ['connectwise|']),
  c('BeyondTrust Remote Support', CAT.rs, 'server', 'BeyondTrust', 'Remote Support', 'beyondtrust, bomgar, remote support, privileged remote access', 'For example 23.3.', ['beyondtrust|']),
  c('Remote Desktop (RDP)', CAT.rs, 'server', 'Microsoft', 'Remote Desktop Services', 'rdp, remote desktop, terminal services, rds', 'Version follows Windows.', ['microsoft|remote desktop']),
  c('OpenSSH', CAT.rs, 'server', 'OpenBSD', 'OpenSSH', 'openssh, ssh, sshd', 'For example 9.6. Run ssh -V.', ['openbsd|openssh']),
  // Camera
  c('Hikvision camera / NVR', CAT.cam, 'camera', 'Hikvision', 'IP Camera firmware', 'hikvision, hik, ds-2cd, ds-7608, camera, nvr, dau ghi, ezviz', 'For example V5.7.3. See Device Information on the web page.', ['hikvision|']),
  c('Dahua camera / NVR', CAT.cam, 'camera', 'Dahua', 'IP Camera Firmware', 'dahua, imou, dh-ipc, camera, nvr, dau ghi', 'For example 2.800.', ['dahua|']),
  c('KBVision camera', CAT.cam, 'camera', 'KBVision', 'IP Camera', 'kbvision, kbvision camera, kx, camera, nvr', 'Version on the device web page.'),
  c('Ezviz camera', CAT.cam, 'camera', 'Ezviz', 'Camera', 'ezviz, camera, wifi camera', 'Version in the Ezviz app.'),
  c('Imou camera', CAT.cam, 'camera', 'Imou', 'Camera', 'imou, camera, wifi camera', 'Version in the Imou app.'),
  c('Axis camera', CAT.cam, 'camera', 'Axis', 'Network Camera', 'axis, camera', 'For example 11.8.'),
  c('Uniview (UNV) camera', CAT.cam, 'camera', 'Uniview', 'IP Camera', 'uniview, unv, camera, nvr', 'Version on the device web page.'),
  c('Samsung MagicINFO', CAT.cam, 'server', 'Samsung', 'MagicINFO 9 Server', 'samsung, magicinfo, signage', 'For example 9.', ['samsung|magicinfo']),
  // Máy in
  c('HP printer (LaserJet / OfficeJet)', CAT.prn, 'printer', 'HP', 'Printer', 'hp, laserjet, officejet, m404, m428, printer, may in', 'Firmware on the printer web page or report page.'),
  c('Canon printer (imageRUNNER / LBP)', CAT.prn, 'printer', 'Canon', 'Printer', 'canon, imagerunner, lbp, mf, printer, may in', 'Firmware on the printer web page.'),
  c('Brother printer', CAT.prn, 'printer', 'Brother', 'Printer', 'brother, hl, mfc, dcp, printer, may in', 'Firmware on the printer web page.'),
  c('Epson printer', CAT.prn, 'printer', 'Epson', 'Printer', 'epson, l3110, l3250, printer, may in', 'Firmware on the printer web page.'),
  c('Ricoh printer / copier', CAT.prn, 'printer', 'Ricoh', 'Printer', 'ricoh, mp, printer, copier, may photocopy, may in', 'Firmware on the printer web page.'),
  c('Xerox printer / copier', CAT.prn, 'printer', 'Xerox', 'Printer', 'xerox, workcentre, printer, copier, may in', 'Firmware on the printer web page.'),
  c('Kyocera printer / copier', CAT.prn, 'printer', 'Kyocera', 'Printer', 'kyocera, ecosys, taskalfa, printer, may in', 'Firmware on the printer web page.'),
  c('Samsung / HP Xpress printer', CAT.prn, 'printer', 'Samsung', 'Printer', 'samsung, xpress, printer, may in', 'Firmware on the printer web page.'),
  // Hệ điều hành
  c('Ubuntu Linux', CAT.os, 'server', 'Canonical', 'Ubuntu Linux', 'ubuntu, linux, may chu', 'For example 22.04. Run lsb_release -a.', ['linux|kernel']),
  c('Debian Linux', CAT.os, 'server', 'Debian', 'Debian Linux', 'debian, linux, may chu', 'For example 12. Run cat /etc/os-release.', ['linux|kernel']),
  c('CentOS / Rocky / AlmaLinux / RHEL', CAT.os, 'server', 'Red Hat', 'Enterprise Linux', 'centos, rocky, alma, almalinux, rhel, red hat, linux, may chu', 'For example 9.3. Run cat /etc/redhat-release.', ['linux|kernel']),
  c('Linux kernel', CAT.os, 'server', 'Linux', 'Kernel', 'linux, kernel, uname', 'For example 5.15. Run uname -r.', ['linux|kernel']),
  c('macOS', CAT.os, 'pc', 'Apple', 'macOS', 'macos, mac, macbook, imac, apple', 'For example 14.5.', ['apple|macos']),
  c('iOS / iPadOS', CAT.os, 'iot', 'Apple', 'iOS', 'ios, ipados, iphone, ipad, apple', 'For example 17.4.', ['apple|ios']),
  c('Android (phones, tablets)', CAT.os, 'iot', 'Google', 'Android', 'android, phone, tablet, dien thoai', 'For example 14.'),
  c('Google Chrome / Chromium', CAT.os, 'pc', 'Google', 'Chrome', 'chrome, chromium, browser', 'For example 122.', ['google|chrome']),
  // Phần mềm hay gặp ở Việt Nam
  c('MISA SME (on-premise)', CAT.biz, 'server', 'MISA', 'MISA SME', 'misa, sme, ke toan, accounting', 'For example 2023 R20.'),
  c('MISA AMIS', CAT.biz, 'server', 'MISA', 'AMIS', 'misa, amis, erp, crm', 'Version on the About page.'),
  c('Fast Accounting', CAT.biz, 'server', 'Fast Software', 'Fast Accounting', 'fast, fast accounting, ke toan, accounting', 'For example 11.'),
  c('Bkav AntiVirus / Bkav Pro', CAT.sec, 'pc', 'Bkav', 'Bkav Pro', 'bkav, antivirus, diet virus, bao mat', 'For example 7.'),
  c('Microsoft Defender Antivirus', CAT.sec, 'pc', 'Microsoft', 'Defender', 'defender, antivirus, windows security', 'Version in Windows Security, About.', ['microsoft|defender', 'microsoft|malware protection engine']),
  c('Kaspersky', CAT.sec, 'pc', 'Kaspersky', 'Endpoint Security', 'kaspersky, antivirus, endpoint security', 'For example 12.', ['kaspersky|']),
  c('ESET', CAT.sec, 'pc', 'ESET', 'Endpoint Security', 'eset, nod32, antivirus, endpoint security', 'For example 10.'),
  c('Fortinet FortiMail / FortiWeb / FortiManager', CAT.sec, 'server', 'Fortinet', 'FortiManager', 'fortimail, fortiweb, fortimanager, fortisandbox, fortinet', 'For example 7.2.', ['fortinet|fortimail', 'fortinet|fortiweb', 'fortinet|fortimanager', 'fortinet|fortisandbox', 'fortinet|forticlient ems']),
  c('Adobe Acrobat / Reader', CAT.biz, 'pc', 'Adobe', 'Acrobat and Reader', 'adobe, acrobat, reader, pdf', 'For example 24.1.', ['adobe|acrobat', 'adobe|reader']),
  c('Adobe ColdFusion', CAT.web, 'server', 'Adobe', 'ColdFusion', 'adobe, coldfusion', 'For example 2023.', ['adobe|coldfusion']),
  c('7-Zip / WinRAR', CAT.biz, 'pc', '7-Zip', '7-Zip', '7zip, winrar, zip, nen file', 'For example 23.01.', ['7-zip|', 'rarlab|']),
  c('Plex Media Server', CAT.biz, 'server', 'Plex', 'Media Server', 'plex, media server', 'For example 1.41.', ['plex|']),
  c('BIND DNS', CAT.net, 'server', 'ISC', 'BIND', 'bind, dns, named', 'For example 9.18.', ['isc|bind']),
  c('ProFTPD / vsFTPd (FTP server)', CAT.net, 'server', 'ProFTPD', 'ProFTPD', 'proftpd, ftp, vsftpd', 'For example 1.3.8.', ['proftpd|']),
  c('SAP NetWeaver', CAT.biz, 'server', 'SAP', 'NetWeaver', 'sap, netweaver, erp', 'For example 7.5.', ['sap|netweaver']),
  c('Citrix Virtual Apps / StoreFront', CAT.vpn, 'server', 'Citrix', 'StoreFront Server', 'citrix, storefront, virtual apps, xenapp', 'For example 2203 LTSR.', ['citrix|storefront']),
]

function kevKeysFor(matches: string[] | undefined, fallback: string): string[] {
  if (!matches?.length) return [fallback]
  const keys = new Set<string>()
  for (const m of matches) {
    const [v = '', p = ''] = m.toLowerCase().split('|')
    for (const r of KEV) if (r.vendor.toLowerCase().includes(v) && (!p || r.product.toLowerCase().includes(p))) keys.add(kevKey(r))
  }
  return keys.size ? [...keys] : [fallback]
}
const sumKev = (keys: string[]) => keys.reduce((n, k) => n + (kevCountOf.get(k) ?? 0), 0)

const curated: CatalogEntry[] = CURATED.map(([display, category, kind, vendor, product, aliases, version_hint, match], i) => {
  const kev = kevKeysFor(match, `${vendor}|${product}`.toLowerCase())
  return {
    id: slug(display), display, category, hint: `${vendor} ${product}`, vendor, product, kind, kev,
    aliases: aliases.split(',').map((s) => s.trim()).filter(Boolean), version_hint, kev_count: sumKev(kev), curated: true, order: i,
  }
})

// Đoán loại thiết bị từ tên khi KEV không nói; sai thì người dùng đổi loại ở trang chi tiết.
const KIND_HINT: [RegExp, K][] = [
  [/firewall|fortios|pan-os|asa|sonicos|firebox|utm/i, 'firewall'], [/router|routeros|vigor|archer|wan vpn/i, 'router'], [/switch/i, 'switch'],
  [/access point|\bwap\b|wireless|wifi/i, 'ap'], [/nas\b|storage|diskstation|qts/i, 'nas'], [/camera|ipc|dvr|surveillance/i, 'camera'], [/nvr/i, 'nvr'],
  [/printer|mfp|laserjet/i, 'printer'], [/wordpress|joomla|drupal|cms|plugin|wiki|webmail|\bphp\b|struts|laravel|magento/i, 'web'],
  [/windows|macos|ios|chrome|firefox|office|reader|acrobat|winrar|7-zip|desktop|client/i, 'pc'], [/phone|mobile|android|\biot\b/i, 'iot'],
]
const autoById = new Map<string, CatalogEntry>()
for (const [i, r] of KEV.entries()) {
  const key = kevKey(r)
  const id = `kev:${slug(r.vendor)}:${slug(r.product)}`
  const dup = autoById.get(id)
  // Hai dòng KEV chỉ khác nhau ở khoảng trắng lạ (ví dụ "Commerce and Magento") là cùng một sản phẩm: một mục, giữ cả hai khoá khớp.
  if (dup) { dup.kev.push(key); dup.kev_count += r.kev_count; continue }
  const display = r.product.toLowerCase().startsWith(r.vendor.toLowerCase()) ? r.product : `${r.vendor} ${r.product}`
  const kind = KIND_HINT.find(([re]) => re.test(`${r.product} ${r.vendor}`))?.[1] ?? 'server'
  autoById.set(id, {
    id, display, category: CAT.other, hint: `${r.vendor}, ${r.product}`, vendor: r.vendor, product: r.product, kind,
    kev: [key], aliases: [], version_hint: 'The version shown in the product, its About page or its admin console.', kev_count: r.kev_count, curated: false, order: 1000 + i,
  })
}
const auto = [...autoById.values()]

export const CATALOG: CatalogEntry[] = [...curated, ...auto]
export const findById = (id: string | undefined) => (id ? CATALOG.find((e) => e.id === id) : undefined)

const HAY = new Map(CATALOG.map((e) => [e.id, {
  name: fold(e.display), vendor: fold(e.vendor), product: fold(e.product), cat: fold(e.category), al: e.aliases.map(fold),
  all: fold(`${e.display} ${e.vendor} ${e.product} ${e.category} ${e.aliases.join(' ')}`),
}]))

const wordsOf = (s: string) => s.split(' ').filter(Boolean)

/** Xếp hạng: khớp đúng tên > đầu tên > từ đầu trong tên > bí danh/hãng > loại; mục tuyển chọn và mục có nhiều lỗ hổng bị khai thác lên trước. */
function score(e: CatalogEntry, terms: string[]): number {
  const h = HAY.get(e.id)!
  const nameWords = wordsOf(h.name)
  let total = 0
  let matched = 0
  const q = terms.join(' ')
  if (h.name === q) total += 200
  else if (h.name.startsWith(q)) total += 120
  for (const t of terms) {
    let s = 0
    if (nameWords.some((w) => w === t)) s = 40
    else if (nameWords.some((w) => w.startsWith(t))) s = 32
    else if (h.al.some((a) => a === t || wordsOf(a).includes(t))) s = 30
    else if (h.al.some((a) => a.startsWith(t) || wordsOf(a).some((w) => w.startsWith(t)))) s = 24
    else if (wordsOf(h.vendor).some((w) => w.startsWith(t))) s = 22
    else if (wordsOf(h.product).some((w) => w.startsWith(t))) s = 20
    else if (h.cat.includes(t)) s = 8
    else if (t.length >= 3 && h.all.includes(t)) s = 5
    if (s) matched++
    total += s
  }
  // Số model, phiên bản ("60f", "2019") không cần khớp, miễn có ít nhất một từ chữ khớp.
  const unmatched = terms.length - matched
  const unmatchedOnlyNumbers = terms.filter((t) => !HAY.get(e.id)!.all.includes(t)).every((t) => /\d/.test(t))
  if (unmatched > 0 && !(matched > 0 && unmatchedOnlyNumbers)) return 0
  if (matched === 0) return 0
  return total + (e.curated ? 15 - Math.min(e.order, 150) / 10 : 0) + Math.min(e.kev_count, 50) / 10
}

export interface SearchResult { items: CatalogEntry[]; total: number }

export function searchCatalog(q: string, limit = 30): SearchResult {
  const terms = wordsOf(fold(q))
  if (!terms.length) return { items: CATALOG.filter((e) => e.curated).slice(0, limit), total: CATALOG.length }
  const hits = CATALOG.map((e) => ({ e, s: score(e, terms) })).filter((x) => x.s > 0).sort((a, b) => b.s - a.s || a.e.order - b.e.order)
  return { items: hits.slice(0, limit).map((x) => x.e), total: hits.length }
}

/** Khớp tên một ô CSV với danh sách: id, tên hiển thị, "hãng sản phẩm" hoặc kết quả tìm kiếm đầu tiên nếu khớp mọi từ. */
export function findCatalog(text: string): CatalogEntry | undefined {
  const n = fold(text)
  if (!n) return undefined
  const exact = CATALOG.find((e) => e.id === text.trim() || HAY.get(e.id)!.name === n || fold(`${e.vendor} ${e.product}`) === n || HAY.get(e.id)!.al.includes(n))
  if (exact) return exact
  const terms = wordsOf(n)
  return searchCatalog(text, 5).items.find((e) => terms.every((t) => HAY.get(e.id)!.all.includes(t)))
}

/** Sản phẩm người dùng tự nhập (hãng + sản phẩm): khớp theo đúng cặp trong KEV nếu có, không thì theo mọi sản phẩm của hãng. */
export function customEntry(vendor: string, product: string): CatalogEntry {
  const v = fold(vendor)
  const p = fold(product)
  const exact = KEV.filter((r) => fold(r.vendor) === v && fold(r.product) === p).map(kevKey)
  const byVendor = KEV.filter((r) => fold(r.vendor) === v).map(kevKey)
  const kev = exact.length ? exact : byVendor.length ? byVendor : [`${vendor}|${product}`.toLowerCase()]
  return {
    id: '', display: `${vendor} ${product}`.trim(), category: CAT.other, hint: `${vendor}, ${product}`, vendor, product, kind: 'unknown', kev, aliases: [],
    version_hint: '', kev_count: sumKev(kev), curated: false, order: 9999,
  }
}
export { sumKev }
