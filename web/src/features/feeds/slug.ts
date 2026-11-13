// vendor_product_slug tối thiểu (DATA_PIPELINE §3): tên người dùng nhận ra cho cặp vendor|product của KEV.

export const keyOf = (vendor: string, product: string) => `${vendor}|${product}`.toLowerCase()
const SLUG: Record<string, string> = {
  'qnap|photo station': 'Photo Station app on QNAP NAS',
  'qnap|qts': 'QNAP NAS (QTS)',
  'synology|diskstation manager': 'Synology NAS (DSM)',
  'wordpress|wordpress core': 'WordPress website',
  'wordpress|core': 'WordPress website',
  'microsoft|windows': 'Windows PCs and servers',
  'microsoft|sharepoint': 'Microsoft SharePoint',
  'microsoft|sql server': 'Microsoft SQL Server',
  'microsoft|exchange server': 'Microsoft Exchange mail server',
  'fortinet|fortios': 'FortiGate firewall (FortiOS)',
  'fortinet|multiple products': 'Several Fortinet products',
  'mikrotik|routeros': 'MikroTik router (RouterOS)',
  'ivanti|connect secure': 'Ivanti Connect Secure VPN',
  'cisco|secure firewall asa software and cisco secure ftd software': 'Cisco ASA/FTD firewall',
  'palo alto networks|pan-os': 'Palo Alto firewall (PAN-OS)',
  'broadcom|vmware esx': 'VMware ESXi hypervisor',
  'gitlab|community edition and enterprise edition': 'Self-hosted GitLab',
  'apple|multiple products': 'Apple devices (iPhone, iPad, Mac)',
  'php group|php': 'PHP on web servers',
  'linux|kernel': 'Linux servers (kernel)',
  'hikvision|multiple products': 'Hikvision cameras and recorders',
  'adobe|commerce and magento': 'Magento online store',
  'plex|media server': 'Plex Media Server',
  'atlassian|multiple products': 'Atlassian software (Jira, Confluence)',
  'beyondtrust|remote support': 'BeyondTrust Remote Support',
  'google|brotli': 'Brotli compression library (in many products)',
  'sudo|sudo': 'sudo',
}

/** Tên người dùng nhận ra (tiếng Anh, D-28); product đã bắt đầu bằng vendor thì không lặp vendor (W5-3, như feeds.DisplayOf). */
export const displayOf = (vendor: string, product: string) => {
  const slug = SLUG[keyOf(vendor, product)]
  if (slug) return slug
  const p = product.toLowerCase()
  const v = vendor.toLowerCase()
  return p === v || p.startsWith(`${v} `) ? product : `${vendor} ${product}`
}
/** Gợi ý loại thiết bị khi người dùng bấm "Tôi có" (S-FEED-2 → khai tay). */
export const kindOf = (key: string) =>
  key.startsWith('qnap|') || key.startsWith('synology|') ? 'nas' : key.includes('fortios') || key.includes('pan-os') || key.includes('asa') ? 'firewall'
    : key.startsWith('mikrotik|') ? 'router' : key.startsWith('hikvision|') ? 'camera' : key.startsWith('wordpress|') || key.includes('magento') ? 'web'
    : key.startsWith('microsoft|windows') ? 'server' : 'unknown'
