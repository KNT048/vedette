// A minimal vendor_product_slug (DATA_PIPELINE §3): the name the user recognises for the KEV vendor|product pair.

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

/** The name the user recognises (English); a product that already starts with the vendor does not repeat the vendor (like feeds.DisplayOf). */
export const displayOf = (vendor: string, product: string) => {
  const slug = SLUG[keyOf(vendor, product)]
  if (slug) return slug
  const p = product.toLowerCase()
  const v = vendor.toLowerCase()
  return p === v || p.startsWith(`${v} `) ? product : `${vendor} ${product}`
}
/** A device type hint when the user clicks "I have this" (S-FEED-2 → hand declaration). */
export const kindOf = (key: string) =>
  key.startsWith('qnap|') || key.startsWith('synology|') ? 'nas' : key.includes('fortios') || key.includes('pan-os') || key.includes('asa') ? 'firewall'
    : key.startsWith('mikrotik|') ? 'router' : key.startsWith('hikvision|') ? 'camera' : key.startsWith('wordpress|') || key.includes('magento') ? 'web'
    : key.startsWith('microsoft|windows') ? 'server' : 'unknown'
