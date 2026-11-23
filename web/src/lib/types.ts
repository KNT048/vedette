// Kiểu dữ liệu dùng chung giữa nhiều module (tài sản là thực thể trung tâm, ARCHITECTURE §4). Kiểu riêng của module ở features/<m>/types.ts.
export type ObsSource = 'manual' | 'declared' | 'agent' | 'snmp' | 'nmap' | 'passive' | 'scan'
/** A device type id of content/devicetypes/types.json: data, not a hand-written union. */
export type AssetKind = string
/** What the identification rules say a device of unknown kind most likely is; never its kind. */
export interface KindGuess { kind: AssetKind; confidence: number; evidence: string; model?: string; alternatives?: AssetKind[] }

export interface Observed { value: string; source: ObsSource; confidence: number; seen_at: string; basis?: 'stated' | 'stated_web' | 'stated_sip' | 'guess'; software_id?: string }

export interface Software {
  id: string
  display: string // tên thương mại tiếng Việt/Anh người dùng nhận ra
  vendor: string
  product: string
  version: string | null
  kev: string[] // khoá khớp KEV: "vendorproject|product" viết thường
  source: ObsSource
  confidence: number
  /** The package release (a person's correction, INV-41) */
  pkg_version?: string | null
  /** Mock only (INV-41): on a person's correction, the id of the reported row it replaces for matching. */
  corrects?: string
  /** Mock only: when a person last entered or changed the row (a row they added, or a correction); seen_at of a manual row. */
  set_at?: string
  /** Mock only (INV-41 (6)): on a correction, the person said the reported row is not installed; it matches nothing. */
  not_installed?: boolean
}

export interface Service { port: number; proto: 'tcp' | 'udp'; name: string; product?: string; version?: string; detail?: string; source: ObsSource; confidence: number }

export interface Asset {
  id: string
  site: string
  ip: string
  mac: string | null
  hostname: string | null // the host name the network reports (read-only), or the name typed when the device was added manually
  /** The name a person gave the device in Vedette: it wins on every page (nameOf); null or absent = the default name. */
  name?: string | null
  kind: AssetKind
  kind_source?: ObsSource | null // the source of the kind; null for the default unknown
  guess?: KindGuess | null
  vendor: Observed | null
  model: Observed | null
  os: Observed | null
  software: Software[]
  services: Service[]
  first_seen: string
  last_seen: string
  approved: boolean
  fragile: boolean // máy in, camera, PLC, NAS cũ: mặc định chỉ thụ động (S-INV-1)
  origin: 'discovered' | 'manual'
  notes?: string
}

export interface Paged<T> { items: T[]; total: number }

export type FindingStatus = 'confirmed' | 'suspected' | 'mitigated' | 'patched' | 'false_positive' | 'not_relevant'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/** Phát hiện = CVE × tài sản (ARCHITECTURE §4 inv_finding). Module findings sở hữu UI/endpoint; module khác chỉ đọc. */
export interface Finding {
  id: string
  asset_id: string
  cve: string
  status: FindingStatus
  severity: Severity
  confidence: number
  /** scan = xác nhận bằng mẫu quét; person = người xác nhận; version = theo phiên bản (xác nhận khi evidence.source: thiết bị tự báo qua SNMP hoặc agent); product = chỉ khớp sản phẩm, chưa biết phiên bản */
  basis: 'scan' | 'version' | 'product' | 'person'
  evidence: { summary: string; template?: string; request?: string; response?: string; checked_at: string; agent?: boolean; agent_row?: boolean; source?: 'snmp' | 'agent' } | null
  first_seen: string
  last_seen: string
  resolved_by: string | null
  resolved_at: string | null
  resolution_note: string | null
  history: { ts: string; user: string; action: string; note?: string }[]
}
