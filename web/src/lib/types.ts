// Kiểu dữ liệu dùng chung giữa nhiều module (tài sản là thực thể trung tâm, ARCHITECTURE §4). Kiểu riêng của module ở features/<m>/types.ts.
export type ObsSource = 'manual' | 'agent' | 'snmp' | 'nmap' | 'passive' | 'scan'
/** A device type id of content/devicetypes/types.json (D-511): data, not a hand-written union. */
export type AssetKind = string
/** What the identification rules say a device of unknown kind most likely is (D-511); never its kind. */
export interface KindGuess { kind: AssetKind; confidence: number; evidence: string; model?: string }

export interface Observed { value: string; source: ObsSource; confidence: number; seen_at: string }

export interface Software {
  id: string
  display: string // tên thương mại tiếng Việt/Anh người dùng nhận ra
  vendor: string
  product: string
  version: string | null
  kev: string[] // khoá khớp KEV: "vendorproject|product" viết thường
  source: ObsSource
  confidence: number
}

export interface Service { port: number; proto: 'tcp' | 'udp'; name: string; product?: string; version?: string; detail?: string; source: ObsSource; confidence: number }

export interface Asset {
  id: string
  site: string
  ip: string
  mac: string | null
  hostname: string | null
  kind: AssetKind
  kind_source?: ObsSource | null // the source of the kind; null for the default unknown (D-511)
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
  /** scan = xác nhận bằng mẫu quét; version = nghi theo phiên bản; product = chỉ khớp sản phẩm, chưa biết phiên bản */
  basis: 'scan' | 'version' | 'product'
  evidence: { summary: string; template?: string; request?: string; response?: string; checked_at: string } | null
  first_seen: string
  last_seen: string
  resolved_by: string | null
  resolved_at: string | null
  resolution_note: string | null
  history: { ts: string; user: string; action: string; note?: string }[]
}
