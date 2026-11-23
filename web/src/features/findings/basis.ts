import type { Finding } from '@/lib/types'
import type { FindingRow } from './types'

/** i18n key for the "basis" of a finding: confirmed by a scan / by version / product match only. */
export const basisKey = (b: Finding['basis']) => `basis.${b}`
/** The basis as the page says it: a version match the device itself stated (its SNMP answer or its agent) is confirmed by it. */
export const basisLabel = (f: Pick<Finding, 'basis' | 'evidence'>) => (f.basis === 'version' && f.evidence?.source ? 'basis.device' : basisKey(f.basis))
export const isOpen = (s: FindingRow['status']) => s === 'confirmed' || s === 'suspected'
/** Device name as on the Devices page: `name` comes from the API; never an internal id. */
export const deviceName = (a: { name: string } | null, fallback: string) => a?.name || fallback
/** A manually declared device, or one seen only through LLDP, has no IP; the API writes "—". */
export const hasIp = (a: { ip: string } | null) => !!a && !!a.ip && a.ip !== '—'

const SEVERITY = ['info', 'low', 'medium', 'high', 'critical'] as const
const CERTAINTY: Record<Finding['basis'], number> = { scan: 2, person: 2, version: 1, product: 0 }
/** The real risk order: certainty first (confirmed by a scan, a person or a version the device reported > version > product only), then severity. */
export const riskRank = (f: Pick<Finding, 'basis' | 'severity'> & { evidence?: Finding['evidence'] }) =>
  (f.basis === 'version' && f.evidence?.source ? 2 : CERTAINTY[f.basis]) * 10 + SEVERITY.indexOf(f.severity)
/** Product name match only, version unknown: the severity is shown dimmed, "Unverified". */
export const unverified = (f: Pick<Finding, 'basis'>) => f.basis === 'product'
