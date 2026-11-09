import { Camera, CircleHelp, Cpu, Globe, HardDrive, Monitor, Network, Printer, Router, Server, Shield, Video, Wifi, type LucideIcon } from 'lucide-react'
import type { AssetKind } from '@/lib/types'
import { ApiError } from '@/lib/api'

export const KIND_ICON: Record<AssetKind, LucideIcon> = {
  firewall: Shield, router: Router, switch: Network, ap: Wifi, nas: HardDrive, server: Server, pc: Monitor,
  printer: Printer, camera: Camera, nvr: Video, iot: Cpu, web: Globe, unknown: CircleHelp,
}

export const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e))

/** Đọc file người dùng chọn: File.text() nếu có, không thì FileReader. */
export function readText(file: File): Promise<string> {
  if (typeof file.text === 'function') return file.text()
  return new Promise((resolve, reject) => {
    const r = new FileReader()
    r.onload = () => resolve(String(r.result ?? ''))
    r.onerror = () => reject(r.error ?? new Error('read failed'))
    r.readAsText(file)
  })
}

export async function sha256Hex(text: string): Promise<string> {
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('')
  } catch { return '' }
}
