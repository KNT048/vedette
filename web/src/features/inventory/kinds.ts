import { Building2, Camera, CircleHelp, Cpu, Globe, HardDrive, Laptop, Monitor, Network, Phone, Printer, Router, Server, Shield, Smartphone, Video, Wifi, type LucideIcon } from 'lucide-react'
import { categoryLabel, categoryOf, kindLabel } from '@/lib/deviceTypes'
import type { AssetKind, KindGuess } from '@/lib/types'
import { ApiError } from '@/lib/api'

/** One icon per category (D-511); the 13 types of before keep their own icon. */
const CATEGORY_ICON: Record<string, LucideIcon> = {
  network: Network, security: Shield, wireless: Wifi, server: Server, computer: Monitor, mobile: Smartphone, printer: Printer,
  video: Camera, telephony: Phone, storage: HardDrive, iot: Cpu, ot: Building2, web: Globe, unknown: CircleHelp,
}
const TYPE_ICON: Record<string, LucideIcon> = { router: Router, nvr: Video, laptop: Laptop }
export const kindIcon = (kind: AssetKind): LucideIcon => TYPE_ICON[kind] ?? CATEGORY_ICON[categoryOf(kind)] ?? CircleHelp

/** What the list and the device page show as the type: the kind, or, while it is unknown, what the rules say it most likely is. */
export function shownKind(d: { kind: AssetKind; guess?: KindGuess | null }): { kind: AssetKind; guessed: boolean } {
  return d.kind === 'unknown' && d.guess ? { kind: d.guess.kind, guessed: true } : { kind: d.kind, guessed: false }
}
/** "Network · Switch": the category, then the type. */
export const typeLine = (kind: AssetKind) => `${categoryLabel(categoryOf(kind))} · ${kindLabel(kind)}`

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
