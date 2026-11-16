// M2-1: the admin network the person types for the general hardening configs (mitigation INV-8).

/** The admin network as the configs take it (a network, or one address made /32 or /128), or null when it is not one. */
export function adminNetwork(raw: string, v6: boolean): string | null {
  const s = raw.trim()
  const m = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(s)
  if (!m) return null
  const [, addr, bits] = m
  if (!v6) {
    const parts = addr!.split('.')
    if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null
    if (bits !== undefined && Number(bits) > 32) return null
    return `${addr}/${bits ?? '32'}`
  }
  if (!/^[0-9a-fA-F:]+$/.test(addr!) || !addr!.includes(':') || addr!.includes(':::') || addr!.split('::').length > 2 || addr!.split(':').length > 8) return null
  if (bits !== undefined && Number(bits) > 128) return null
  return `${addr!.toLowerCase()}/${bits ?? '128'}`
}
