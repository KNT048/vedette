// The guide of docs/cookbook (a Help page) for each main screen, by the path's first part; the longest match wins. A test checks
// that every guide named here exists (features/help/help.test.tsx).
export const GUIDE_OF: Record<string, string> = {
  '/devices': '02-add-devices-and-agents',
  '/findings': '03-read-and-fix-a-finding',
  '/settings/channels': '04-alerts-email-telegram-zalo',
  '/exposure': '05-external-exposure-scan',
  '/honeypot': '06-honeypot-decoys',
  '/reports': '07-periodic-report',
  '/settings/updates': '08-updates-backup-restore',
  '/settings/data': '08-updates-backup-restore',
}

const BY_LENGTH = Object.keys(GUIDE_OF).sort((a, b) => b.length - a.length)

export function guideOf(pathname: string): string | undefined {
  const hit = BY_LENGTH.find((p) => pathname === p || pathname.startsWith(`${p}/`))
  return hit ? GUIDE_OF[hit] : undefined
}
