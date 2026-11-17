import { useMemo } from 'react'
import { encode } from 'uqr'

const QUIET = 4 // modules of white around the code; the QR standard asks for 4 or phone cameras struggle

/**
 * A QR code as one SVG path on a white square, the quiet zone part of the view box (docs/UI.md §12). Always black on white, in the
 * dark theme too, so a phone can read it: the one place in the app with colour values (styleGuard allowlist).
 */
export function QrSvg({ size, path, label }: { size: number; path: string; label: string }) {
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${size} ${size}`} shapeRendering="crispEdges" className="size-48 shrink-0 rounded-md border border-rule">
      {/* ui-guard: a QR code is black on white in both themes, or phones cannot read it in the dark theme */}
      <rect width={size} height={size} fill="white" />
      <path d={path} fill="black" />
    </svg>
  )
}

/** A QR code drawn here with uqr (no outside service), with the 4-module quiet zone. */
export function QrCode({ value, label }: { value: string; label: string }) {
  const { n, d } = useMemo(() => {
    const qr = encode(value, { ecc: 'M', border: 0 })
    let path = ''
    qr.data.forEach((row, y) => row.forEach((dark, x) => { if (dark) path += `M${x + QUIET} ${y + QUIET}h1v1h-1z` }))
    return { n: qr.size + QUIET * 2, d: path }
  }, [value])
  return <QrSvg size={n} path={d} label={label} />
}
