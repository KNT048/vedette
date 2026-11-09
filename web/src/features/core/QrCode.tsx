import { useMemo } from 'react'
import { encode } from 'uqr'

const QUIET = 4 // modules of white around the code; the QR standard asks for 4 or phone cameras struggle

/**
 * QR vẽ tại chỗ bằng uqr (không gọi dịch vụ ngoài, D-35). Luôn đen trên trắng, kể cả giao diện tối,
 * kèm vùng yên tĩnh 4 ô, để điện thoại quét được.
 */
export function QrCode({ value, label }: { value: string; label: string }) {
  const { n, d } = useMemo(() => {
    const qr = encode(value, { ecc: 'M', border: 0 })
    let path = ''
    qr.data.forEach((row, y) => row.forEach((dark, x) => { if (dark) path += `M${x + QUIET} ${y + QUIET}h1v1h-1z` }))
    return { n: qr.size + QUIET * 2, d: path }
  }, [value])
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${n} ${n}`} shapeRendering="crispEdges" className="size-48 shrink-0 rounded-sm border border-rule">
      <rect width={n} height={n} fill="#fff" />
      <path d={d} fill="#000" />
    </svg>
  )
}
