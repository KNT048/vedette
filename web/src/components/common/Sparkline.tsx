import { useState, type KeyboardEvent } from 'react'
import { cn } from '@/lib/utils'

const W = 120
const H = 40
const PAD = 4

/**
 * A trend line inside a stat tile (docs/UI.md §5, #825): one series, inline SVG, no chart library. The line is the de-emphasis ink
 * (`muted`) on a faint `sunken` area, the current value is a dot in `tone`, so the tile's number stays the one thing to read. The scale
 * starts at 0 (a flat line at the bottom is "none all month", never a zoomed-in wobble).
 *
 * Reading a day: hover, or focus the chart and use ←/→ (Home/End): a cross-line and the dot move to that day and the line under the chart
 * says it (`point(i)`, read out politely). Otherwise that line shows the range ends (`start`, `end`). The chart's accessible name is `label`,
 * which should hold the first and last value in words.
 */
export function Sparkline({ values, label, point, start, end, tone = 'accent', className }: {
  values: number[]
  label: string
  point: (i: number) => string
  start?: string
  end?: string
  tone?: 'accent' | 'danger' | 'ok'
  className?: string
}) {
  const [at, setAt] = useState<number | null>(null)
  const n = values.length
  if (n < 2) return null
  const max = Math.max(1, ...values)
  const x = (i: number) => (i / (n - 1)) * W
  const y = (v: number) => H - PAD - (v / max) * (H - 2 * PAD)
  const line = values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join('')
  const shown = at ?? n - 1
  const key = (e: KeyboardEvent) => {
    const next = e.key === 'ArrowLeft' ? shown - 1 : e.key === 'ArrowRight' ? shown + 1 : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : null
    if (next === null) return
    e.preventDefault()
    setAt(Math.min(n - 1, Math.max(0, next)))
  }
  return (
    <div className={cn('grid gap-1', className)}>
      <div className="relative h-10">
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={label} tabIndex={0}
          className="block size-full overflow-visible rounded-sm"
          onPointerLeave={() => setAt(null)} onKeyDown={key} onFocus={() => setAt(n - 1)} onBlur={() => setAt(null)}>
          <path d={`${line}L${W} ${H}L0 ${H}Z`} className="fill-sunken" />
          <path d={line} fill="none" className="stroke-muted" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
          {at !== null ? <line x1={x(at)} x2={x(at)} y1={0} y2={H} className="stroke-control" strokeWidth={1} vectorEffect="non-scaling-stroke" /> : null}
          {/* One hit column per day, wider than the line */}
          {values.map((_, i) => (
            <rect key={i} data-day={i} x={x(i) - W / (n - 1) / 2} y={0} width={W / (n - 1)} height={H} fill="transparent" onPointerEnter={() => setAt(i)} />
          ))}
        </svg>
        {/* The dot is HTML: an SVG circle would stretch with preserveAspectRatio="none". Placed in % of the chart box. */}
        <span aria-hidden data-testid="sparkline-dot"
          className={cn('pointer-events-none absolute size-2 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-surface',
            tone === 'danger' ? 'bg-danger' : tone === 'ok' ? 'bg-ok' : 'bg-accent')}
          style={{ left: `${(x(shown) / W) * 100}%`, top: `${(y(values[shown]!) / H) * 100}%` }} />
      </div>
      <p aria-live="polite" className="flex min-h-4 justify-between gap-2 text-caption text-muted tabular-nums">
        {at !== null ? <span>{point(at)}</span> : <><span>{start}</span><span>{end}</span></>}
      </p>
    </div>
  )
}
