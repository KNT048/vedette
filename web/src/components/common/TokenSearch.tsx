import { useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { ListFilter, Search, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'

// One search box with filter tokens (#849, the Devices reference page of #842), in the style of runZero and Lansweeper:
// free text plus `key:value` tokens and bare flags (`fragile`), offered by an autocomplete list, with a few chips under the box
// for the common ones. The query is one string (the page keeps it in the URL); `parseQuery` splits it, the page matches rows.
// Combobox with list autocomplete: https://www.w3.org/WAI/ARIA/apg/patterns/combobox/examples/combobox-autocomplete-list/

/** A value a key takes, as offered in the list: `count` is how many rows have it (shown right-aligned, as runZero does). */
export type TokenValue = { value: string; label: string; count?: number }
/** A filter: `values` given → a `key:value` token; no `values` → a bare flag such as `fragile`. `free` lets the value be any text
 *  (`software:office`); the offered values are then examples. */
export type TokenKey = { key: string; label: string; values?: TokenValue[]; free?: boolean }
export type TokenChip = { token: string; label: string; count?: number }
export type ParsedQuery = { text: string[]; tokens: { key: string; value: string | null }[] }

/** Words of a query; a double-quoted run is one word (`"ip phone"`, `type:"ip phone"`). */
function words(q: string): string[] {
  return [...q.matchAll(/(?:[^\s"]+|"[^"]*")+/g)].map((m) => m[0])
}
const unquote = (s: string) => s.replace(/"/g, '')
const lc = (s: string) => s.toLowerCase()

/** Splits a query into free-text words and the tokens of known keys (case-insensitive). An unknown `foo:bar` is free text. A key still
 *  being typed filters nothing, so the list does not empty under the cursor: `type:` with no value, and the last word when it is exactly
 *  a key that takes a value (`type`, `source` before their colon). Any other partial word ("ty", "sou") is free text, as it may be a name. */
export function parseQuery(q: string, keys: TokenKey[]): ParsedQuery {
  const byKey = new Map(keys.map((k) => [lc(k.key), k]))
  const out: ParsedQuery = { text: [], tokens: [] }
  const list = words(q)
  const typing = list.length > 0 && !/\s$/.test(q) ? list.length - 1 : -1
  for (const [n, w] of list.entries()) {
    if (n === typing && byKey.get(lc(w))?.values) continue
    const i = w.indexOf(':')
    const k = i > 0 ? byKey.get(lc(w.slice(0, i))) : byKey.get(lc(w))
    if (i > 0 && k?.values) {
      const value = lc(unquote(w.slice(i + 1)))
      if (value) out.tokens.push({ key: k.key, value })
    } else if (i < 0 && k && !k.values) out.tokens.push({ key: k.key, value: null })
    else out.text.push(lc(unquote(w)))
  }
  return out
}

/** The query with `token` added, or removed when it is already there (a chip's toggle). */
export function toggleToken(q: string, token: string): string {
  const list = words(q)
  const has = list.some((w) => lc(w) === lc(token))
  return (has ? list.filter((w) => lc(w) !== lc(token)) : [...list, token]).join(' ')
}
export const hasToken = (q: string, token: string) => words(q).some((w) => lc(w) === lc(token))

type Option = { id: string; insert: string; label: ReactNode; hint?: string; count?: number; done: boolean }

/** The word the caret is in: [start, end) in the text; a quoted run is one word (`type:"ip phone"`), as `words` reads it. */
function currentWord(text: string, caret: number): [number, number] {
  for (const m of text.matchAll(/(?:[^\s"]+|"[^"]*"?)+/g)) {
    const s = m.index, e = m.index + m[0].length
    if (caret >= s && caret <= e) return [s, e]
  }
  return [caret, caret]
}

function optionsFor(word: string, keys: TokenKey[], query: string): Option[] {
  const i = word.indexOf(':')
  if (i > 0) {
    const key = keys.find((k) => lc(k.key) === lc(word.slice(0, i)))
    if (!key?.values) return []
    const part = lc(unquote(word.slice(i + 1)))
    return key.values
      .filter((v) => !part || lc(v.value).startsWith(part) || lc(v.label).includes(part))
      .filter((v) => !hasToken(query, `${key.key}:${v.value}`))
      .slice(0, 12)
      .map((v) => ({ id: `${key.key}:${v.value}`, insert: `${key.key}:${/\s/.test(v.value) ? `"${v.value}"` : v.value}`, label: <><span className="font-medium">{key.key}:</span>{v.value}</>, hint: v.label === v.value ? undefined : v.label, count: v.count, done: true }))
  }
  const w = lc(word)
  return keys
    .filter((k) => !w || lc(k.key).startsWith(w))
    .filter((k) => k.values || !hasToken(query, k.key))
    .map((k) => (k.values
      ? { id: `${k.key}:`, insert: `${k.key}:`, label: <span className="font-medium">{k.key}:</span>, hint: k.label, done: false }
      : { id: k.key, insert: k.key, label: <span className="font-medium">{k.key}</span>, hint: k.label, done: true }))
}

/** The search box. `value` is the whole query; every keystroke calls `onChange` (the page filters a loaded list, so no debounce). */
export function TokenSearch({ value, onChange, keys, chips, label, placeholder, chipsLabel, className, actions, summary }: {
  value: string
  onChange: (q: string) => void
  keys: TokenKey[]
  chips?: TokenChip[]
  label: string
  placeholder?: string
  /** Name of the chip group for screen readers, e.g. "Common filters". */
  chipsLabel?: string
  className?: string
  /** Buttons for the right end of the toolbar row (export, settings, add). */
  actions?: ReactNode
  /** A small line in the second row of the toolbar, before the active filter chips ("12 devices"). */
  summary?: ReactNode
}) {
  const { t } = useTranslation()
  const id = useId()
  const listId = `${id}-list`
  const input = useRef<HTMLInputElement>(null)
  const [open, setOpen] = useState(false)
  const [caret, setCaret] = useState(value.length)
  const [hot, setHot] = useState(-1) // nothing highlighted until an arrow key: Enter on a typed word must not pick a suggestion
  // After a pick the caret goes right after the inserted token, once React has written the new value (not a frame later: typing
  // that follows at once must land there).
  const caretTo = useRef<number | null>(null)
  useLayoutEffect(() => {
    if (caretTo.current === null || !input.current) return
    input.current.setSelectionRange(caretTo.current, caretTo.current)
    caretTo.current = null
  })
  const [start, end] = currentWord(value, Math.min(caret, value.length))
  const word = value.slice(start, end)
  const options = useMemo(() => (open ? optionsFor(word, keys, value) : []), [open, word, keys, value])
  const shown = open && options.length > 0
  const activeIdx = hot < 0 ? -1 : Math.min(hot, options.length - 1)
  const active = (chips ?? []).filter((c) => hasToken(value, c.token))

  function pick(o: Option) {
    const before = value.slice(0, start)
    const after = value.slice(end).replace(/^\s*/, '')
    const sep = o.done ? ' ' : ''
    const next = `${before}${o.insert}${sep}${after}`.replace(/\s{2,}/g, ' ')
    const pos = before.length + o.insert.length + sep.length
    onChange(next)
    setCaret(pos)
    setHot(-1)
    setOpen(!o.done)
    caretTo.current = pos
    input.current?.focus()
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') { e.preventDefault(); if (!open) setOpen(true); else setHot((a) => (options.length ? (a + 1) % options.length : -1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setHot((a) => (options.length ? (a <= 0 ? options.length - 1 : a - 1) : -1)) }
    else if (e.key === 'Enter' && shown) { const o = options[activeIdx]; if (o) { e.preventDefault(); pick(o) } else setOpen(false) }
    else if (e.key === 'Escape') {
      // First Escape closes the list, a second one clears the box (APG combobox).
      if (shown) { e.preventDefault(); e.stopPropagation(); setOpen(false) } else if (value) { e.preventDefault(); onChange('') }
    }
  }

  return (
    <div className={cn('grid min-w-0 gap-2', className)}>
      <div className="flex flex-wrap items-center gap-2">
      <div className="relative min-w-48 max-w-2xl flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted" aria-hidden />
        <Input
          ref={input}
          id={id}
          type="search"
          role="combobox"
          aria-label={label}
          aria-expanded={shown}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={shown && options[activeIdx] ? `${id}-o-${activeIdx}` : undefined}
          autoComplete="off"
          spellCheck={false}
          value={value}
          placeholder={placeholder}
          onChange={(e) => { onChange(e.target.value); setCaret(e.target.selectionStart ?? e.target.value.length); setHot(-1); setOpen(true) }}
          onSelect={(e) => setCaret(e.currentTarget.selectionStart ?? value.length)}
          onClick={() => setOpen(true)}
          onBlur={() => setOpen(false)}
          onKeyDown={onKeyDown}
          className="pl-9 pr-10 [&::-webkit-search-cancel-button]:hidden"
        />
        {value ? (
          <button type="button" aria-label={t('tokenSearch.clear')} onClick={() => { onChange(''); setCaret(0); input.current?.focus() }}
            className="absolute right-0.5 top-1/2 grid size-10 -translate-y-1/2 place-items-center rounded-md text-muted hover:text-ink sm:size-9">
            <X className="size-4" aria-hidden />
          </button>
        ) : null}
        <ul id={listId} role="listbox" aria-label={t('tokenSearch.suggestions')} hidden={!shown}
          className="absolute left-0 right-0 top-full z-30 mt-1 max-h-72 overflow-y-auto rounded-lg border border-rule bg-surface py-1 shadow-md">
          {options.map((o, i) => (
            <li key={o.id} id={`${id}-o-${i}`} role="option" aria-selected={i === activeIdx}
              // mousedown, not click: the input would blur (and close the list) before a click lands.
              onMouseDown={(e) => { e.preventDefault(); pick(o) }}
              onMouseMove={() => setHot(i)}
              className={cn('flex min-h-9 cursor-pointer items-center gap-3 px-3 text-sm', i === activeIdx && 'bg-sunken')}>
              <span className="whitespace-nowrap">{o.label}</span>
              {o.hint ? <span className="min-w-0 truncate text-meta text-muted">{o.hint}</span> : null}
              {o.count !== undefined ? <span className="ml-auto text-meta tabular-nums text-muted">{o.count}</span> : null}
            </li>
          ))}
        </ul>
      </div>
      {chips?.length ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button className="shrink-0"><ListFilter aria-hidden />{t('tokenSearch.filters')}{active.length ? ' ' : ''}{active.length ? <span className="tabular-nums text-muted">{active.length}</span> : null}</Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>{chipsLabel ?? t('tokenSearch.chips')}</DropdownMenuLabel>
            {chips.map((c) => (
              <DropdownMenuCheckboxItem key={c.token} checked={hasToken(value, c.token)} onSelect={(e) => { e.preventDefault(); onChange(toggleToken(value, c.token)) }}>
                <span>{c.label}</span>{' '}
                {c.count !== undefined ? <span className="ml-auto pl-4 text-meta tabular-nums text-muted">{c.count}</span> : null}
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}
      {actions ? <div className="flex flex-wrap items-center gap-2 sm:ml-auto">{actions}</div> : null}
      </div>
      {summary || active.length ? (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5">
          {summary}
          {active.map((c) => (
            <button key={c.token} type="button" aria-label={t('tokenSearch.removeFilter', { name: c.label })} onClick={() => onChange(toggleToken(value, c.token))}
              className="inline-flex h-9 items-center gap-1.5 rounded-full border border-accent bg-accent-soft px-3 text-meta font-medium text-ink sm:h-8">
              {c.label}<X className="size-3" aria-hidden />
            </button>
          ))}
          {active.length > 1 ? <Button size="sm" variant="link" onClick={() => onChange(active.reduce((q, c) => toggleToken(q, c.token), value))}>{t('tokenSearch.clearFilters')}</Button> : null}
        </div>
      ) : null}
    </div>
  )
}
