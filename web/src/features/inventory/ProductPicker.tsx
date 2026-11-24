import { useEffect, useId, useState, type KeyboardEvent, type RefObject } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Input, Label } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { useCatalog } from './api'
import { kindIcon } from './kinds'
import type { CatalogItem } from './types'
import { InfoTip } from '@/components/common/InfoTip'

/** The chosen product: an entry in the catalogue, or a vendor + product typed by the user (matched by vendor). */
export interface ChosenProduct { catalog_id?: string; vendor?: string; product?: string; display: string; hint: string; version_hint: string | null; custom: boolean }
export const chosenFromItem = (it: CatalogItem): ChosenProduct => ({ catalog_id: it.id, display: it.display, hint: it.hint, version_hint: it.version_hint, custom: false })
/** The part of the body sent to the server that says "this product". */
export const productFields = (p: ChosenProduct) => (p.custom ? { vendor: p.vendor, product: p.product } : { catalog_id: p.catalog_id })

/**
 * A product search by commercial name, model or vendor (S-INV-2). Before typing no list is shown, only a hint line (a list of 30 entries would suggest only 30 products are supported).
 * A scrolling list shows only after typing; the server returns at most 30 rows, the rest is reported as "N more match". If it is not found, type the vendor + product.
 * A standard ARIA combobox: up/down/Enter on the keyboard, the number of results is readable by a screen reader.
 */
/** `error`: why the form cannot be sent without a product (shown under the field, which is marked invalid); null or absent when none. */
export function ProductPicker({ value, onChange, label, listOpenRef, error }: { value: ChosenProduct | null; onChange: (v: ChosenProduct | null) => void; label: string; listOpenRef?: RefObject<boolean>; error?: string | null }) {
  const { t } = useTranslation('inventory')
  const uid = useId()
  const inputId = `${uid}-input`
  const listId = `${uid}-list`
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const [custom, setCustom] = useState(false)
  const [vendor, setVendor] = useState('')
  const [product, setProduct] = useState('')
  const typed = q.trim() !== ''
  const res = useCatalog(q.trim())
  // No list until the user types: a fixed-length list on open reads as "only these products are supported".
  const items = typed ? (res.data?.items ?? []) : []
  const total = typed ? (res.data?.total ?? 0) : 0
  const listVisible = open && !value && !custom && items.length > 0
  // The dialog that holds this field asks for this flag so Esc closes only the suggestion list, not the whole dialog.
  useEffect(() => {
    if (listOpenRef) listOpenRef.current = listVisible
    return () => { if (listOpenRef) listOpenRef.current = false }
  }, [listVisible, listOpenRef])

  function pick(it: CatalogItem) { onChange(chosenFromItem(it)); setOpen(false); setQ('') }
  function onKey(e: KeyboardEvent) {
    if (value) return
    if (e.key === 'Escape' && listVisible) { e.preventDefault(); setOpen(false); return }
    if (e.key === 'ArrowDown') { e.preventDefault(); setOpen(true); setActive((i) => Math.min(i + 1, items.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter' && open && items[active]) { e.preventDefault(); pick(items[active]) }
  }
  function setCustomValue(v: string, p: string) {
    setVendor(v); setProduct(p)
    onChange(v.trim() && p.trim() ? { vendor: v.trim(), product: p.trim(), display: `${v.trim()} ${p.trim()}`, hint: t('picker.customHint'), version_hint: null, custom: true } : null)
  }

  if (custom) {
    return (
      <div className="grid gap-3">
        <div className="grid gap-1.5">
          <Label htmlFor={`${uid}-vendor`}>{t('picker.vendor')}</Label>
          <Input id={`${uid}-vendor`} value={vendor} maxLength={64} placeholder={t('picker.vendorPlaceholder')} autoComplete="off" onChange={(e) => setCustomValue(e.target.value, product)} />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor={`${uid}-product`}>{t('picker.product')}</Label>
          <Input id={`${uid}-product`} value={product} maxLength={64} placeholder={t('picker.productPlaceholder')} autoComplete="off" onChange={(e) => setCustomValue(vendor, e.target.value)} />
        </div>
        {error && !value ? <p className="text-meta text-danger">{error}</p> : null}
        <div className="flex items-center gap-1"><p className="text-meta text-muted" role="status">{t('picker.customNote')}</p><InfoTip>{t('picker.customNoteInfo')}</InfoTip></div>
        <div><Button size="sm" onClick={() => { setCustom(false); setVendor(''); setProduct(''); onChange(null) }}>{t('picker.backToList')}</Button></div>
      </div>
    )
  }

  return (
    <div className="grid gap-1.5">
      <Label htmlFor={inputId}>{label}</Label>
      <div className="relative flex gap-2">
        <Input
          id={inputId} role="combobox" aria-expanded={open && !value} aria-autocomplete="list" aria-controls={open && !value ? listId : undefined}
          aria-activedescendant={open && !value && items[active] ? `${uid}-opt-${active}` : undefined}
          autoComplete="off" readOnly={!!value} placeholder={t('picker.placeholder')}
          aria-invalid={error ? true : undefined} aria-describedby={error ? `${uid}-error` : undefined}
          value={value ? value.display : q}
          onChange={(e) => { setQ(e.target.value); setOpen(true); setActive(0) }}
          onFocus={() => setOpen(true)} onBlur={() => setOpen(false)} onKeyDown={onKey}
        />
        {value ? <Button onClick={() => onChange(null)}>{t('picker.change')}</Button> : null}
        {listVisible ? (
          <div className="absolute left-0 right-0 top-full z-30 mt-1 overflow-hidden rounded-md border border-rule bg-surface shadow-md">
            <ul id={listId} role="listbox" aria-label={label} className="max-h-60 overflow-y-auto p-1">
              {items.map((it, i) => {
                const Icon = kindIcon(it.kind)
                return (
                  <li key={it.id} id={`${uid}-opt-${i}`} role="option" aria-selected={i === active}
                    onMouseDown={(e) => e.preventDefault()} onClick={() => pick(it)} onMouseEnter={() => setActive(i)}
                    className={cn('flex cursor-pointer items-center gap-3 rounded-sm px-2 py-2 text-sm', i === active && 'bg-sunken')}>
                    <Icon className="size-4 shrink-0 text-muted" aria-hidden />
                    <span className="grid min-w-0">
                      <span className="font-medium [overflow-wrap:anywhere]">{it.display}</span>
                      <span className="text-caption text-muted [overflow-wrap:anywhere]">{it.category}, {it.vendor}</span>
                      {it.kev_cves > 0 ? <span className="text-caption text-warn">{t('picker.kev', { count: it.kev_cves })}</span> : null}
                    </span>
                  </li>
                )
              })}
            </ul>
            <div className="grid gap-0.5 border-t border-rule px-2 py-1">
              {total > items.length ? <span className="text-caption text-muted">{t('picker.more', { count: total - items.length })}</span> : null}
              <div><Button size="sm" variant="link" className="h-auto whitespace-normal text-left" onMouseDown={(e) => e.preventDefault()} onClick={() => { setCustom(true); setOpen(false) }}>{t('picker.notListed')}</Button></div>
            </div>
          </div>
        ) : null}
      </div>
      {error && !value ? <p id={`${uid}-error`} className="text-meta text-danger">{error}</p> : null}
      <div className="text-meta text-muted" role="status">
        {value ? t('picker.chosen', { hint: value.hint }) : open && typed && !res.isPending && items.length === 0 ? t('picker.none') : t('picker.hint')}
      </div>
      {value || listVisible ? null : <div><Button size="sm" variant="link" className="h-auto whitespace-normal text-left" onClick={() => { setCustom(true); setOpen(false) }}>{t('picker.notListed')}</Button></div>}
    </div>
  )
}
