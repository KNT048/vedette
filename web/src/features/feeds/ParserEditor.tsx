import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label, Select, Textarea } from '@/components/ui/input'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { DataTable } from '@/components/common/DataTable'
import { ApiError } from '@/lib/api'
import { fmtNumber } from '@/lib/format'
import { FIELDS, FORMATS, ROW_LIMIT, SIZE_LIMIT, defaultParser } from './defaults'
import { useParseTest } from './api'
import type { DateFormat, FeedFormat, FeedKind, FieldMap, ParseRecord, Parser } from './types'

const DATE_FORMATS: DateFormat[] = ['auto', 'dmy', 'mdy', 'epoch']
const DELIMS = [',', ';', '\t', '|']

/** Parsing rules and live test (S-FEED-5, D-37): pick the format, map fields, optional regex and normalisation, then try it on a sample before saving. */
export function ParserEditor({ kind, parser, onChange, onFormat }: { kind: FeedKind; parser: Parser; onChange: (p: Parser) => void; onFormat: (f: FeedFormat) => void }) {
  const { t } = useTranslation('feeds')
  const test = useParseTest()
  const [own, setOwn] = useState('')
  const fmt = parser.format
  const set = (patch: Partial<Parser>) => { test.reset(); onChange({ ...parser, ...patch }) }
  const setField = (id: string, patch: Partial<FieldMap>) => set({ fields: { ...parser.fields, [id]: { ...parser.fields[id]!, ...patch } } })
  const mapped = fmt === 'json' || fmt === 'csv' || fmt === 'rss'
  const fields = FIELDS[kind].filter((f) => mapped || (fmt === 'lines' && f.id === 'indicator'))
  // JSON examples come from the starting rules of this feed type, so an IOC field shows $.ioc or $.type, not a CVE path.
  const jsonExample = defaultParser(kind, 'json').fields
  const sourceHint = (id: string) => fmt === 'json' ? t('parser.srcJson', { example: jsonExample[id]?.source }) : fmt === 'csv' ? t('parser.srcCsv') : t('parser.srcRss')
  // A result belongs to the type and rules it was run with: switching the type or the format (which resets the rules) hides it.
  const fresh = test.variables?.kind === kind && JSON.stringify(test.variables.parser) === JSON.stringify(parser)
  const result = fresh ? test.data : undefined
  const err = fresh && (test.error instanceof ApiError || test.error instanceof Error) ? test.error.message : null

  return (
    <div className="grid gap-4 rounded-md border border-rule p-4" role="group" aria-label={t('parser.title')}>
      <div className="grid gap-1">
        <h3 className="text-sm font-semibold">{t('parser.title')}</h3>
        <p className="text-[13px] text-muted">{t('parser.intro')}</p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t('parser.format')} htmlFor="pe-format">
          <Select id="pe-format" value={fmt} onChange={(e) => onFormat(e.target.value as FeedFormat)}>{FORMATS[kind].map((f) => <option key={f} value={f}>{t(`parser.formats.${f}`)}</option>)}</Select>
        </Field>
        {fmt === 'json' ? (
          <Field label={t('parser.recordsPath')} htmlFor="pe-records" hint={t(`parser.recordsHint.${kind}`)}>
            <Input id="pe-records" value={parser.records_path} onChange={(e) => set({ records_path: e.target.value })} autoComplete="off" spellCheck={false} className="font-mono text-[13px]" />
          </Field>
        ) : null}
        {fmt === 'csv' ? (
          <div className="grid grid-cols-2 items-end gap-4">
            <Field label={t('parser.delimiter')} htmlFor="pe-delim">
              <Select id="pe-delim" value={parser.delimiter} onChange={(e) => set({ delimiter: e.target.value })}>{DELIMS.map((d) => <option key={d} value={d}>{t(`parser.delims.${d === '\t' ? 'tab' : d === ',' ? 'comma' : d === ';' ? 'semicolon' : 'pipe'}`)}</option>)}</Select>
            </Field>
            <div className="flex h-9 items-center gap-2">
              <Checkbox id="pe-header" checked={parser.has_header} onCheckedChange={(v) => set({ has_header: v === true })} />
              <Label htmlFor="pe-header" className="font-normal">{t('parser.header')}</Label>
            </div>
          </div>
        ) : null}
      </div>
      <p className="text-[13px] text-muted">{t(`parser.note.${fmt}`, { example: jsonExample[FIELDS[kind][0]!.id]?.source })}</p>

      {fields.length ? (
        <div className="grid gap-3">
          {fields.map(({ id, required, date }) => {
            const f = parser.fields[id]!
            return (
              <fieldset key={id} className="grid gap-3 rounded-md border border-rule p-3 sm:grid-cols-2">
                <legend className="px-1 text-[13px] font-medium">{t(`parser.field.${id}`)}{required ? ` (${t('parser.required')})` : ''}</legend>
                {mapped ? (
                  <Field label={t('parser.source')} htmlFor={`pe-${id}-src`} hint={sourceHint(id)}>
                    <Input id={`pe-${id}-src`} value={f.source} onChange={(e) => setField(id, { source: e.target.value })} autoComplete="off" spellCheck={false} className="font-mono text-[13px]" />
                  </Field>
                ) : null}
                <Field label={t('parser.regex')} htmlFor={`pe-${id}-re`} hint={t('parser.regexHint')}>
                  <Input id={`pe-${id}-re`} value={f.regex} onChange={(e) => setField(id, { regex: e.target.value })} autoComplete="off" spellCheck={false} className="font-mono text-[13px]" placeholder={id === 'cve' ? '(CVE-\\d{4}-\\d{4,})' : id === 'indicator' ? '^(\\S+)' : ''} />
                </Field>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2 sm:col-span-2">
                  <span className="flex items-center gap-2"><Checkbox id={`pe-${id}-trim`} checked={f.trim} onCheckedChange={(v) => setField(id, { trim: v === true })} /><Label htmlFor={`pe-${id}-trim`} className="font-normal">{t('parser.trim')}</Label></span>
                  <span className="flex items-center gap-2"><Checkbox id={`pe-${id}-lc`} checked={f.lowercase} onCheckedChange={(v) => setField(id, { lowercase: v === true })} /><Label htmlFor={`pe-${id}-lc`} className="font-normal">{t('parser.lowercase')}</Label></span>
                  {date ? (
                    <span className="flex items-center gap-2"><Label htmlFor={`pe-${id}-date`} className="font-normal">{t('parser.dateFormat')}</Label>
                      <Select id={`pe-${id}-date`} value={f.date_format} onChange={(e) => setField(id, { date_format: e.target.value as DateFormat })} className="h-8 w-auto">{DATE_FORMATS.map((d) => <option key={d} value={d}>{t(`parser.dates.${d}`)}</option>)}</Select></span>
                  ) : null}
                </div>
              </fieldset>
            )
          })}
        </div>
      ) : null}

      <details className="text-sm">
        <summary className="cursor-pointer text-muted">{t('parser.ownSample')}</summary>
        <div className="mt-2 grid gap-1.5">
          <Label htmlFor="pe-own" className="sr-only">{t('parser.ownSample')}</Label>
          <Textarea id="pe-own" value={own} onChange={(e) => { setOwn(e.target.value); test.reset() }} spellCheck={false} className="font-mono text-[12.5px]" placeholder={t('parser.ownPlaceholder')} />
          <p className="text-[13px] text-muted">{t('parser.ownHint')}</p>
        </div>
      </details>

      <div className="flex flex-wrap items-center gap-3">
        <Button type="button" variant="primary" disabled={test.isPending} onClick={() => test.mutate({ kind, parser, sample: own.trim() ? own : undefined })}>{test.isPending ? t('parser.testing') : t('parser.test')}</Button>
        <span className="text-[13px] text-muted">{t('parser.limits', { size: SIZE_LIMIT / 1_000_000, rows: fmtNumber(ROW_LIMIT) })}</span>
      </div>
      {err ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{err}</p> : null}
      {result ? (
        <div className="grid gap-3" aria-live="polite">
          <p className="flex flex-wrap items-center gap-2 text-sm" role="status">
            <Chip tone={result.accepted ? 'ok' : 'danger'}>{t('parser.accepted', { count: result.accepted })}</Chip>
            <Chip tone={result.rejected ? 'warn' : 'off'}>{t('parser.rejected', { count: result.rejected })}</Chip>
            <span className="text-muted">{result.sample_label}</span>
          </p>
          {result.truncated ? <p className="text-[13px] text-warn">{t('parser.truncated', { rows: fmtNumber(ROW_LIMIT) })}</p> : null}
          {result.records.length ? (
            <DataTable<ParseRecord> caption={t('parser.previewCaption')} data={result.records} pageSize={20}
              columns={result.columns.map((c) => ({ id: c, header: t(`parser.field.${c}`), accessorFn: (r: ParseRecord) => r[c] ?? '', cell: ({ getValue }: { getValue: () => unknown }) => <span className="block max-w-72 truncate" title={String(getValue())}>{String(getValue()) || <span className="text-muted">-</span>}</span> }))} />
          ) : <p className="text-sm text-muted">{t('parser.noRecords')}</p>}
          {result.rejected ? (
            <div className="grid gap-1 text-sm">
              <p className="font-medium">{t('parser.whyRejected')}</p>
              <ul className="list-disc pl-5 text-[13px]">{result.reasons.slice(0, 6).map((r) => <li key={r.reason}>{r.reason} <span className="text-muted">({fmtNumber(r.count)})</span></li>)}</ul>
              {/* Each reject shows its value: the sample is the admin's own paste or the built-in one, never a fetched feed (INV-7). Text only, never HTML. */}
              <p className="font-medium">{t(fmt === 'lines' || fmt === 'csv' ? 'parser.firstRejectedLines' : 'parser.firstRejectedRows')}</p>
              <ul className="grid gap-0.5 text-[13px]">{result.rejects.map((r, i) => <li key={i} className="break-words"><span className="text-muted">{t(fmt === 'lines' || fmt === 'csv' ? 'parser.rejectLine' : 'parser.rejectRow', { n: r.row })}</span> {r.reason}</li>)}</ul>
            </div>
          ) : null}
          <details className="text-sm"><summary className="cursor-pointer text-muted">{t('parser.showSample')}</summary><div className="mt-2 max-h-72 overflow-auto"><CodeBlock code={result.sample.slice(0, 6000)} label={result.sample_label} /></div></details>
        </div>
      ) : null}
    </div>
  )
}
