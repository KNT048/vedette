import { Notice } from '@/components/common/PageHeader'
import { ApiError } from '@/lib/api'

/** The error of an action (not a page-load error): say what is wrong, with the fix from the server. */
export function ActionError({ error }: { error: unknown }) {
  if (!error) return null
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error)
  return <Notice tone="danger" role="alert" title={msg} className="mb-0" />
}

/** A horizontally scrolling frame for a table in a document: it must be focusable from the keyboard (axe scrollable-region-focusable); no role/label because the parent section is already a named region. */
export function Scroll({ children }: { children: React.ReactNode }) {
  return <div className="overflow-x-auto" tabIndex={0}>{children}</div>
}
