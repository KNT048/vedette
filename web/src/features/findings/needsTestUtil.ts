// Needs your input shows one collapsed card per device; its software lines list their CVEs behind a click. Tests that look inside
// open them as a person does.
import { waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

/** Opens every device card under `root` and every software line's CVE list (waits for the first card to show). */
export async function openNeeds(root: HTMLElement = document.body, opts: { cves?: boolean } = {}) {
  await waitFor(() => { if (!root.querySelector('article[aria-label^="What "]')) throw new Error('no device card yet') }, { timeout: 5000 })
  for (const b of Array.from(root.querySelectorAll<HTMLButtonElement>('article[aria-label^="What "] button[aria-expanded="false"]'))) await userEvent.click(b)
  if (opts.cves === false) return
  await waitFor(() => { if (!root.querySelector('[data-testid="needs-line"], article[aria-label^="What "] [aria-label^="What "] li')) throw new Error('no entries yet') }, { timeout: 5000 })
  for (const s of Array.from(root.querySelectorAll<HTMLElement>('[data-testid="needs-line"] summary'))) await userEvent.click(s)
}
