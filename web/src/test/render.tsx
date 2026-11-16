// renderApp: dựng toàn bộ app (router thật, mock API thật) tại một đường dẫn, đã đăng nhập với vai cho trước.
import { fireEvent, render, screen, within } from '@testing-library/react'
import axe from 'axe-core'
import { expect } from 'vitest'
import { App } from '@/app/App'
import { orgStore, sessionStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'

const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }

export function renderApp(path: string, opts: { role?: Role | null; setupComplete?: boolean } = {}) {
  const role = opts.role === undefined ? 'admin' : opts.role
  orgStore.update((o) => ({ ...o, setup_complete: opts.setupComplete ?? true }))
  sessionStore.set({ userId: role ? USER[role] : null })
  return render(<App initialPath={path} />)
}

/** a11y: axe-core trên DOM (jsdom không tính được tương phản màu — kiểm ở E2E). */
export async function expectNoA11yViolations(node: Element = document.body) {
  const res = await axe.run(node, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })
  const msg = res.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(' | ')})`).join('\n')
  expect(res.violations, msg).toHaveLength(0)
}

/** A link of the main nav as a user reaches it (docs/UI.md §2): Testing Library ignores `inert`, so a link inside a closed group would
 *  be found though nobody can reach it. This opens the group first, then checks the link is not inert. */
export async function mainNavLink(name: string | RegExp) {
  const nav = await screen.findByRole('navigation', { name: 'Main navigation' })
  const link = await within(nav).findByRole('link', { name })
  const closed = link.closest('[inert]')
  if (closed) fireEvent.click(nav.querySelector(`[aria-controls="${closed.id}"]`)!)
  expect(link.closest('[inert]')).toBeNull()
  return link
}
