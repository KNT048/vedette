import '@testing-library/jest-dom/vitest'
import { afterAll, afterEach, beforeAll } from 'vitest'
import { cleanup, configure } from '@testing-library/react'
import { server } from './server'
import { resetMockDb } from '@/mocks/db'
import { loadAllNamespaces } from '@/lib/i18n'

// A screen under a loaded CI runner can take more than the default second to render after a request: every findBy/waitFor waits up
// to 5 s (it still returns as soon as the element is there), so a slow runner is not a failed test.
configure({ asyncUtilTimeout: 5000 })

class RO { observe() {} unobserve() {} disconnect() {} }
globalThis.ResizeObserver ??= RO as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}

// Screens render synchronously in tests: every namespace is there before the first one does (the product loads them per route).
beforeAll(loadAllNamespaces)
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }))
afterEach(() => { cleanup(); server.resetHandlers(); resetMockDb() })
afterAll(() => server.close())
