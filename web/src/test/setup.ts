import '@testing-library/jest-dom/vitest'
import { afterAll, afterEach, beforeAll } from 'vitest'
import { cleanup } from '@testing-library/react'
import { server } from './server'
import { resetMockDb } from '@/mocks/db'
import '@/lib/i18n'

class RO { observe() {} unobserve() {} disconnect() {} }
globalThis.ResizeObserver ??= RO as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}

beforeAll(() => server.listen({ onUnhandledFrame: 'error' }))
afterEach(() => { cleanup(); server.resetHandlers(); resetMockDb() })
afterAll(() => server.close())
