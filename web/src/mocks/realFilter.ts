import type { RequestHandler } from 'msw'
import { moduleOf } from '@/lib/apiModules'

/** Path below /api/v1 of a REST handler, with `:id` turned into a concrete segment. */
export function handlerApiPath(h: RequestHandler): string {
  const path = String((h.info as unknown as { path: string }).path)
  return path.replace(/^\*?\/api\/v1/, '').replace(/:\w+/g, 'x')
}

/** Handlers whose module is NOT served by the real backend; those requests stay with MSW. */
export function mockedHandlers(all: RequestHandler[], isReal: (module: string) => boolean): RequestHandler[] {
  return all.filter((h) => !isReal(moduleOf(handlerApiPath(h))))
}
