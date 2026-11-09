// Gom handler: lõi + mỗi module tự khai trong features/<m>/mocks.ts (không sửa file này khi thêm module).
import type { RequestHandler } from 'msw'
import { coreHandlers } from './core'

const modules = import.meta.glob<{ handlers: RequestHandler[] }>('../features/*/mocks.ts', { eager: true })

/** Handler theo module (test hợp đồng đối chiếu với features/<m>/contract.ts). Handler lõi tính vào module core. */
export const handlersByModule: Record<string, RequestHandler[]> = { core: [...coreHandlers] }
for (const [p, m] of Object.entries(modules)) {
  const id = p.match(/features\/([\w-]+)\//)![1]!
  handlersByModule[id] = [...(handlersByModule[id] ?? []), ...m.handlers]
}

export const handlers: RequestHandler[] = [...coreHandlers, ...Object.values(modules).flatMap((m) => m.handlers)]
