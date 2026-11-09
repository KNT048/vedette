import { setupServer } from 'msw/node'
import { handlers } from '@/mocks/handlers'

/** Dùng `server.use(...)` trong test để giả lập lỗi API. */
export const server = setupServer(...handlers)
