import { setupServer } from 'msw/node'
import { handlers } from '@/mocks/handlers'

/** Use `server.use(...)` in a test to simulate API errors. */
export const server = setupServer(...handlers)
