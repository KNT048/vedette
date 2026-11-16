// Test harness (#849): the SNMP credential list has no page under Devices any more (Settings › Scanning, #850, places it), so its
// tests render the component itself, with the app's query client, a router at `path` (for ?snmp_ip=) and the toaster.
import { QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { RouterProvider, createMemoryRouter } from 'react-router'
import { Toaster } from 'sonner'
import { makeQueryClient } from '@/app/App'
import { sessionStore } from '@/mocks/stores'
import { SnmpSection } from './SnmpSection'

export function renderSnmp(path = '/', userId = 'u-admin') {
  sessionStore.set({ userId })
  const router = createMemoryRouter([{ path: '*', element: <SnmpSection /> }], { initialEntries: [path] })
  return render(<QueryClientProvider client={makeQueryClient()}><RouterProvider router={router} /><Toaster /></QueryClientProvider>)
}
