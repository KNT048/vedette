import type { Feature } from '@/app/feature'

// Module scan: quét xác nhận an toàn (S-SCAN-1..4). #850: no menu entry; its settings, history and probe log are tabs of
// Settings › Scanning (features/scanning), and Scan now sits where the person is (features/scanning/ScanNow.tsx).
export const feature: Feature = {
  id: 'scan',
  routes: [{ path: 'scans', lazy: () => import('./ScansMoved').then((m) => ({ Component: m.default })) }],
}
