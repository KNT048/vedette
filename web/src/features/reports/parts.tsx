import { ApiError } from '@/lib/api'

/** Lỗi của một thao tác (không phải lỗi tải trang): nói cái gì sai, kèm cách sửa từ máy chủ. */
export function ActionError({ error }: { error: unknown }) {
  if (!error) return null
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error)
  return <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{msg}</p>
}

/** Khung cuộn ngang của bảng trong tài liệu: phải focus được bằng bàn phím (axe scrollable-region-focusable); không đặt role/nhãn vì mục cha đã là vùng có tên. */
export function Scroll({ children }: { children: React.ReactNode }) {
  return <div className="overflow-x-auto" tabIndex={0}>{children}</div>
}
