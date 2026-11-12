// Hợp đồng API (D-18): mỗi module khai endpoint bằng schema Zod trong features/<m>/contract.ts.
// Từ đây sinh api/openapi.json (`pnpm openapi`); test hợp đồng gọi mock và kiểm phản hồi khớp schema.
// Kiểu dùng trong UI lấy bằng z.infer từ chính schema này → UI, mock và backend M2 không lệch nhau.
import type { z } from 'zod'
import type { Role } from './session'

export type Method = 'get' | 'post' | 'put' | 'patch' | 'delete'

export interface Endpoint {
  method: Method
  /** Đường dẫn kiểu OpenAPI, không có tiền tố /api/v1. Ví dụ: /feeds/cve/{id} */
  path: string
  /** Một câu tiếng Việt: endpoint làm gì cho người dùng. */
  summary: string
  stories: string[]
  /** Vai tối thiểu; 'public' = không cần đăng nhập. */
  role: Role | 'public'
  params?: z.ZodObject
  query?: z.ZodObject
  body?: z.ZodType
  /** null = 204 không có nội dung. 'file' = tải tệp (CSV, JSON, rule). 'text' = văn bản thuần `text/plain; charset=utf-8` (danh sách chặn cho firewall). */
  response: z.ZodType | null | 'file' | 'text'
  /** Media type of a 'file' response; default application/octet-stream. */
  fileType?: string
  /** HTTP status của phản hồi thành công có nội dung (API_CONVENTIONS §12). Mặc định 200; 201 = tạo mới; 202 = đã nhận, chạy tiếp nền. Endpoint trả hai mã tuỳ tình huống: giữ mặc định và nói rõ trong `summary`. */
  status?: 200 | 201 | 202
  /** Giá trị để test hợp đồng gọi thử GET (đường dẫn có tham số cần example, không có thì bỏ qua). */
  example?: { params?: Record<string, string>; query?: Record<string, string> }
}

export const defineEndpoints = (e: Endpoint[]) => e
