// Kho dữ liệu của mock API. Trình duyệt: lưu localStorage để dữ liệu người dùng nhập còn sau khi tải lại;
// test: chỉ trong bộ nhớ. Nút "Khôi phục dữ liệu mẫu" trong Cài đặt gọi resetMockDb().
// Đổi số khi cấu trúc dữ liệu lưu trong trình duyệt thay đổi không tương thích: mọi trình duyệt bắt đầu lại sạch.
// v2: tiếng Anh (D-28). v3: phản ứng D-51, Incidents D-52, kênh có người duyệt (2026-11-09). v4: tên bảng theo tiền tố module (D-57 (12), WP-06).
const KEY = 'vedette-mock-db-v4'
const persist = typeof window !== 'undefined' && import.meta.env.MODE !== 'test'

let cache: Record<string, unknown> | null = null
function load(): Record<string, unknown> {
  if (cache) return cache
  cache = {}
  if (persist) {
    try { cache = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Record<string, unknown> } catch { cache = {} }
  }
  return cache
}
function save() {
  if (!persist || !cache) return
  try { localStorage.setItem(KEY, JSON.stringify(cache)) } catch { /* đầy bộ nhớ: bỏ qua, dữ liệu vẫn trong phiên */ }
}

export interface Collection<T> { get(): T; set(v: T): void; update(fn: (v: T) => T): T }

// Chế độ dữ liệu: 'sample' = bản xem thử có dữ liệu mẫu (mặc định); 'clean' = cài thật, mọi bảng bắt đầu rỗng
// (người dùng tự khai thiết bị, cấu hình kênh…). Cài đặt ban đầu chọn chế độ; "Xoá toàn bộ dữ liệu" về lại chưa chọn.
const MODE = '__mode'
export type DataMode = 'sample' | 'clean'
export const dataMode = (): DataMode => (load()[MODE] === 'clean' ? 'clean' : 'sample')
export function setDataMode(m: DataMode) { load()[MODE] = m; save() }

/**
 * Một "bảng" của mock. `seed` chỉ chạy khi chưa có dữ liệu. Tên = tiền tố module (rule modules.md).
 * `empty`: giá trị khi cài sạch. Bắt buộc với bảng chứa DỮ LIỆU MẪU (thiết bị, sự kiện, lịch sử…);
 * bỏ trống với bảng chỉ chứa cấu hình mặc định hợp lý cho người dùng thật.
 */
export function collection<T>(name: string, seed: () => T, empty?: () => T): Collection<T> {
  return {
    get() {
      const db = load()
      if (!(name in db)) { db[name] = dataMode() === 'clean' && empty ? empty() : seed(); save() }
      return db[name] as T
    },
    set(v) { load()[name] = v; save() },
    update(fn) { const v = fn(this.get()); this.set(v); return v },
  }
}

/** Đọc một bảng mà KHÔNG gieo dữ liệu (undefined nếu chưa có). Dùng khi đọc chéo module trong mock. */
export function peek<T>(name: string): T | undefined {
  return load()[name] as T | undefined
}

export function resetMockDb() {
  cache = {}
  if (persist) { try { localStorage.removeItem(KEY) } catch { /* bỏ qua */ } }
}

let seq = 0
export function newId(prefix: string) {
  seq += 1
  return `${prefix}-${Date.now().toString(36)}${seq.toString(36)}`
}

export const nowIso = () => new Date().toISOString()
export const daysAgo = (d: number, h = 0) => new Date(Date.now() - d * 864e5 - h * 36e5).toISOString()
