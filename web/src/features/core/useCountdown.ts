import { useEffect, useState } from 'react'

/** Đếm ngược theo giây (nút "gửi lại mã"). `start(n)` đặt lại; chạy theo đồng hồ nên không trôi khi tab ngủ. */
export function useCountdown() {
  const [until, setUntil] = useState(0)
  const [left, setLeft] = useState(0)
  useEffect(() => {
    if (!until) return
    const tick = () => { const s = Math.max(0, Math.ceil((until - Date.now()) / 1000)); setLeft(s); if (s === 0) setUntil(0) }
    tick()
    const id = setInterval(tick, 500)
    return () => clearInterval(id)
  }, [until])
  return { left, start: (seconds: number) => setUntil(Date.now() + seconds * 1000) }
}
