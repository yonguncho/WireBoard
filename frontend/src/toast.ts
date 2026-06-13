// 전역 토스트 + 클립보드 복사 유틸 — 구독자(App)에게 메시지를 전달한다.
type ToastListener = (msg: string) => void

let _listener: ToastListener | null = null

export function subscribeToast(fn: ToastListener): () => void {
  _listener = fn
  return () => { if (_listener === fn) _listener = null }
}

export function showToast(msg: string): void {
  _listener?.(msg)
}

export async function copyText(text: string, label?: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
    showToast(`${label ?? text} 복사됨`)
  } catch {
    // clipboard API 실패 시 폴백 (http 환경 등)
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
    showToast(`${label ?? text} 복사됨`)
  }
}
