// Global toast + clipboard copy utility — delivers messages to the subscriber (App).
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
    showToast(`${label ?? text} copied`)
  } catch {
    // Fallback when the clipboard API fails (e.g. plain http environments)
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
    showToast(`${label ?? text} copied`)
  }
}
