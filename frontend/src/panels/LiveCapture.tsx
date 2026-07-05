import { useState, useEffect, useRef, useCallback } from 'react'
import {
  getCaptureCapability, getCaptureInterfaces, startCapture, getCaptureStatus, stopCapture,
} from '../api'
import type { CaptureIface, CaptureResult } from '../api'

interface Props {
  onCaptured: (res: CaptureResult) => void
  onClose: () => void
}

type Phase = 'checking' | 'unavailable' | 'idle' | 'running' | 'stopping'

export function LiveCapture({ onCaptured, onClose }: Props) {
  const [phase, setPhase] = useState<Phase>('checking')
  const [message, setMessage] = useState('')
  const [ifaces, setIfaces] = useState<CaptureIface[]>([])
  const [iface, setIface] = useState('')
  const [src, setSrc] = useState('')
  const [dst, setDst] = useState('')
  const [port, setPort] = useState('')
  const [host, setHost] = useState('')
  const [maxPackets, setMaxPackets] = useState(5000)
  const [maxSeconds, setMaxSeconds] = useState(60)
  const [captureId, setCaptureId] = useState<string | null>(null)
  const [pktCount, setPktCount] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const pollRef = useRef<number | null>(null)

  useEffect(() => {
    (async () => {
      try {
        const cap = await getCaptureCapability()
        if (!cap.available) { setPhase('unavailable'); setMessage(cap.message); return }
        const list = await getCaptureInterfaces()
        const withIp = list.filter(i => i.has_ip)
        setIfaces(list)
        setIface((withIp[0] ?? list[0])?.name ?? '')
        setMessage(cap.admin_note)
        setPhase('idle')
      } catch (e) {
        setPhase('unavailable')
        setMessage(e instanceof Error ? e.message : String(e))
      }
    })()
    return () => { if (pollRef.current) window.clearInterval(pollRef.current) }
  }, [])

  const poll = useCallback((id: string) => {
    pollRef.current = window.setInterval(async () => {
      try {
        const s = await getCaptureStatus(id)
        setPktCount(s.packet_count)
        setElapsed(s.elapsed)
        if (!s.running && s.stopped) {   // auto-stopped (limit reached)
          if (pollRef.current) window.clearInterval(pollRef.current)
          finalize(id)
        }
      } catch { /* keep polling */ }
    }, 1000)
  }, [])

  const begin = async () => {
    setError(null)
    try {
      const r = await startCapture({
        iface,
        src: src.trim() || undefined,
        dst: dst.trim() || undefined,
        port: port.trim() ? Number(port) : undefined,
        host: host.trim() || undefined,
        max_packets: maxPackets,
        max_seconds: maxSeconds,
      })
      setCaptureId(r.capture_id)
      setPktCount(0); setElapsed(0)
      setPhase('running')
      poll(r.capture_id)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const finalize = async (id: string) => {
    setPhase('stopping')
    try {
      const res = await stopCapture(id)
      onCaptured(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setPhase('idle'); setCaptureId(null)
    }
  }

  const stop = () => {
    if (pollRef.current) window.clearInterval(pollRef.current)
    if (captureId) finalize(captureId)
  }

  return (
    <div className="cap-overlay" onClick={phase !== 'running' && phase !== 'stopping' ? onClose : undefined}>
      <div className="cap-modal" onClick={e => e.stopPropagation()}>
        <div className="cap-head">
          <span className="cap-title">🎙 Live Capture <span className="cap-beta">beta</span></span>
          {phase !== 'running' && phase !== 'stopping' && <button className="cap-x" onClick={onClose}>✕</button>}
        </div>

        {phase === 'checking' && <div className="cap-body"><div className="spinner sm" /> Checking capture capability…</div>}

        {phase === 'unavailable' && (
          <div className="cap-body">
            <div className="cap-warn">Live capture is unavailable on this system.</div>
            <p className="cap-msg">{message}</p>
            <p className="cap-hint">Live capture needs the <strong>Npcap</strong> driver (npcap.com) and the app must run
              as <strong>Administrator</strong>. Offline pcap analysis works without either.</p>
            <button className="filter-btn" onClick={onClose}>Close</button>
          </div>
        )}

        {(phase === 'idle' || phase === 'running' || phase === 'stopping') && (
          <div className="cap-body">
            <label className="cap-field">
              <span>Interface</span>
              <select className="cap-input" value={iface} disabled={phase !== 'idle'}
                onChange={e => setIface(e.target.value)}>
                {ifaces.map(i => (
                  <option key={i.name} value={i.name}>
                    {i.ip ? `${i.ip} — ` : ''}{i.description || i.name}
                  </option>
                ))}
              </select>
            </label>

            <div className="cap-grid">
              <label className="cap-field"><span>Source IP</span>
                <input className="cap-input" placeholder="any" value={src} disabled={phase !== 'idle'} onChange={e => setSrc(e.target.value)} /></label>
              <label className="cap-field"><span>Destination IP</span>
                <input className="cap-input" placeholder="any" value={dst} disabled={phase !== 'idle'} onChange={e => setDst(e.target.value)} /></label>
              <label className="cap-field"><span>Port</span>
                <input className="cap-input" placeholder="any" value={port} disabled={phase !== 'idle'} onChange={e => setPort(e.target.value)} /></label>
              <label className="cap-field"><span>Host IP (src or dst)</span>
                <input className="cap-input" placeholder="any" value={host} disabled={phase !== 'idle'} onChange={e => setHost(e.target.value)} /></label>
              <label className="cap-field"><span>Max packets</span>
                <input className="cap-input" type="number" value={maxPackets} disabled={phase !== 'idle'} onChange={e => setMaxPackets(Number(e.target.value))} /></label>
              <label className="cap-field"><span>Max seconds</span>
                <input className="cap-input" type="number" value={maxSeconds} disabled={phase !== 'idle'} onChange={e => setMaxSeconds(Number(e.target.value))} /></label>
            </div>

            {phase === 'idle' && (
              <>
                <p className="cap-hint">{message} Filters build a BPF like <code>src host … and dst host … and port …</code>. Captured 100% locally.</p>
                {error && <div className="cap-err">{error}</div>}
                <div className="cap-actions">
                  <button className="filter-btn cap-start" onClick={begin} disabled={!iface}>● Start capture</button>
                  <button className="filter-btn" style={{ background: '#4a5568' }} onClick={onClose}>Cancel</button>
                </div>
              </>
            )}

            {phase === 'running' && (
              <div className="cap-live">
                <div className="cap-live-stat"><span className="cap-rec">● REC</span> {pktCount.toLocaleString()} packets · {elapsed.toFixed(0)}s</div>
                <div className="cap-live-hint">Auto-stops at {maxPackets.toLocaleString()} packets or {maxSeconds}s.</div>
                <button className="filter-btn cap-stop" onClick={stop}>■ Stop & analyze</button>
              </div>
            )}

            {phase === 'stopping' && <div className="cap-live"><div className="spinner sm" /> Stopping & analyzing {pktCount.toLocaleString()} packets…</div>}
          </div>
        )}
      </div>
    </div>
  )
}
