import { useEffect, useState, useMemo } from 'react'
import type { ReactNode } from 'react'
import { getFlow, getStream } from '../api'
import type { FlowData, FlowPacket, StreamData, TlsInfo } from '../api'

// ── TCP Expert Info (backend tags) ─────────────────────────────────────────────
const EXPERT_SHORT: Record<string, string> = {
  retransmission: 'RETX', out_of_order: 'OOO', lost_segment: 'LOST',
  duplicate_ack: 'DUP-ACK', zero_window: 'ZWIN', window_full: 'WUPD',
  keep_alive: 'KA', reset: 'RST',
}
const EXPERT_LABEL: Record<string, string> = {
  retransmission: 'Retransmission (previously-seen sequence)',
  out_of_order: 'Out-of-order segment',
  lost_segment: 'Previous segment not captured (sequence gap)',
  duplicate_ack: 'Duplicate ACK',
  zero_window: 'Zero window — receiver buffer full',
  window_full: 'Window update after zero window',
  keep_alive: 'Keep-alive probe',
  reset: 'Connection reset (RST)',
}
const EXPERT_SEV: Record<string, string> = {
  zero_window: 'warn', out_of_order: 'warn', lost_segment: 'warn', reset: 'warn',
  retransmission: 'note', duplicate_ack: 'note', window_full: 'note', keep_alive: 'note',
}
function expertSev(tag: string): string { return EXPERT_SEV[tag] ?? 'note' }

// ── HEX utils ─────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): number[] {
  return (hex.replace(/\s+/g, '').match(/.{1,2}/g) ?? []).map(b => parseInt(b, 16))
}

function formatHexDump(hex: string): string {
  if (!hex) return ''
  const bytes = hexToBytes(hex)
  const lines: string[] = []
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16)
    const offset = i.toString(16).padStart(4, '0')
    const hexPart = chunk
      .map((b, j) => (j === 8 ? ' ' + b.toString(16).padStart(2, '0') : b.toString(16).padStart(2, '0')))
      .join(' ')
      .padEnd(49)
    const asciiPart = chunk.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('')
    lines.push(`${offset}  ${hexPart}  ${asciiPart}`)
  }
  return lines.join('\n')
}

function hexToAscii(hex: string): string {
  return hexToBytes(hex)
    .map(b => (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13 ? String.fromCharCode(b) : '.')
    .join('')
}

// ── Protocol decode ──────────────────────────────────────────────────────────

function decodeInfo(pkt: FlowPacket): string {
  const flags    = pkt.flags || ''
  const isSyn    = flags.includes('SYN') && !flags.includes('ACK')
  const isSynAck = flags.includes('SYN') && flags.includes('ACK')
  const isRst    = flags.includes('RST')
  const isFin    = flags.includes('FIN')

  if (!pkt.payload_hex || pkt.payload_len === 0) {
    if (isSyn)    return 'Connection request (SYN)'
    if (isSynAck) return 'Connection accept (SYN+ACK)'
    if (isRst)    return 'Connection reset (RST)'
    if (isFin)    return 'Connection close (FIN)'
    return 'Acknowledgment (ACK)'
  }

  const ascii = hexToAscii(pkt.payload_hex).trimStart()
  const httpReq = ascii.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP\/[\d.]+/)
  if (httpReq) return `HTTP ${httpReq[1]} ${httpReq[2]}`
  const httpRes = ascii.match(/^HTTP\/([\d.]+)\s+(\d+)\s*([^\r\n]*)/)
  if (httpRes) return `HTTP ${httpRes[2]} ${httpRes[3].trim() || 'OK'}`
  if (pkt.proto === 'UDP') return `UDP ${pkt.payload_len} bytes`
  if (isRst) return `RST+data ${pkt.payload_len} bytes`
  if (isFin) return `FIN+data ${pkt.payload_len} bytes`
  return `Data ${pkt.payload_len} bytes`
}

// ── Connection analysis (client-side) ────────────────────────────────────────

interface FlowAnalysis {
  handshake: string; rttMs: number | null
  retransmits: number; dataPkts: number
  closeType: string; score: number; status: string; issues: string[]
}

function computeFlowAnalysis(packets: FlowPacket[]): FlowAnalysis {
  const fwd = packets.filter(p => p.direction === 'fwd')
  const rev = packets.filter(p => p.direction === 'rev')
  const synPkt    = fwd.find(p => p.flags?.includes('SYN') && !p.flags?.includes('ACK'))
  const synAckPkt = rev.find(p => p.flags?.includes('SYN') && p.flags?.includes('ACK'))
  const rstPkts   = packets.filter(p => p.flags?.includes('RST'))
  const finPkts   = packets.filter(p => p.flags?.includes('FIN'))

  const rttMs = synPkt && synAckPkt && synAckPkt.ts > synPkt.ts
    ? Math.round((synAckPkt.ts - synPkt.ts) * 10000) / 10 : null

  let handshake = 'N/A'
  if (synPkt) {
    if (synAckPkt) handshake = 'COMPLETE'
    else if (rstPkts.some(p => p.direction === 'rev')) handshake = 'REFUSED'
    else if (!rev.length) handshake = 'TIMEOUT'
    else handshake = 'HALF_OPEN'
  }

  const seen = new Set<string>()
  let retransmits = 0, dataPkts = 0
  for (const p of packets) {
    if (p.payload_len > 0 && p.proto === 'TCP') {
      const key = `${p.direction}:${p.seq}`
      dataPkts++
      if (seen.has(key)) retransmits++
      else seen.add(key)
    }
  }

  const closeType = rstPkts.length ? 'RESET' : finPkts.length ? 'NORMAL' : 'TIMEOUT'

  let score = 100; const issues: string[] = []
  if (handshake === 'REFUSED')   { score -= 40; issues.push('Connection refused (server RST)') }
  else if (handshake === 'TIMEOUT')   { score -= 35; issues.push('No connection response (timeout)') }
  else if (handshake === 'HALF_OPEN') { score -= 25; issues.push('Incomplete handshake') }
  if (rttMs !== null) {
    if (rttMs > 500) { score -= 20; issues.push(`Critical RTT (${rttMs.toFixed(1)} ms)`) }
    else if (rttMs > 150) { score -= 10; issues.push(`High RTT (${rttMs.toFixed(1)} ms)`) }
  }
  const rr = dataPkts ? retransmits / dataPkts : 0
  if (rr > 0.20) { score -= 30; issues.push(`Excessive retransmits (${(rr * 100).toFixed(0)}%)`) }
  else if (rr > 0.05) { score -= 15; issues.push(`Retransmits present (${(rr * 100).toFixed(0)}%)`) }
  if (closeType === 'RESET') { score -= 10; issues.push('RST forced close') }
  score = Math.max(0, Math.min(100, score))
  const status = score >= 80 ? 'Healthy' : score >= 50 ? 'Warning' : 'Critical'
  return { handshake, rttMs, retransmits, dataPkts, closeType, score, status, issues }
}

// ── Subcomponents ────────────────────────────────────────────────────────────

function fmtBytes(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}
function fmtRelTs(s: number) {
  return s < 1 ? '+' + (s * 1000).toFixed(1) + ' ms' : '+' + s.toFixed(3) + ' s'
}

function FlagBadge({ flags }: { flags: string }) {
  if (!flags || flags === '—') return <span className="flag-badge flag-none">—</span>
  const cls = flags.includes('RST') ? 'flag-rst'
    : flags.includes('SYN') && flags.includes('ACK') ? 'flag-synack'
    : flags.includes('SYN') ? 'flag-syn'
    : flags.includes('FIN') ? 'flag-fin'
    : flags.includes('PSH') ? 'flag-psh' : 'flag-ack'
  return <span className={`flag-badge ${cls}`}>{flags}</span>
}

function PacketRow({ pkt, idx, base }: { pkt: FlowPacket; idx: number; base: string }) {
  const [expanded, setExpanded] = useState(false)
  const isFwd = pkt.direction === 'fwd'
  const info  = decodeInfo(pkt)
  const hasHex = !!pkt.payload_hex && pkt.payload_len > 0
  return (
    <>
      <tr
        className={`pkt-row ${isFwd ? 'pkt-fwd' : 'pkt-rev'}`}
        onClick={() => hasHex && setExpanded(v => !v)}
        style={{ cursor: hasHex ? 'pointer' : 'default' }}
        title={hasHex ? 'Click → HEX dump' : ''}
      >
        <td className="mono pkt-num">{idx + 1}</td>
        <td className="mono pkt-relts">{idx === 0 ? '0.000 s' : fmtRelTs(pkt.rel_ts)}</td>
        <td className="pkt-dir">
          {isFwd ? <span className="dir-fwd">→ {base}</span> : <span className="dir-rev">← {base}</span>}
        </td>
        <td><FlagBadge flags={pkt.flags} /></td>
        <td className="mono">{pkt.proto === 'TCP' && pkt.seq != null ? pkt.seq.toLocaleString() : '—'}</td>
        <td className="mono">{pkt.proto === 'TCP' && pkt.ack != null ? pkt.ack.toLocaleString() : '—'}</td>
        <td className="mono">{pkt.length}</td>
        <td className="mono">{pkt.payload_len > 0 ? pkt.payload_len : '—'}</td>
        <td className="pkt-expert-cell">
          {(pkt.expert ?? []).map(t => (
            <span key={t} className={`pkt-expert-tag exp-${expertSev(t)}`} title={EXPERT_LABEL[t] ?? t}>{EXPERT_SHORT[t] ?? t}</span>
          ))}
        </td>
        <td className="pkt-info-cell">{info}{hasHex && <span className="hex-expand-hint">{expanded ? ' ▲' : ' ▼'}</span>}</td>
      </tr>
      {expanded && pkt.payload_hex && (
        <tr className="pkt-hex-row">
          <td colSpan={10}>
            <pre className="hex-dump-wireshark">{formatHexDump(pkt.payload_hex)}</pre>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Ladder (Flow Sequence) diagram ───────────────────────────────────────────

function ladderColor(pkt: FlowPacket): string {
  const flags = pkt.flags || ''
  if (flags.includes('RST')) return '#ef4444'
  if (flags.includes('SYN') && flags.includes('ACK')) return '#c084fc'
  if (flags.includes('SYN')) return '#60a5fa'
  if (flags.includes('FIN')) return '#f59e0b'
  if (pkt.payload_len > 0) return '#22c55e'
  return '#718096'
}

const LADDER_LEGEND: [string, string][] = [
  ['#60a5fa', 'SYN'], ['#c084fc', 'SYN+ACK'], ['#22c55e', 'Data'],
  ['#718096', 'ACK'], ['#f59e0b', 'FIN'], ['#ef4444', 'RST'],
]

function LadderView({ packets, session }: { packets: FlowPacket[]; session: FlowData['session'] | null }) {
  const [selected, setSelected] = useState<number | null>(null)
  if (!session) return null
  if (!packets.length) return <div className="flow-no-packets">No packets (unsupported for non-PCAP formats)</div>

  const rows: ReactNode[] = []
  packets.forEach((p, i) => {
    const prev = packets[i - 1]
    const gap = prev ? p.rel_ts - prev.rel_ts : 0
    if (gap >= 1) {
      rows.push(
        <div key={`gap-${i}`} className="ladder-gap">
          <span className="ladder-gap-line" />
          <span className="ladder-gap-label">⏱ {gap.toFixed(1)}s gap</span>
          <span className="ladder-gap-line" />
        </div>
      )
    }
    const color = ladderColor(p)
    const isFwd = p.direction === 'fwd'
    const hasHex = !!p.payload_hex && p.payload_len > 0
    const isSel = selected === i
    rows.push(
      <div
        key={i}
        className={`ladder-row${isSel ? ' selected' : ''}`}
        onClick={() => hasHex && setSelected(isSel ? null : i)}
        style={{ cursor: hasHex ? 'pointer' : 'default' }}
        title={hasHex ? 'Click → HEX dump' : ''}
      >
        <span className="ladder-time">{i === 0 ? '0.000 s' : fmtRelTs(p.rel_ts)}</span>
        <div className="ladder-arrow-track">
          <div className={`ladder-arrow ${isFwd ? 'fwd' : 'rev'}`} style={{ color }}>
            <span className="ladder-arrow-line" style={{ background: color }} />
            <span className="ladder-arrow-head" />
            <span className="ladder-arrow-label" style={{ color }}>{decodeInfo(p)}</span>
          </div>
        </div>
        <span className="ladder-bytes">{p.payload_len > 0 ? fmtBytes(p.payload_len) : (p.flags || '—')}</span>
        {isSel && p.payload_hex && (
          <pre className="ladder-hex">{formatHexDump(p.payload_hex)}</pre>
        )}
      </div>
    )
  })

  return (
    <div className="ladder-wrap">
      <div className="ladder-endpoints">
        <span className="ladder-endpoint src">
          {session.src_ip}<span className="ep-port">:{session.src_port}</span>
        </span>
        <span style={{ fontSize: 11, color: 'var(--txt-muted)' }}>{session.protocol} flow · {packets.length} packets</span>
        <span className="ladder-endpoint dst">
          {session.dst_ip}<span className="ep-port">:{session.dst_port}</span>
        </span>
      </div>
      <div className="ladder-body">
        <span className="ladder-rail" style={{ left: 98 }} />
        <span className="ladder-rail" style={{ right: 90 }} />
        {rows}
      </div>
      <div className="ladder-legend">
        {LADDER_LEGEND.map(([c, label]) => (
          <span key={label} className="ladder-legend-item">
            <span className="ladder-legend-swatch" style={{ background: c }} />{label}
          </span>
        ))}
        <span className="ladder-legend-item" style={{ marginLeft: 'auto' }}>→ Sent · ← Received · Click row for HEX</span>
      </div>
    </div>
  )
}

function ReplayView({ packets }: { packets: FlowPacket[] }) {
  const segments = useMemo(() =>
    packets
      .filter(p => p.payload_hex && p.payload_len > 0)
      .map(p => ({ dir: p.direction, info: decodeInfo(p), text: hexToAscii(p.payload_hex!) }))
      .filter(s => s.text.trim().length > 0),
    [packets]
  )
  if (!segments.length) return <div className="replay-empty">No payload to replay</div>
  return (
    <div className="replay-view">
      {segments.map((seg, i) => (
        <div key={i} className={`replay-segment ${seg.dir === 'fwd' ? 'replay-fwd' : 'replay-rev'}`}>
          <div className="replay-dir-label">
            {seg.dir === 'fwd' ? '→ Sent' : '← Received'}
            <span className="replay-info-tag"> [{seg.info}]</span>
          </div>
          <pre className="replay-text">{seg.text}</pre>
        </div>
      ))}
    </div>
  )
}

function MetricRow({ label, value, cls }: { label: string; value: string; cls: string }) {
  const color = cls === 'ok' ? '#22c55e' : cls === 'bad' ? '#ef4444' : cls === 'warn' ? '#f59e0b' : 'var(--txt-secondary)'
  return (
    <div className="metric-row">
      <span className="metric-label">{label}</span>
      <span className="metric-value" style={{ color }}>{value}</span>
    </div>
  )
}

interface ExpertEvent { severity: 'error' | 'warn' | 'note'; pktIdx: number; relTs: number; msg: string }

function buildExpertEvents(packets: FlowPacket[]): ExpertEvent[] {
  const events: ExpertEvent[] = []
  const seenSeqs = new Map<string, number>()

  packets.forEach((p, i) => {
    const flags = p.flags || ''
    const relTs = p.rel_ts

    if (flags.includes('SYN') && !flags.includes('ACK') && i > 0)
      events.push({ severity: 'warn', pktIdx: i, relTs, msg: 'SYN retransmit' })

    if (p.payload_len > 0 && p.proto === 'TCP') {
      const key = `${p.direction}:${p.seq}`
      const prev = seenSeqs.get(key)
      if (prev !== undefined) {
        events.push({ severity: 'warn', pktIdx: i, relTs, msg: `TCP retransmit (Seq ${p.seq}, packet #${prev + 1})` })
      } else {
        seenSeqs.set(key, i)
      }
    }

    if (flags.includes('RST')) {
      const hasData = packets.slice(0, i).some(q => q.payload_len > 0)
      events.push({ severity: hasData ? 'error' : 'warn', pktIdx: i, relTs, msg: hasData ? 'RST — forced close during data transfer' : 'RST — refused before connection established' })
    }

    if (p.seq === 0 && p.ack === 0 && !flags.includes('SYN') && p.payload_len === 0 && p.proto === 'TCP')
      events.push({ severity: 'note', pktIdx: i, relTs, msg: 'Seq/Ack both 0 — capture may be incomplete' })
  })

  return events
}

function ConnAnalysisView({ packets, session }: { packets: FlowPacket[]; session: FlowData['session'] | null }) {
  const a = useMemo(() => computeFlowAnalysis(packets), [packets])
  const expertEvents = useMemo(() => buildExpertEvents(packets), [packets])
  if (!session) return null

  const hsLabel: Record<string, string> = { COMPLETE: '✓ Complete', REFUSED: '✗ Refused', TIMEOUT: '✗ Timeout', HALF_OPEN: '⚠ Incomplete', 'N/A': '— N/A' }
  const hsClass: Record<string, string> = { COMPLETE: 'ok', REFUSED: 'bad', TIMEOUT: 'bad', HALF_OPEN: 'warn', 'N/A': 'neutral' }
  const closeLabel: Record<string, string> = { NORMAL: '✓ Normal (FIN)', RESET: '✗ Forced (RST)', TIMEOUT: '⚠ Timeout', 'N/A': '—' }

  const scoreColor = a.score >= 80 ? '#22c55e' : a.score >= 50 ? '#f59e0b' : '#ef4444'

  return (
    <div className="conn-analysis">
      <div className="conn-score-row">
        <div className="conn-score-circle" style={{ borderColor: scoreColor }}>
          <span className="conn-score-num" style={{ color: scoreColor }}>{a.score}</span>
          <span className="conn-score-label">{a.status}</span>
        </div>
        <div className="conn-metrics">
          <MetricRow label="Handshake"  value={hsLabel[a.handshake] ?? a.handshake}    cls={hsClass[a.handshake] ?? 'neutral'} />
          <MetricRow label="RTT"        value={a.rttMs !== null ? `${a.rttMs.toFixed(1)} ms` : 'Not measurable'} cls={a.rttMs !== null && a.rttMs > 150 ? 'warn' : 'ok'} />
          <MetricRow label="Retransmits" value={a.dataPkts ? `${a.retransmits} / ${a.dataPkts} packets (${Math.round(a.retransmits / a.dataPkts * 100)}%)` : 'None'} cls={a.retransmits > 0 ? 'warn' : 'ok'} />
          <MetricRow label="Close"      value={closeLabel[a.closeType] ?? a.closeType}   cls={a.closeType === 'NORMAL' ? 'ok' : a.closeType === 'RESET' ? 'bad' : 'warn'} />
          <MetricRow label="Session Time" value={`${session.duration_s.toFixed(3)} s`}    cls="neutral" />
          <MetricRow label="Sent/Received"  value={`${fmtBytes(session.bytes_sent)} / ${fmtBytes(session.bytes_recv)}`} cls="neutral" />
        </div>
      </div>
      {a.issues.length > 0 ? (
        <div className="conn-issues">
          <div className="conn-issues-title">Diagnosis</div>
          {a.issues.map((issue, i) => (
            <div key={i} className="conn-issue-item"><span className="conn-issue-icon">⚠</span> {issue}</div>
          ))}
        </div>
      ) : (
        <div className="conn-ok-msg">✓ No anomalies — normal communication</div>
      )}

      {expertEvents.length > 0 && (
        <div className="expert-info">
          <div className="expert-info-title">Expert Information</div>
          <table className="expert-table">
            <thead><tr><th>#</th><th>+Time</th><th>Level</th><th>Details</th></tr></thead>
            <tbody>
              {expertEvents.map((ev, i) => {
                const sev = ev.severity === 'error' ? { color: '#ef4444', icon: '✗' }
                  : ev.severity === 'warn' ? { color: '#f59e0b', icon: '⚠' }
                  : { color: '#63b3ed', icon: 'ℹ' }
                return (
                  <tr key={i} className="expert-row">
                    <td className="mono">{ev.pktIdx + 1}</td>
                    <td className="mono">+{ev.relTs.toFixed(3)}s</td>
                    <td><span className="expert-sev" style={{ color: sev.color }}>{sev.icon}</span></td>
                    <td className="expert-msg">{ev.msg}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Follow Stream ────────────────────────────────────────────────────────────

function FollowStreamView({ uploadId, sessionId, session }: {
  uploadId: string; sessionId: string; session: FlowData['session'] | null
}) {
  const [data, setData] = useState<StreamData | null>(null)
  const [encoding, setEncoding] = useState<'ascii' | 'hex'>('ascii')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true); setError(null); setData(null)
    getStream(uploadId, sessionId, encoding)
      .then(setData)
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }, [uploadId, sessionId, encoding])

  if (loading) return <div className="flow-loading"><div className="spinner sm" />Loading...</div>
  if (error) return <div className="flow-error">{error}</div>
  if (!data || data.segments.length === 0) return <div className="flow-no-packets">No payload — stream reassembly not possible</div>

  return (
    <div className="follow-stream">
      <div className="follow-stream-toolbar">
        <span className="follow-stream-stats">
          ↑ {fmtBytes(data.fwd_bytes)} sent · ↓ {fmtBytes(data.rev_bytes)} received
          {data.truncated && <span className="trunc-badge"> (top 200 packets)</span>}
        </span>
        <div className="follow-encoding-btns">
          <button className={`follow-enc-btn${encoding === 'ascii' ? ' active' : ''}`} onClick={() => setEncoding('ascii')}>ASCII</button>
          <button className={`follow-enc-btn${encoding === 'hex' ? ' active' : ''}`} onClick={() => setEncoding('hex')}>HEX</button>
        </div>
      </div>
      {session && (
        <div className="follow-stream-legend">
          <span className="follow-fwd-legend">■ {session.src_ip}:{session.src_port} (sent)</span>
          <span className="follow-rev-legend">■ {session.dst_ip}:{session.dst_port} (received)</span>
        </div>
      )}
      <div className="follow-stream-body">
        {data.segments.map((seg, i) => (
          <div key={i} className={`follow-segment follow-${seg.direction}`}>
            <div className="follow-seg-header">
              <span className="follow-seg-dir">{seg.direction === 'fwd' ? '→' : '←'}</span>
              <span className="follow-seg-ts">+{seg.rel_ts.toFixed(3)}s</span>
              <span className="follow-seg-len">{seg.length} B</span>
              {seg.flags && <span className="follow-seg-flags">{seg.flags}</span>}
            </div>
            <pre className={`follow-seg-text${encoding === 'hex' ? ' hex-mode' : ''}`}>{seg.text}</pre>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── TLS handshake detail ─────────────────────────────────────────────────────

function TlsRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="tls-row">
      <span className="tls-label">{label}</span>
      <span className="tls-value">{value || <span className="tls-na">—</span>}</span>
    </div>
  )
}

function TlsView({ tls }: { tls: TlsInfo }) {
  const alerts = tls.alerts ?? []
  const stages = tls.handshake_stages ?? []
  return (
    <div className="tls-view">
      {/* Handshake outcome + Alerts — "TLS에서 끊김" 진단 */}
      {(alerts.length > 0 || tls.handshake_complete !== undefined) && (
        <div className="tls-card">
          <div className="tls-card-title">Handshake Result</div>
          <TlsRow label="Status" value={
            alerts.some(a => a.level === 'fatal')
              ? <span className="badge badge-err">FAILED (fatal alert)</span>
              : tls.handshake_complete
                ? <span className="badge badge-ok">Completed</span>
                : <span className="badge" style={{ background: 'rgba(245,158,11,.2)', color: '#f59e0b' }}>Incomplete / not captured</span>
          } />
          {stages.length > 0 && (
            <TlsRow label="Stages seen" value={<span className="mono" style={{ fontSize: 11 }}>{stages.join(' → ')}</span>} />
          )}
          {alerts.map((a, i) => (
            <TlsRow key={i} label={`Alert (${a.from})`} value={
              <span className={a.level === 'fatal' ? 'badge badge-err' : 'badge'} style={a.level !== 'fatal' ? { background: 'rgba(245,158,11,.2)', color: '#f59e0b' } : undefined}>
                {a.level}: {a.description}
              </span>
            } />
          ))}
        </div>
      )}
      <div className="tls-card">
        <div className="tls-card-title">TLS Handshake</div>
        <TlsRow label="Server Name (SNI)" value={tls.sni && <span className="mono tls-sni">{tls.sni}</span>} />
        <TlsRow label="ALPN" value={tls.alpn && <span className="mono">{tls.alpn}</span>} />
        <TlsRow label="Negotiated Version" value={tls.negotiated_version && <span className="tls-ver">{tls.negotiated_version}</span>} />
        <TlsRow label="Client Offered Version" value={tls.client_version} />
        <TlsRow label="Chosen Cipher" value={tls.chosen_cipher && <span className="mono tls-cipher">{tls.chosen_cipher}</span>} />
        <TlsRow label="JA4 Fingerprint" value={tls.ja4 && <span className="mono tls-ja4">{tls.ja4}</span>} />
      </div>

      {tls.offered_ciphers.length > 0 && (
        <div className="tls-card">
          <div className="tls-card-title">
            Client Offered Cipher Suites
            <span className="tls-count"> ({tls.offered_cipher_count})</span>
          </div>
          <div className="tls-cipher-list">
            {tls.offered_ciphers.map((c, i) => (
              <span key={i} className={`tls-cipher-chip${c === tls.chosen_cipher ? ' tls-cipher-chosen' : ''}`}>{c}</span>
            ))}
            {tls.offered_cipher_count > tls.offered_ciphers.length && (
              <span className="tls-cipher-more">+{tls.offered_cipher_count - tls.offered_ciphers.length} more</span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main ─────────────────────────────────────────────────────────────────────

interface Props { uploadId: string; sessionId: string; onClose: () => void }
type ViewTab = 'ladder' | 'packets' | 'replay' | 'stream' | 'analysis' | 'tls'

export function FlowViewer({ uploadId, sessionId, onClose }: Props) {
  const [data, setData]   = useState<FlowData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [view, setView]   = useState<ViewTab>('ladder')

  useEffect(() => {
    setData(null); setError(null)
    getFlow(uploadId, sessionId)
      .then(setData)
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [uploadId, sessionId])

  const s        = data?.session
  const analysis = useMemo(() => data ? computeFlowAnalysis(data.packets) : null, [data])
  const scoreColor = analysis ? (analysis.score >= 80 ? '#22c55e' : analysis.score >= 50 ? '#f59e0b' : '#ef4444') : undefined

  return (
    <div className="flow-overlay" onClick={onClose}>
      <div className="flow-panel" onClick={e => e.stopPropagation()}>

        <div className="flow-panel-header">
          <div className="flow-title">
            {s ? (
              <span className="flow-tuple">
                <span className="flow-src">{s.src_ip}:{s.src_port}</span>
                <span className="flow-arrow"> → </span>
                <span className="flow-dst">{s.dst_ip}:{s.dst_port}</span>
                <span className="flow-proto-badge">{s.protocol}</span>
                {s.rst && <span className="flow-rst-badge">RST</span>}
                {analysis && (
                  <span className="flow-score-badge" style={{ background: scoreColor, color: '#111' }}>
                    {analysis.status} {analysis.score}
                  </span>
                )}
              </span>
            ) : 'Loading...'}
          </div>
          <button className="flow-close-btn" onClick={onClose}>✕</button>
        </div>

        {s && data && (
          <div className="flow-stats-bar">
            <span><strong>{data.packet_count.toLocaleString()}</strong> packets{data.truncated && <span className="trunc-badge"> (top 200)</span>}</span>
            <span>↑{fmtBytes(s.bytes_sent)}</span>
            <span>↓{fmtBytes(s.bytes_recv)}</span>
            <span>⏱{s.duration_s.toFixed(3)}s</span>
            {analysis?.rttMs !== null && analysis?.rttMs !== undefined && (
              <span style={{ color: (analysis.rttMs > 150 ? '#f59e0b' : '#22c55e') }}>RTT {analysis.rttMs.toFixed(1)} ms</span>
            )}
            {s.ip_badge && (
              <span title={`Observed TTL ${s.ip_badge.ttl}, assuming initial ${s.ip_badge.assumed_initial}`}>
                🛰 ~{s.ip_badge.estimated_hops} hops (TTL {s.ip_badge.ttl})
              </span>
            )}
            {s.wscale && (s.wscale.fwd > 0 || s.wscale.rev > 0) && (
              <span title="TCP window scale negotiated in SYN; true window = raw × factor">
                ⇅ WScale ×{s.wscale.fwd_factor}/×{s.wscale.rev_factor}
              </span>
            )}
            {s.l2 && (s.l2.src_vendor || s.l2.dst_vendor) && (
              <span title={`Src MAC ${s.l2.src_mac} · Dst MAC ${s.l2.dst_mac}`}>
                🖧 {s.l2.src_vendor ?? '?'} → {s.l2.dst_vendor ?? '?'}
              </span>
            )}
            {data.expert_summary && Object.keys(data.expert_summary).length > 0 && (
              <span style={{ color: '#f59e0b' }} title="TCP Expert Info events in this flow">
                ⚑ {Object.entries(data.expert_summary).map(([k, v]) => `${EXPERT_SHORT[k] ?? k}:${v}`).join(' ')}
              </span>
            )}
            <div className="flow-view-tabs">
              <button className={`flow-tab${view === 'ladder'   ? ' active' : ''}`} onClick={() => setView('ladder')}>Ladder</button>
              <button className={`flow-tab${view === 'packets'  ? ' active' : ''}`} onClick={() => setView('packets')}>Packets</button>
              <button className={`flow-tab${view === 'stream'   ? ' active' : ''}`} onClick={() => setView('stream')}>Follow Stream</button>
              <button className={`flow-tab${view === 'replay'   ? ' active' : ''}`} onClick={() => setView('replay')}>Replay</button>
              <button className={`flow-tab${view === 'analysis' ? ' active' : ''}`} onClick={() => setView('analysis')}>Connection Analysis</button>
              {data.tls && (
                <button className={`flow-tab flow-tab-tls${view === 'tls' ? ' active' : ''}`} onClick={() => setView('tls')}>🔒 TLS</button>
              )}
            </div>
          </div>
        )}

        {error && <div className="flow-error">{error}</div>}
        {!data && !error && <div className="flow-loading"><div className="spinner sm" />Loading...</div>}

        {data && view === 'packets' && s && (
          data.packets.length > 0 ? (
            <div className="flow-table-wrap">
              <table className="flow-table">
                <thead>
                  <tr><th>#</th><th>Time</th><th>Direction</th><th>Flags</th><th>Seq</th><th>Ack</th><th>Size</th><th>Payload</th><th>Expert</th><th>Info</th></tr>
                </thead>
                <tbody>
                  {data.packets.map((p, i) => <PacketRow key={i} pkt={p} idx={i} base={`${s.dst_ip}:${s.dst_port}`} />)}
                </tbody>
              </table>
            </div>
          ) : <div className="flow-no-packets">No packets (packet viewer unsupported for non-PCAP formats)</div>
        )}

        {data && view === 'ladder'   && <LadderView packets={data.packets} session={s ?? null} />}
        {data && view === 'stream'   && <FollowStreamView uploadId={uploadId} sessionId={sessionId} session={s ?? null} />}
        {data && view === 'replay'   && <ReplayView packets={data.packets} />}
        {data && view === 'analysis' && <ConnAnalysisView packets={data.packets} session={s ?? null} />}
        {data && view === 'tls' && data.tls && <TlsView tls={data.tls} />}
      </div>
    </div>
  )
}
