import { useState } from 'react'
import { ConvEntry, DrilldownSession, getDrilldown } from '../api'

interface Props {
  data: ConvEntry[]
  uploadId?: string
  onFlowSelect?: (sessionId: string) => void
}

interface DrillState { src: string; dst: string; sessions: DrilldownSession[] }

function fmtBytes(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

export function Panel9Conversations({ data, uploadId, onFlowSelect }: Props) {
  const [sortBy, setSortBy] = useState<'bytes' | 'issues'>('bytes')
  const rows = [...(data ?? [])]
    .sort((a, b) => sortBy === 'issues'
      ? ((b.issue_rate ?? 0) - (a.issue_rate ?? 0)) || (b.bytes - a.bytes)
      : b.bytes - a.bytes)
    .slice(0, 20)
  const [drill, setDrill] = useState<DrillState | null>(null)
  const [loading, setLoading] = useState(false)

  const openDrill = async (src: string, dst: string) => {
    if (!uploadId) return
    setLoading(true)
    try {
      const r = await getDrilldown(uploadId, src, undefined, dst)
      setDrill({ src, dst, sessions: r.sessions })
    } catch { /* Ignore drill-down failures */ } finally {
      setLoading(false)
    }
  }

  const openFlow = (sessionId: string) => {
    if (onFlowSelect) {
      setDrill(null)
      onFlowSelect(sessionId)
    }
  }

  if (!rows.length) return <div className="no-data">No data</div>
  return (
    <div style={{ position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 4 }}>
        <select className="pkt-filter-input" style={{ width: 130, fontSize: 11 }}
          value={sortBy} onChange={e => setSortBy(e.target.value as 'bytes' | 'issues')}>
          <option value="bytes">Sort: traffic</option>
          <option value="issues">Sort: issue rate</option>
        </select>
      </div>
      <table className="mini-table full-width">
        <thead>
          <tr><th>SRC</th><th>DST</th><th>Packets</th><th>Bytes</th><th>Duration(s)</th><th>RST</th><th>No-reply</th></tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const hasIssue = (r.rst ?? 0) + (r.no_reply ?? 0) > 0
            return (
            <tr key={i} className={`conv-row${hasIssue ? ' row-error' : ''}`}
              style={uploadId ? { cursor: 'pointer' } : {}}
              onClick={() => openDrill(r.src, r.dst)}>
              <td className="mono">{r.src}</td>
              <td className="mono">{r.dst}</td>
              <td>{r.packets.toLocaleString()}</td>
              <td>{fmtBytes(r.bytes)}</td>
              <td>{r.duration_s.toFixed(1)}</td>
              <td>{(r.rst ?? 0) > 0 ? <span style={{ color: '#fc4343' }}>{r.rst}</span> : '—'}</td>
              <td>{(r.no_reply ?? 0) > 0 ? <span style={{ color: '#f59e0b' }}>{r.no_reply}</span> : '—'}</td>
            </tr>
            )
          })}
        </tbody>
      </table>
      {loading && <div style={{ textAlign: 'center', color: '#a0aec0', fontSize: 12, marginTop: 4 }}>Loading...</div>}
      {drill && (
        <div className="drilldown-backdrop" onClick={() => setDrill(null)}>
        <div className="drilldown-modal" onClick={e => e.stopPropagation()}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <strong style={{ color: '#63b3ed' }}>{drill.src} ↔ {drill.dst} — {drill.sessions.length} Sessions</strong>
            <button className="filter-btn" style={{ background: '#4a5568', padding: '2px 8px' }} onClick={() => setDrill(null)}>✕</button>
          </div>
          {drill.sessions.length === 0 ? (
            <div style={{ color: '#a0aec0', fontSize: 12 }}>No session data</div>
          ) : (
            <table className="mini-table full-width">
              <thead>
                <tr>
                  <th>Src Port</th><th>Dst Port</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>RST</th>
                  {onFlowSelect && <th>Flow</th>}
                </tr>
              </thead>
              <tbody>
                {drill.sessions.map(s => {
                  const forward = s.src_ip === drill.src
                  const srcPort = forward ? s.src_port : s.dst_port
                  const dstPort = forward ? s.dst_port : s.src_port
                  return (
                    <tr key={s.session_id} className={s.rst ? 'row-error' : ''}>
                      <td>{srcPort}</td>
                      <td>{dstPort}</td>
                      <td>{s.protocol}</td>
                      <td>{s.packet_count.toLocaleString()}</td>
                      <td>{fmtBytes(s.bytes_sent + s.bytes_recv)}</td>
                      <td>{s.rst ? '⚠' : ''}</td>
                      {onFlowSelect && (
                        <td><button className="flow-open-btn" onClick={() => openFlow(s.session_id)} title="Open packet viewer">Packets ▶</button></td>
                      )}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
        </div>
      )}
    </div>
  )
}
