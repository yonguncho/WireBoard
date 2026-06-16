import { useState } from 'react'
import { IpRankEntry, DrilldownSession, getDrilldown } from '../api'

interface Props {
  data: IpRankEntry[]
  uploadId?: string
  onFlowSelect?: (sessionId: string) => void
}

interface DrillState { ip: string; sessions: DrilldownSession[]; count: number; truncated: boolean }

function fmt(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

function fmtTs(ts: number) {
  return new Date(ts * 1000).toLocaleTimeString()
}

export function Panel6IpRanking({ data, uploadId, onFlowSelect }: Props) {
  const rows = (data ?? []).slice(0, 20)
  const [drill, setDrill] = useState<DrillState | null>(null)
  const [loading, setLoading] = useState(false)

  const openDrill = async (ip: string) => {
    if (!uploadId) return
    setLoading(true)
    try {
      const r = await getDrilldown(uploadId, ip)
      setDrill({ ip: r.ip, sessions: r.sessions, count: r.session_count, truncated: r.truncated })
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
      <table className="mini-table full-width">
        <thead>
          <tr><th>#</th><th>IP</th><th>Bytes</th><th>Type</th></tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={r.ip} className={i < 3 ? 'row-highlight' : ''}
              style={uploadId ? { cursor: 'pointer' } : {}}
              onClick={() => openDrill(r.ip)}>
              <td>{i + 1}</td>
              <td className="mono">{r.ip}</td>
              <td>{fmt(r.bytes)}</td>
              <td><span className={`badge ${r.is_internal ? 'badge-int' : 'badge-ext'}`}>{r.is_internal ? 'INT' : 'EXT'}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      {loading && <div style={{ textAlign: 'center', color: '#a0aec0', fontSize: 12, marginTop: 4 }}>Loading...</div>}
      {drill && (
        <div className="drilldown-backdrop" onClick={() => setDrill(null)}>
        <div className="drilldown-modal" onClick={e => e.stopPropagation()}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <strong style={{ color: '#63b3ed' }}>
              {drill.ip} — {drill.count} Sessions
              {drill.truncated && <span style={{ color: '#a0aec0', fontWeight: 400, fontSize: 11, marginLeft: 6 }}>(showing top 50 by bytes)</span>}
            </strong>
            <button className="filter-btn" style={{ background: '#4a5568', padding: '2px 8px' }} onClick={() => setDrill(null)}>✕</button>
          </div>
          <table className="mini-table full-width">
            <thead>
              <tr>
                <th>Destination</th><th>Port</th><th>Protocol</th><th>Bytes</th><th>Start</th><th>RST</th>
                {onFlowSelect && <th>Flow</th>}
              </tr>
            </thead>
            <tbody>
              {drill.sessions.map(s => {
                const peer = s.src_ip === drill.ip ? s.dst_ip : s.src_ip
                const port = s.src_ip === drill.ip ? s.dst_port : s.src_port
                const bytes = s.bytes_sent + s.bytes_recv
                return (
                  <tr key={s.session_id} className={s.rst ? 'row-error' : ''}>
                    <td className="mono">{peer}</td>
                    <td>{port}</td>
                    <td>{s.protocol}</td>
                    <td>{fmt(bytes)}</td>
                    <td>{fmtTs(s.start_ts)}</td>
                    <td>{s.rst ? '⚠' : ''}</td>
                    {onFlowSelect && (
                      <td><button className="flow-open-btn" onClick={() => openFlow(s.session_id)} title="Open packet viewer">Packets ▶</button></td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        </div>
      )}
    </div>
  )
}
