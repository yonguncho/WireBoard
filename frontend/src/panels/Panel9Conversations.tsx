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
  const rows = (data ?? []).slice(0, 20)
  const [drill, setDrill] = useState<DrillState | null>(null)
  const [loading, setLoading] = useState(false)

  const openDrill = async (src: string, dst: string) => {
    if (!uploadId) return
    setLoading(true)
    try {
      const r = await getDrilldown(uploadId, src)
      setDrill({
        src, dst,
        sessions: r.sessions.filter(s =>
          (s.src_ip === src && s.dst_ip === dst) || (s.src_ip === dst && s.dst_ip === src)
        ),
      })
    } catch { /* 드릴다운 실패 시 무시 */ } finally {
      setLoading(false)
    }
  }

  const openFlow = (sessionId: string) => {
    if (onFlowSelect) {
      setDrill(null)
      onFlowSelect(sessionId)
    }
  }

  if (!rows.length) return <div className="no-data">데이터 없음</div>
  return (
    <div style={{ position: 'relative' }}>
      <table className="mini-table full-width">
        <thead>
          <tr><th>SRC</th><th>DST</th><th>패킷</th><th>바이트</th><th>시간(s)</th></tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="conv-row"
              style={uploadId ? { cursor: 'pointer' } : {}}
              onClick={() => openDrill(r.src, r.dst)}>
              <td className="mono">{r.src}</td>
              <td className="mono">{r.dst}</td>
              <td>{r.packets.toLocaleString()}</td>
              <td>{fmtBytes(r.bytes)}</td>
              <td>{r.duration_s.toFixed(1)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {loading && <div style={{ textAlign: 'center', color: '#a0aec0', fontSize: 12, marginTop: 4 }}>로딩 중...</div>}
      {drill && (
        <div className="drilldown-modal">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <strong style={{ color: '#63b3ed' }}>{drill.src} ↔ {drill.dst} — {drill.sessions.length}개 세션</strong>
            <button className="filter-btn" style={{ background: '#4a5568', padding: '2px 8px' }} onClick={() => setDrill(null)}>✕</button>
          </div>
          {drill.sessions.length === 0 ? (
            <div style={{ color: '#a0aec0', fontSize: 12 }}>세션 데이터 없음</div>
          ) : (
            <table className="mini-table full-width">
              <thead>
                <tr>
                  <th>Src Port</th><th>Dst Port</th><th>Protocol</th><th>패킷</th><th>바이트</th><th>RST</th>
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
                        <td><button className="flow-open-btn" onClick={() => openFlow(s.session_id)} title="패킷 뷰어 열기">패킷 ▶</button></td>
                      )}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
