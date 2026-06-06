import { useState } from 'react'
import { getDrilldown } from '../api'
import type { ConvEntry, DrilldownSession } from '../api'

interface Props {
  data: ConvEntry[]
  uploadId?: string
  onFlowSelect?: (sessionId: string) => void
}

function fmtBytes(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

interface SessionModal {
  src: string; dst: string
  sessions: DrilldownSession[]
}

export function Panel9Conversations({ data, uploadId, onFlowSelect }: Props) {
  const rows = (data ?? []).slice(0, 20)
  const [modal, setModal] = useState<SessionModal | null>(null)
  const [loading, setLoading] = useState(false)

  const handleRowClick = async (src: string, dst: string) => {
    if (!uploadId) return
    setLoading(true)
    try {
      const r = await getDrilldown(uploadId, src)
      // 해당 대화 pair만 필터 (src → dst)
      const filtered = r.sessions.filter(
        s => (s.src_ip === src && s.dst_ip === dst) || (s.src_ip === dst && s.dst_ip === src)
      )
      setModal({ src, dst, sessions: filtered })
    } catch (_) { /* ignore */ }
    finally { setLoading(false) }
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
            <tr
              key={i}
              style={uploadId ? { cursor: 'pointer' } : {}}
              className="conv-row"
              onClick={() => handleRowClick(r.src, r.dst)}
            >
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

      {modal && (
        <div className="drilldown-modal">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <strong style={{ color: '#63b3ed' }}>
              {modal.src} ↔ {modal.dst} — {modal.sessions.length}개 세션
            </strong>
            <button className="filter-btn" style={{ background: '#4a5568', padding: '2px 8px' }} onClick={() => setModal(null)}>✕</button>
          </div>
          {modal.sessions.length === 0 ? (
            <div style={{ color: '#a0aec0', fontSize: 12 }}>세션 데이터 없음</div>
          ) : (
            <table className="mini-table full-width">
              <thead>
                <tr>
                  <th>Src Port</th><th>Dst Port</th><th>Protocol</th>
                  <th>패킷</th><th>바이트</th><th>RST</th>
                  {onFlowSelect && <th>Flow</th>}
                </tr>
              </thead>
              <tbody>
                {modal.sessions.map(s => {
                  const fwd   = s.src_ip === modal.src
                  const sport = fwd ? s.src_port : s.dst_port
                  const dport = fwd ? s.dst_port : s.src_port
                  return (
                    <tr key={s.session_id} className={s.rst ? 'row-error' : ''}>
                      <td>{sport}</td>
                      <td>{dport}</td>
                      <td>{s.protocol}</td>
                      <td>{s.packet_count.toLocaleString()}</td>
                      <td>{fmtBytes(s.bytes_sent + s.bytes_recv)}</td>
                      <td>{s.rst ? '⚠' : ''}</td>
                      {onFlowSelect && (
                        <td>
                          <button
                            className="flow-open-btn"
                            onClick={() => { setModal(null); onFlowSelect(s.session_id) }}
                            title="패킷 뷰어 열기"
                          >
                            패킷 ▶
                          </button>
                        </td>
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
