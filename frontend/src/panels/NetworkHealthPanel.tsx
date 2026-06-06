import { useState, useCallback } from 'react'
import { getNetworkHealth } from '../api'
import type { NetworkHealthData, SessionHealth } from '../api'

interface Props { uploadId: string }

function scoreColor(s: number) {
  return s >= 80 ? '#22c55e' : s >= 50 ? '#f59e0b' : '#ef4444'
}

function ScoreCircle({ score, status }: { score: number; status: string }) {
  const c = scoreColor(score)
  return (
    <div className="nh-score-circle" style={{ borderColor: c }}>
      <span className="nh-score-num" style={{ color: c }}>{score}</span>
      <span className="nh-score-label">{status}</span>
    </div>
  )
}

function SessionRow({ s, onSelect, selected }: { s: SessionHealth; selected: boolean; onSelect: () => void }) {
  const c = scoreColor(s.score)
  return (
    <tr className={`nh-session-row${selected ? ' nh-row-selected' : ''}`} onClick={onSelect}>
      <td><span className="nh-score-pill" style={{ background: c, color: '#0a0a0a' }}>{s.score}</span></td>
      <td><span className={`nh-status-badge nh-status-${s.status}`}>{s.status}</span></td>
      <td className="mono nh-addr">{s.src_ip}:{s.src_port}</td>
      <td className="mono nh-arrow">→</td>
      <td className="mono nh-addr">{s.dst_ip}:{s.dst_port}</td>
      <td><span className="nh-proto">{s.protocol}</span></td>
      <td className="mono nh-handshake">{s.handshake}</td>
      <td className="mono">{s.rtt_ms !== null ? `${s.rtt_ms.toFixed(1)} ms` : '—'}</td>
      <td className="mono">{s.retransmit_count > 0 ? <span style={{ color: '#f59e0b' }}>{s.retransmit_count} ({(s.retransmit_rate * 100).toFixed(1)}%)</span> : '—'}</td>
      <td className="nh-root-cause">{s.root_cause}</td>
    </tr>
  )
}

function SessionDetail({ s }: { s: SessionHealth }) {
  return (
    <div className="nh-detail">
      <div className="nh-detail-header">
        <span className="mono">{s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}</span>
        <span className="nh-proto">{s.protocol}</span>
        <ScoreCircle score={s.score} status={s.status} />
      </div>

      <div className="nh-detail-grid">
        <div className="nh-detail-card">
          <div className="nh-detail-card-title">연결 정보</div>
          <div className="nh-detail-row"><span>핸드셰이크</span><span className="mono">{s.handshake}</span></div>
          <div className="nh-detail-row"><span>RTT</span><span className="mono">{s.rtt_ms !== null ? `${s.rtt_ms.toFixed(2)} ms` : '—'}</span></div>
          <div className="nh-detail-row"><span>종료 방식</span><span className="mono">{s.close_type}</span></div>
          <div className="nh-detail-row"><span>RST 유형</span><span className="mono">{s.rst_type}</span></div>
        </div>
        <div className="nh-detail-card">
          <div className="nh-detail-card-title">트래픽</div>
          <div className="nh-detail-row"><span>패킷 수</span><span className="mono">{s.packet_count.toLocaleString()}</span></div>
          <div className="nh-detail-row"><span>송신</span><span className="mono">{s.bytes_sent.toLocaleString()} B</span></div>
          <div className="nh-detail-row"><span>수신</span><span className="mono">{s.bytes_recv.toLocaleString()} B</span></div>
          <div className="nh-detail-row"><span>세션 시간</span><span className="mono">{s.duration_s.toFixed(3)} s</span></div>
        </div>
        <div className="nh-detail-card">
          <div className="nh-detail-card-title">재전송</div>
          <div className="nh-detail-row"><span>횟수</span><span className="mono">{s.retransmit_count}</span></div>
          <div className="nh-detail-row"><span>비율</span><span className="mono">{(s.retransmit_rate * 100).toFixed(2)}%</span></div>
        </div>
      </div>

      {s.issues.length > 0 && (
        <div className="nh-issues">
          <div className="nh-issues-title">진단된 이슈</div>
          {s.issues.map((issue, i) => (
            <div key={i} className="nh-issue-item"><span className="nh-issue-icon">⚠</span> {issue}</div>
          ))}
        </div>
      )}

      {s.recommendations.length > 0 && (
        <div className="nh-recs">
          <div className="nh-recs-title">권장 조치</div>
          {s.recommendations.map((rec, i) => (
            <div key={i} className="nh-rec-item"><span className="nh-rec-icon">→</span> {rec}</div>
          ))}
        </div>
      )}
    </div>
  )
}

type FilterMode = 'all' | '정상' | '주의' | '이상'

export function NetworkHealthPanel({ uploadId }: Props) {
  const [data, setData]     = useState<NetworkHealthData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState<string | null>(null)
  const [filter, setFilter] = useState<FilterMode>('all')
  const [selected, setSelected] = useState<SessionHealth | null>(null)
  const [sortKey, setSortKey] = useState<'score' | 'rtt_ms' | 'retransmit_rate'>('score')

  const load = useCallback(async () => {
    setLoading(true); setError(null); setSelected(null)
    try {
      const d = await getNetworkHealth(uploadId)
      setData(d)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally { setLoading(false) }
  }, [uploadId])

  if (!data && !loading && !error) {
    return (
      <div className="nh-init">
        <button className="filter-btn" onClick={load}>통신 상태 진단 실행</button>
        <p className="pkt-hint">전체 세션의 TCP 핸드셰이크·RTT·재전송·RST를 분석해 이상 원인을 진단합니다</p>
      </div>
    )
  }

  if (loading) return <div className="nh-init"><div className="spinner sm" /> 분석 중...</div>
  if (error)   return <div className="nh-init" style={{ color: '#fc8181' }}>오류: {error}</div>
  if (!data)   return null

  const sessions = [...data.sessions]
    .filter(s => filter === 'all' || s.status === filter)
    .sort((a, b) => {
      if (sortKey === 'score') return a.score - b.score
      if (sortKey === 'rtt_ms') return (b.rtt_ms ?? -1) - (a.rtt_ms ?? -1)
      return b.retransmit_rate - a.retransmit_rate
    })

  return (
    <div className="nh-panel">
      {/* 전체 요약 */}
      <div className="nh-summary-bar">
        <div className="nh-overall">
          <ScoreCircle score={data.overall_score} status={data.overall_score >= 80 ? '정상' : data.overall_score >= 50 ? '주의' : '이상'} />
          <div className="nh-overall-label">전체 점수</div>
        </div>
        <div className="nh-counts">
          <div className="nh-count-item nh-ok" onClick={() => setFilter(filter === '정상' ? 'all' : '정상')}>
            <span className="nh-count-num">{data.healthy}</span>
            <span className="nh-count-label">정상</span>
          </div>
          <div className="nh-count-item nh-warn" onClick={() => setFilter(filter === '주의' ? 'all' : '주의')}>
            <span className="nh-count-num">{data.warning}</span>
            <span className="nh-count-label">주의</span>
          </div>
          <div className="nh-count-item nh-crit" onClick={() => setFilter(filter === '이상' ? 'all' : '이상')}>
            <span className="nh-count-num">{data.critical}</span>
            <span className="nh-count-label">이상</span>
          </div>
        </div>

        {data.top_issues.length > 0 && (
          <div className="nh-top-issues">
            <div className="nh-top-issues-title">주요 문제</div>
            {data.top_issues.slice(0, 5).map((ti, i) => (
              <div key={i} className="nh-top-issue-item">
                <span className="nh-top-issue-count">{ti.count}건</span>
                <span className="nh-top-issue-text">{ti.issue}</span>
              </div>
            ))}
          </div>
        )}

        <div className="nh-controls">
          <button className="filter-btn" onClick={load}>새로고침</button>
          <select className="pkt-filter-input" value={sortKey} onChange={e => setSortKey(e.target.value as typeof sortKey)} style={{ width: 120 }}>
            <option value="score">점수순</option>
            <option value="rtt_ms">RTT순</option>
            <option value="retransmit_rate">재전송순</option>
          </select>
          <span className="pkt-total"><strong>{data.total_sessions.toLocaleString()}</strong> 세션 | 표시 <strong>{sessions.length}</strong></span>
        </div>
      </div>

      <div className="nh-body">
        {/* 세션 테이블 */}
        <div className="nh-table-wrap">
          <table className="nh-table">
            <thead>
              <tr>
                <th>점수</th><th>상태</th><th>출발지</th><th></th><th>목적지</th>
                <th>Proto</th><th>핸드셰이크</th><th>RTT</th><th>재전송</th><th>진단 원인</th>
              </tr>
            </thead>
            <tbody>
              {sessions.length === 0 ? (
                <tr><td colSpan={10} className="pkt-empty">세션 없음</td></tr>
              ) : sessions.map(s => (
                <SessionRow
                  key={s.session_id}
                  s={s}
                  selected={selected?.session_id === s.session_id}
                  onSelect={() => setSelected(selected?.session_id === s.session_id ? null : s)}
                />
              ))}
            </tbody>
          </table>
        </div>

        {/* 상세 패널 */}
        {selected && (
          <div className="nh-detail-wrap">
            <button className="nh-close-btn" onClick={() => setSelected(null)}>✕</button>
            <SessionDetail s={selected} />
          </div>
        )}
      </div>
    </div>
  )
}
