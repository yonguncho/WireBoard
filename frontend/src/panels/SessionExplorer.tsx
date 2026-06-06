import { useState, useEffect, useMemo } from 'react'
import { getNetworkHealth } from '../api'
import type { NetworkHealthData, SessionHealth, PanelData } from '../api'

interface Props {
  uploadId: string
  panels: PanelData
  sessionCount: number
  onFlowSelect: (sessionId: string) => void
}

// ── 유틸 ─────────────────────────────────────────────────────────────────────

function scoreColor(s: number) {
  return s >= 80 ? '#22c55e' : s >= 50 ? '#f59e0b' : '#ef4444'
}

function fmtBytes(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

// ── 통계 카드 ────────────────────────────────────────────────────────────────

function StatBig({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
  return (
    <div className="se-stat-card">
      <div className="se-stat-value" style={color ? { color } : undefined}>{value}</div>
      <div className="se-stat-label">{label}</div>
      {sub && <div className="se-stat-sub">{sub}</div>}
    </div>
  )
}

// ── 세션 행 ──────────────────────────────────────────────────────────────────

function SessionRow({ s, selected, onClick }: { s: SessionHealth; selected: boolean; onClick: () => void }) {
  const c = scoreColor(s.score)
  return (
    <div
      className={`se-session-row${selected ? ' se-row-selected' : ''} se-status-${s.status}`}
      onClick={onClick}
    >
      <div className="se-score-dot" style={{ background: c }} title={`점수 ${s.score}`}>
        {s.score}
      </div>
      <div className="se-row-main">
        <div className="se-row-tuple">
          <span className="se-ip">{s.src_ip}</span>
          <span className="se-port">:{s.src_port}</span>
          <span className="se-arrow"> → </span>
          <span className="se-ip">{s.dst_ip}</span>
          <span className="se-port">:{s.dst_port}</span>
          <span className="se-proto-tag">{s.protocol}</span>
        </div>
        <div className="se-row-meta">
          <span className={`se-status-chip se-chip-${s.status}`}>{s.status}</span>
          {s.rtt_ms !== null && (
            <span className="se-meta-item" style={{ color: s.rtt_ms > 150 ? '#f59e0b' : 'var(--txt-secondary)' }}>
              RTT {s.rtt_ms.toFixed(1)}ms
            </span>
          )}
          {s.retransmit_count > 0 && (
            <span className="se-meta-item" style={{ color: '#f59e0b' }}>
              재전송 {s.retransmit_count}회
            </span>
          )}
          <span className="se-meta-item">{fmtBytes(s.bytes_sent + s.bytes_recv)}</span>
          <span className="se-root-cause">{s.root_cause}</span>
        </div>
      </div>
      <div className="se-row-arrow">{selected ? '◀' : '▶'}</div>
    </div>
  )
}

// ── 세션 상세 ────────────────────────────────────────────────────────────────

const HS_LABEL: Record<string, string> = {
  COMPLETE: '✓ 완료', REFUSED: '✗ 거부됨', TIMEOUT: '✗ 타임아웃',
  HALF_OPEN: '⚠ 불완전', 'N/A': '— 해당없음',
}
const HS_COLOR: Record<string, string> = {
  COMPLETE: '#22c55e', REFUSED: '#ef4444', TIMEOUT: '#ef4444',
  HALF_OPEN: '#f59e0b', 'N/A': '#5a7099',
}
const CLOSE_LABEL: Record<string, string> = {
  NORMAL: '정상 (FIN)', RESET: '강제 (RST)', TIMEOUT: '타임아웃', 'N/A': '—',
}

function SessionDetail({ s, onFlowOpen }: { s: SessionHealth; onFlowOpen: () => void }) {
  const c = scoreColor(s.score)
  return (
    <div className="se-detail">
      {/* 헤더 */}
      <div className="se-detail-top">
        <div className="se-detail-score-wrap">
          <div className="se-detail-score-circle" style={{ borderColor: c }}>
            <span className="se-detail-score-num" style={{ color: c }}>{s.score}</span>
            <span className="se-detail-score-lbl">{s.status}</span>
          </div>
        </div>
        <div className="se-detail-id">
          <div className="se-detail-tuple">
            <span className="mono">{s.src_ip}:{s.src_port}</span>
            <span className="se-detail-arrow"> → </span>
            <span className="mono">{s.dst_ip}:{s.dst_port}</span>
          </div>
          <div className="se-detail-proto">{s.protocol} · {s.duration_s.toFixed(3)}s · {s.packet_count}패킷</div>
        </div>
      </div>

      {/* 지표 */}
      <div className="se-detail-metrics">
        <div className="se-metric">
          <span className="se-metric-label">핸드셰이크</span>
          <span className="se-metric-value" style={{ color: HS_COLOR[s.handshake] ?? 'var(--txt-secondary)' }}>
            {HS_LABEL[s.handshake] ?? s.handshake}
          </span>
        </div>
        <div className="se-metric">
          <span className="se-metric-label">RTT</span>
          <span className="se-metric-value" style={{ color: s.rtt_ms !== null && s.rtt_ms > 150 ? '#f59e0b' : '#22c55e' }}>
            {s.rtt_ms !== null ? `${s.rtt_ms.toFixed(2)} ms` : '측정 불가'}
          </span>
        </div>
        <div className="se-metric">
          <span className="se-metric-label">재전송</span>
          <span className="se-metric-value" style={{ color: s.retransmit_count > 0 ? '#f59e0b' : '#22c55e' }}>
            {s.retransmit_count > 0 ? `${s.retransmit_count}회 (${(s.retransmit_rate * 100).toFixed(1)}%)` : '없음'}
          </span>
        </div>
        <div className="se-metric">
          <span className="se-metric-label">종료</span>
          <span className="se-metric-value" style={{ color: s.close_type === 'RESET' ? '#ef4444' : 'var(--txt-secondary)' }}>
            {CLOSE_LABEL[s.close_type] ?? s.close_type}
          </span>
        </div>
        <div className="se-metric">
          <span className="se-metric-label">송신/수신</span>
          <span className="se-metric-value">{fmtBytes(s.bytes_sent)} / {fmtBytes(s.bytes_recv)}</span>
        </div>
      </div>

      {/* 이슈 */}
      {s.issues.length > 0 ? (
        <div className="se-detail-issues">
          <div className="se-detail-section-title">진단된 문제</div>
          {s.issues.map((issue, i) => (
            <div key={i} className="se-issue-item">
              <span className="se-issue-icon">⚠</span> {issue}
            </div>
          ))}
        </div>
      ) : (
        <div className="se-detail-ok">✓ 이상 없음 — 정상 통신</div>
      )}

      {/* 권장 조치 */}
      {s.recommendations.length > 0 && (
        <div className="se-detail-recs">
          <div className="se-detail-section-title">권장 조치</div>
          {s.recommendations.map((rec, i) => (
            <div key={i} className="se-rec-item">
              <span className="se-rec-icon">→</span> {rec}
            </div>
          ))}
        </div>
      )}

      {/* 패킷 분석 버튼 */}
      <button className="se-flow-btn" onClick={onFlowOpen}>
        패킷 분석 열기 ↗
      </button>
    </div>
  )
}

// ── 메인 ─────────────────────────────────────────────────────────────────────

export function SessionExplorer({ uploadId, panels, sessionCount, onFlowSelect }: Props) {
  const [health, setHealth] = useState<NetworkHealthData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState<string | null>(null)
  const [ipFilter, setIpFilter] = useState('')
  const [selected, setSelected] = useState<SessionHealth | null>(null)
  const [showCriticalOnly, setShowCriticalOnly] = useState(false)

  useEffect(() => {
    getNetworkHealth(uploadId)
      .then(setHealth)
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }, [uploadId])

  // 프로토콜 상위 3개
  const topProtos = useMemo(() => {
    const dist = panels.panel2_protocol.distribution
    return Object.entries(dist)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
  }, [panels])

  const filteredSessions = useMemo(() => {
    if (!health) return []
    let list = health.sessions
    if (ipFilter.trim()) {
      const q = ipFilter.trim().toLowerCase()
      list = list.filter(s =>
        s.src_ip.includes(q) || s.dst_ip.includes(q)
      )
    }
    if (showCriticalOnly) {
      list = list.filter(s => s.status !== '정상')
    }
    return [...list].sort((a, b) => a.score - b.score)
  }, [health, ipFilter, showCriticalOnly])

  const attackCount  = panels.panel10_attacks.length
  const rstCount     = panels.panel5_anomalies.rst_count
  const retransCount = panels.panel5_anomalies.retransmit_count

  return (
    <div className="se-wrap">
      {/* ── 통계 현황판 ── */}
      <div className="se-stats-row">
        <StatBig
          label="전체 세션"
          value={sessionCount.toLocaleString()}
        />
        <StatBig
          label="고유 IP"
          value={panels.panel6_ip_ranking.length.toString()}
        />
        <StatBig
          label="공격 탐지"
          value={attackCount.toString()}
          color={attackCount > 0 ? '#ef4444' : '#22c55e'}
          sub={attackCount > 0 ? '위협 감지됨' : '정상'}
        />
        <StatBig
          label="RST 패킷"
          value={rstCount.toLocaleString()}
          color={rstCount > 100 ? '#f59e0b' : 'var(--txt-primary)'}
        />
        <StatBig
          label="재전송"
          value={retransCount.toLocaleString()}
          color={retransCount > 50 ? '#f59e0b' : 'var(--txt-primary)'}
        />
        <div className="se-proto-dist">
          <div className="se-proto-title">프로토콜</div>
          {topProtos.map(([proto, cnt]) => (
            <div key={proto} className="se-proto-row">
              <span className="se-proto-name">{proto}</span>
              <span className="se-proto-cnt">{cnt.toLocaleString()}</span>
            </div>
          ))}
        </div>
        {health && (
          <div className="se-health-summary">
            <div className="se-proto-title">통신 상태</div>
            <div className="se-health-bars">
              <div className="se-hbar se-hbar-ok">
                <span>{health.healthy}</span><span>정상</span>
              </div>
              <div className="se-hbar se-hbar-warn">
                <span>{health.warning}</span><span>주의</span>
              </div>
              <div className="se-hbar se-hbar-crit">
                <span>{health.critical}</span><span>이상</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── IP 검색 + 필터 ── */}
      <div className="se-search-bar">
        <input
          className="se-ip-input"
          placeholder="IP 주소 입력 — 해당 세션만 표시 (예: 192.168.1.10)"
          value={ipFilter}
          onChange={e => { setIpFilter(e.target.value); setSelected(null) }}
        />
        {ipFilter && (
          <button className="filter-btn" style={{ background: '#4a5568' }}
            onClick={() => { setIpFilter(''); setSelected(null) }}>
            초기화
          </button>
        )}
        <label className="se-toggle-label">
          <input
            type="checkbox"
            checked={showCriticalOnly}
            onChange={e => setShowCriticalOnly(e.target.checked)}
            className="se-toggle-check"
          />
          비정상만 표시
        </label>
        {health && (
          <span className="pkt-total">
            <strong>{filteredSessions.length}</strong> / {health.sessions.length} 세션
            {health.overall_score < 80 && (
              <span style={{ color: scoreColor(health.overall_score), marginLeft: 8 }}>
                전체 점수 {health.overall_score}
              </span>
            )}
          </span>
        )}
      </div>

      {/* ── 세션 목록 + 상세 ── */}
      <div className="se-body">
        {/* 세션 목록 */}
        <div className={`se-list-wrap${selected ? ' se-list-narrow' : ''}`}>
          {loading && (
            <div className="se-placeholder">
              <div className="spinner sm" /> 세션 분석 중...
            </div>
          )}
          {error && (
            <div className="se-placeholder" style={{ color: '#fc8181' }}>오류: {error}</div>
          )}
          {!loading && !error && filteredSessions.length === 0 && (
            <div className="se-placeholder">
              {ipFilter ? `"${ipFilter}" 관련 세션 없음` : '세션 없음'}
            </div>
          )}
          {filteredSessions.map(s => (
            <SessionRow
              key={s.session_id}
              s={s}
              selected={selected?.session_id === s.session_id}
              onClick={() => setSelected(selected?.session_id === s.session_id ? null : s)}
            />
          ))}
        </div>

        {/* 세션 상세 */}
        {selected && (
          <div className="se-detail-wrap">
            <button className="se-detail-close" onClick={() => setSelected(null)}>✕</button>
            <SessionDetail
              s={selected}
              onFlowOpen={() => onFlowSelect(selected.session_id)}
            />
          </div>
        )}
      </div>
    </div>
  )
}
