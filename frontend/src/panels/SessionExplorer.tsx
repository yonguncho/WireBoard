import { useState, useEffect, useMemo } from 'react'
import { getNetworkHealth } from '../api'
import type { NetworkHealthData, SessionHealth, PanelData } from '../api'
import { copyText, showToast } from '../toast'

interface Props {
  uploadId: string
  panels: PanelData
  sessionCount: number
  onFlowSelect: (sessionId: string) => void
}

// ── Utils ────────────────────────────────────────────────────────────────────

function scoreColor(s: number) {
  return s >= 80 ? '#22c55e' : s >= 50 ? '#f59e0b' : '#ef4444'
}

function fmtBytes(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

type SortKey = 'score' | 'bytes' | 'duration' | 'packets' | 'rtt'

const SORT_OPTIONS: [SortKey, string][] = [
  ['score', 'Lowest score first (problems first)'],
  ['bytes', 'Most traffic first'],
  ['duration', 'Longest duration first'],
  ['packets', 'Most packets first'],
  ['rtt', 'Slowest RTT first'],
]

function sortSessions(list: SessionHealth[], key: SortKey): SessionHealth[] {
  const sorted = [...list]
  switch (key) {
    case 'bytes':    sorted.sort((a, b) => (b.bytes_sent + b.bytes_recv) - (a.bytes_sent + a.bytes_recv)); break
    case 'duration': sorted.sort((a, b) => b.duration_s - a.duration_s); break
    case 'packets':  sorted.sort((a, b) => b.packet_count - a.packet_count); break
    case 'rtt':      sorted.sort((a, b) => (b.rtt_ms ?? -1) - (a.rtt_ms ?? -1)); break
    default:         sorted.sort((a, b) => a.score - b.score)
  }
  return sorted
}

function exportSessionsCsv(sessions: SessionHealth[]) {
  if (!sessions.length) { showToast('No sessions to export'); return }
  const header = 'src_ip,src_port,dst_ip,dst_port,protocol,status,score,rtt_ms,retransmit_count,bytes_sent,bytes_recv,packet_count,duration_s,root_cause'
  const esc = (v: string) => /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v
  const rows = sessions.map(s => [
    s.src_ip, s.src_port, s.dst_ip, s.dst_port, s.protocol, s.status, s.score,
    s.rtt_ms ?? '', s.retransmit_count, s.bytes_sent, s.bytes_recv,
    s.packet_count, s.duration_s.toFixed(3), esc(s.root_cause ?? ''),
  ].join(','))
  const blob = new Blob(['﻿' + [header, ...rows].join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `wireboard_sessions_${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
  showToast(`${sessions.length} sessions saved to CSV`)
}

// ── Stat cards ───────────────────────────────────────────────────────────────

function StatBig({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
  return (
    <div className="se-stat-card">
      <div className="se-stat-value" style={color ? { color } : undefined}>{value}</div>
      <div className="se-stat-label">{label}</div>
      {sub && <div className="se-stat-sub">{sub}</div>}
    </div>
  )
}

// ── Session row ──────────────────────────────────────────────────────────────

function SessionRow({ s, selected, onClick }: { s: SessionHealth; selected: boolean; onClick: () => void }) {
  const c = scoreColor(s.score)
  return (
    <div
      className={`se-session-row${selected ? ' se-row-selected' : ''} se-status-${s.status}`}
      onClick={onClick}
    >
      <div className="se-score-dot" style={{ background: c }} title={`Score ${s.score}`}>
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
              Retransmits {s.retransmit_count}
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

// ── Session detail ───────────────────────────────────────────────────────────

const HS_LABEL: Record<string, string> = {
  COMPLETE: '✓ Complete', REFUSED: '✗ Refused', TIMEOUT: '✗ Timeout',
  HALF_OPEN: '⚠ Incomplete', 'N/A': '— N/A',
}
const HS_COLOR: Record<string, string> = {
  COMPLETE: '#22c55e', REFUSED: '#ef4444', TIMEOUT: '#ef4444',
  HALF_OPEN: '#f59e0b', 'N/A': '#5a7099',
}
const CLOSE_LABEL: Record<string, string> = {
  NORMAL: 'Normal (FIN)', RESET: 'Forced (RST)', TIMEOUT: 'Timeout', 'N/A': '—',
}

function SessionDetail({ s, onFlowOpen }: { s: SessionHealth; onFlowOpen: () => void }) {
  const c = scoreColor(s.score)
  return (
    <div className="se-detail">
      {/* Header */}
      <div className="se-detail-top">
        <div className="se-detail-score-wrap">
          <div className="se-detail-score-circle" style={{ borderColor: c }}>
            <span className="se-detail-score-num" style={{ color: c }}>{s.score}</span>
            <span className="se-detail-score-lbl">{s.status}</span>
          </div>
        </div>
        <div className="se-detail-id">
          <div className="se-detail-tuple">
            <span className="mono copyable" title="Click to copy IP" onClick={() => copyText(s.src_ip)}>{s.src_ip}:{s.src_port}</span>
            <span className="se-detail-arrow"> → </span>
            <span className="mono copyable" title="Click to copy IP" onClick={() => copyText(s.dst_ip)}>{s.dst_ip}:{s.dst_port}</span>
          </div>
          <div className="se-detail-proto">{s.protocol} · {s.duration_s.toFixed(3)}s · {s.packet_count} packets</div>
        </div>
      </div>

      {/* Metrics */}
      <div className="se-detail-metrics">
        <div className="se-metric">
          <span className="se-metric-label">Handshake</span>
          <span className="se-metric-value" style={{ color: HS_COLOR[s.handshake] ?? 'var(--txt-secondary)' }}>
            {HS_LABEL[s.handshake] ?? s.handshake}
          </span>
        </div>
        <div className="se-metric">
          <span className="se-metric-label">RTT</span>
          <span className="se-metric-value" style={{ color: s.rtt_ms !== null && s.rtt_ms > 150 ? '#f59e0b' : '#22c55e' }}>
            {s.rtt_ms !== null ? `${s.rtt_ms.toFixed(2)} ms` : 'Not measurable'}
          </span>
        </div>
        <div className="se-metric">
          <span className="se-metric-label">Retransmits</span>
          <span className="se-metric-value" style={{ color: s.retransmit_count > 0 ? '#f59e0b' : '#22c55e' }}>
            {s.retransmit_count > 0 ? `${s.retransmit_count} (${(s.retransmit_rate * 100).toFixed(1)}%)` : 'None'}
          </span>
        </div>
        <div className="se-metric">
          <span className="se-metric-label">Close</span>
          <span className="se-metric-value" style={{ color: s.close_type === 'RESET' ? '#ef4444' : 'var(--txt-secondary)' }}>
            {CLOSE_LABEL[s.close_type] ?? s.close_type}
          </span>
        </div>
        <div className="se-metric">
          <span className="se-metric-label">Sent/Received</span>
          <span className="se-metric-value">{fmtBytes(s.bytes_sent)} / {fmtBytes(s.bytes_recv)}</span>
        </div>
      </div>

      {/* Issues */}
      {s.issues.length > 0 ? (
        <div className="se-detail-issues">
          <div className="se-detail-section-title">Diagnosed Issues</div>
          {s.issues.map((issue, i) => (
            <div key={i} className="se-issue-item">
              <span className="se-issue-icon">⚠</span> {issue}
            </div>
          ))}
        </div>
      ) : (
        <div className="se-detail-ok">✓ No anomalies — normal communication</div>
      )}

      {/* Recommended actions */}
      {s.recommendations.length > 0 && (
        <div className="se-detail-recs">
          <div className="se-detail-section-title">Recommended Actions</div>
          {s.recommendations.map((rec, i) => (
            <div key={i} className="se-rec-item">
              <span className="se-rec-icon">→</span> {rec}
            </div>
          ))}
        </div>
      )}

      {/* Packet analysis button */}
      <button className="se-flow-btn" onClick={onFlowOpen}>
        Open Packet Analysis ↗
      </button>
    </div>
  )
}

// ── Main ─────────────────────────────────────────────────────────────────────

export function SessionExplorer({ uploadId, panels, sessionCount, onFlowSelect }: Props) {
  const [health, setHealth] = useState<NetworkHealthData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState<string | null>(null)
  const [ipFilter, setIpFilter] = useState('')
  const [selected, setSelected] = useState<SessionHealth | null>(null)
  const [showCriticalOnly, setShowCriticalOnly] = useState(false)
  const [sortKey, setSortKey] = useState<SortKey>('score')

  useEffect(() => {
    getNetworkHealth(uploadId)
      .then(setHealth)
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }, [uploadId])

  // Top 3 protocols
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
      list = list.filter(s => s.status !== 'Healthy')
    }
    return sortSessions(list, sortKey)
  }, [health, ipFilter, showCriticalOnly, sortKey])

  const attackCount  = panels.panel10_attacks.length
  const rstCount     = panels.panel5_anomalies.rst_count
  const retransCount = panels.panel5_anomalies.retransmit_count

  return (
    <div className="se-wrap">
      {/* ── Stats dashboard ── */}
      <div className="se-stats-row">
        <StatBig
          label="Total Sessions"
          value={sessionCount.toLocaleString()}
        />
        <StatBig
          label="Unique IPs"
          value={panels.panel6_ip_ranking.length.toString()}
        />
        <StatBig
          label="Detected Events"
          value={attackCount.toString()}
          color={attackCount > 0 ? '#ef4444' : '#22c55e'}
          sub={attackCount > 0 ? 'Anomalous pattern detected' : 'Normal'}
        />
        <StatBig
          label="RST Packets"
          value={rstCount.toLocaleString()}
          color={rstCount > 100 ? '#f59e0b' : 'var(--txt-primary)'}
        />
        <StatBig
          label="Retransmits"
          value={retransCount.toLocaleString()}
          color={retransCount > 50 ? '#f59e0b' : 'var(--txt-primary)'}
        />
        <div className="se-proto-dist">
          <div className="se-proto-title">Protocol</div>
          {topProtos.map(([proto, cnt]) => (
            <div key={proto} className="se-proto-row">
              <span className="se-proto-name">{proto}</span>
              <span className="se-proto-cnt">{cnt.toLocaleString()}</span>
            </div>
          ))}
        </div>
        {health && (
          <div className="se-health-summary">
            <div className="se-proto-title">Communication Status</div>
            <div className="se-health-bars">
              <div className="se-hbar se-hbar-ok">
                <span>{health.healthy}</span><span>Normal</span>
              </div>
              <div className="se-hbar se-hbar-warn">
                <span>{health.warning}</span><span>Warning</span>
              </div>
              <div className="se-hbar se-hbar-crit">
                <span>{health.critical}</span><span>Critical</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── IP search + filter ── */}
      <div className="se-search-bar">
        <input
          className="se-ip-input"
          placeholder="Enter IP address — show only matching sessions (e.g. 192.168.1.10)"
          value={ipFilter}
          onChange={e => { setIpFilter(e.target.value); setSelected(null) }}
        />
        {ipFilter && (
          <button className="filter-btn" style={{ background: '#4a5568' }}
            onClick={() => { setIpFilter(''); setSelected(null) }}>
            Reset
          </button>
        )}
        <label className="se-toggle-label">
          <input
            type="checkbox"
            checked={showCriticalOnly}
            onChange={e => setShowCriticalOnly(e.target.checked)}
            className="se-toggle-check"
          />
          Show abnormal only
        </label>
        <select
          className="se-sort-select"
          value={sortKey}
          onChange={e => setSortKey(e.target.value as SortKey)}
          title="Session sort order"
        >
          {SORT_OPTIONS.map(([key, label]) => (
            <option key={key} value={key}>{label}</option>
          ))}
        </select>
        <button
          className="se-csv-btn"
          title="Save currently filtered sessions to CSV"
          onClick={() => exportSessionsCsv(filteredSessions)}
        >
          ↓ CSV
        </button>
        {health && (
          <span className="pkt-total">
            <strong>{filteredSessions.length}</strong> / {health.sessions.length} sessions
            {health.overall_score < 80 && (
              <span style={{ color: scoreColor(health.overall_score), marginLeft: 8 }}>
                Overall score {health.overall_score}
              </span>
            )}
          </span>
        )}
      </div>

      {/* ── Session list + detail ── */}
      <div className="se-body">
        {/* Session list */}
        <div className={`se-list-wrap${selected ? ' se-list-narrow' : ''}`}>
          {loading && (
            <div className="se-placeholder">
              <div className="spinner sm" /> Analyzing sessions...
            </div>
          )}
          {error && (
            <div className="se-placeholder" style={{ color: '#fc8181' }}>Error: {error}</div>
          )}
          {!loading && !error && filteredSessions.length === 0 && (
            <div className="se-placeholder">
              {ipFilter ? `No sessions matching "${ipFilter}"` : 'No sessions'}
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

        {/* Session detail */}
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
