import { useState, useCallback } from 'react'
import { getNetworkHealth } from '../api'
import type { NetworkHealthData, SessionHealth } from '../api'

const ICMP_LABEL_KR: Record<string, string> = {
  ttl_expired:      'TTL expired',
  fragment_timeout: 'Fragment reassembly timeout',
  net_unreachable:  'Network unreachable',
  host_unreachable: 'Host unreachable',
  port_unreachable: 'Port unreachable',
  admin_prohibited: 'Administratively prohibited',
  unreachable:      'Unreachable',
}

function icmpLabelKr(label: string | undefined): string {
  return label ? (ICMP_LABEL_KR[label] ?? label) : '—'
}

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
          <div className="nh-detail-card-title">Connection info</div>
          <div className="nh-detail-row"><span>Handshake</span><span className="mono">{s.handshake}</span></div>
          <div className="nh-detail-row"><span>RTT (network)</span><span className="mono">{s.rtt_ms !== null ? `${s.rtt_ms.toFixed(2)} ms` : '—'}</span></div>
          <div className="nh-detail-row"><span>Server delay</span><span className="mono">{s.server_delay_ms != null ? `${s.server_delay_ms.toFixed(1)} ms` : '—'}</span></div>
          {s.bottleneck && s.bottleneck !== 'none' && (
            <div className="nh-detail-row"><span>Bottleneck</span><span className="mono" style={{ color: s.bottleneck === 'application' ? '#f59e0b' : '#fc4343', fontWeight: 700 }}>{s.bottleneck.toUpperCase()}</span></div>
          )}
          <div className="nh-detail-row"><span>Close type</span><span className="mono">{s.close_type}</span></div>
          <div className="nh-detail-row"><span>RST type</span><span className="mono">{s.rst_type}</span></div>
        </div>
        <div className="nh-detail-card">
          <div className="nh-detail-card-title">Traffic</div>
          <div className="nh-detail-row"><span>Packets</span><span className="mono">{s.packet_count.toLocaleString()}</span></div>
          <div className="nh-detail-row"><span>Sent</span><span className="mono">{s.bytes_sent.toLocaleString()} B</span></div>
          <div className="nh-detail-row"><span>Received</span><span className="mono">{s.bytes_recv.toLocaleString()} B</span></div>
          <div className="nh-detail-row"><span>Session time</span><span className="mono">{s.duration_s.toFixed(3)} s</span></div>
        </div>
        <div className="nh-detail-card">
          <div className="nh-detail-card-title">Retransmission</div>
          <div className="nh-detail-row"><span>Count</span><span className="mono">{s.retransmit_count}</span></div>
          <div className="nh-detail-row"><span>Ratio</span><span className="mono">{(s.retransmit_rate * 100).toFixed(2)}%</span></div>
        </div>
        {s.failure_type === 'path_issue' && (
          <div className="nh-detail-card">
            <div className="nh-detail-card-title">Path issue (ICMP)</div>
            <div className="nh-detail-row"><span>Type</span><span className="mono">{icmpLabelKr(s.icmp_label)}</span></div>
            <div className="nh-detail-row"><span>Responding router</span><span className="mono">{s.icmp_src_ip ?? '—'}</span></div>
          </div>
        )}
      </div>

      {s.issues.length > 0 && (
        <div className="nh-issues">
          <div className="nh-issues-title">Diagnosed issues</div>
          {s.issues.map((issue, i) => (
            <div key={i} className="nh-issue-item">
              <span className="nh-issue-icon">⚠</span> {issue}
            </div>
          ))}
        </div>
      )}

      {s.recommendations.length > 0 && (
        <div className="nh-recs">
          <div className="nh-recs-title">Recommended actions</div>
          {s.recommendations.map((rec, i) => (
            <div key={i} className="nh-rec-item">
              <span className="nh-rec-icon">→</span> {rec}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

type NhSortKey = 'score' | 'rtt_ms' | 'retransmit_rate'

export function NetworkHealthPanel({ uploadId }: Props) {
  const [data, setData]         = useState<NetworkHealthData | null>(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [selected, setSelected] = useState<SessionHealth | null>(null)
  const [sortKey, setSortKey]   = useState<NhSortKey>('score')

  const run = useCallback(async () => {
    setLoading(true); setError(null); setSelected(null)
    try {
      setData(await getNetworkHealth(uploadId))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [uploadId])

  if (!data && !loading && !error) return (
    <div className="nh-init">
      <button className="filter-btn" onClick={run}>Run connection health diagnostics</button>
      <p className="pkt-hint">Analyzes TCP handshake · RTT · retransmission · RST across all sessions to diagnose anomaly causes</p>
    </div>
  )
  if (loading) return <div className="nh-init"><div className="spinner sm" /> Analyzing...</div>
  if (error)   return <div className="nh-init" style={{ color: '#fc8181' }}>Error: {error}</div>
  if (!data)   return null

  const visible = [...data.sessions]
    .filter(s => statusFilter === 'all' || s.status === statusFilter)
    .sort((a, b) =>
      sortKey === 'score'  ? a.score - b.score :
      sortKey === 'rtt_ms' ? (b.rtt_ms ?? -1) - (a.rtt_ms ?? -1) :
      b.retransmit_rate - a.retransmit_rate
    )

  return (
    <div className="nh-panel">
      {/* NOC verdict: network problem vs application problem — decides who to page */}
      {data.verdict && data.verdict.side !== 'none' && (
        <div className={`nh-verdict nh-verdict-${data.verdict.side}`}>
          <span className="nh-verdict-badge">
            {data.verdict.side === 'network' ? '🌐 NETWORK' :
             data.verdict.side === 'application' ? '🖥 APPLICATION' : '🔌 SERVER'}
          </span>
          <span className="nh-verdict-text">{data.verdict.headline}</span>
        </div>
      )}

      {/* Capture-quality caveats — prevents over-trusting partial captures */}
      {(data.capture_quality?.warnings?.length ?? 0) > 0 && (
        <div className="nh-quality">
          {data.capture_quality!.warnings.map((w, i) => (
            <div key={i} className="nh-quality-item">⚠ {w}</div>
          ))}
        </div>
      )}

      <div className="nh-summary-bar">
        <div className="nh-overall">
          <ScoreCircle
            score={data.overall_score}
            status={data.overall_score >= 80 ? 'Healthy' : data.overall_score >= 50 ? 'Warning' : 'Critical'}
          />
          <div className="nh-overall-label">Overall score</div>
        </div>
        <div className="nh-counts">
          <div className="nh-count-item nh-ok" onClick={() => setStatusFilter(statusFilter === 'Healthy' ? 'all' : 'Healthy')}>
            <span className="nh-count-num">{data.healthy}</span>
            <span className="nh-count-label">Healthy</span>
          </div>
          <div className="nh-count-item nh-warn" onClick={() => setStatusFilter(statusFilter === 'Warning' ? 'all' : 'Warning')}>
            <span className="nh-count-num">{data.warning}</span>
            <span className="nh-count-label">Warning</span>
          </div>
          <div className="nh-count-item nh-crit" onClick={() => setStatusFilter(statusFilter === 'Critical' ? 'all' : 'Critical')}>
            <span className="nh-count-num">{data.critical}</span>
            <span className="nh-count-label">Critical</span>
          </div>
        </div>
        {data.top_issues.length > 0 && (
          <div className="nh-top-issues">
            <div className="nh-top-issues-title">Top issues</div>
            {data.top_issues.slice(0, 5).map((t, i) => (
              <div key={i} className="nh-top-issue-item">
                <span className="nh-top-issue-count">{t.count}</span>
                <span className="nh-top-issue-text">{t.issue}</span>
              </div>
            ))}
          </div>
        )}
        <div className="nh-controls">
          <button className="filter-btn" onClick={run}>Refresh</button>
          <select className="pkt-filter-input" value={sortKey} style={{ width: 120 }}
            onChange={e => setSortKey(e.target.value as NhSortKey)}>
            <option value="score">By score</option>
            <option value="rtt_ms">By RTT</option>
            <option value="retransmit_rate">By retransmission</option>
          </select>
          <span className="pkt-total">
            <strong>{data.total_sessions.toLocaleString()}</strong> sessions | shown <strong>{visible.length}</strong>
          </span>
        </div>
      </div>

      <div className="nh-body">
        <div className="nh-table-wrap">
          <table className="nh-table">
            <thead>
              <tr>
                <th>Score</th><th>Status</th><th>Source</th><th></th><th>Destination</th>
                <th>Proto</th><th>Handshake</th><th>RTT</th><th>Retransmit</th><th>Diagnosed cause</th>
              </tr>
            </thead>
            <tbody>
              {visible.length === 0 ? (
                <tr><td colSpan={10} className="pkt-empty">No sessions</td></tr>
              ) : visible.map(s => (
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