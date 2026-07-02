import { useState, useCallback, useMemo } from 'react'
import { uploadPcap, analyzePcap, compareCaptures } from '../api'
import type { CompareResult, CompareSession, ConversationDiff } from '../api'

const ALLOWED = /\.(pcap|pcapng|cap|har|log|txt|tcpdump)$/i

interface Props {
  baseUploadId: string
  baseFilename: string
}

// Session match key: treat both directions as identical (sorted IP pair + dst_port + protocol)
function sessionKey(s: CompareSession): string {
  const [a, b] = s.src_ip < s.dst_ip ? [s.src_ip, s.dst_ip] : [s.dst_ip, s.src_ip]
  return `${a}|${b}|${s.dst_port}|${s.protocol}`
}

function fmtBytes(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}MB`
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}KB`
  return `${n}B`
}

function fmtTs(ts: number, baseTs: number): string {
  const rel = ts - baseTs
  if (rel < 60) return `+${rel.toFixed(3)}s`
  return `+${Math.floor(rel / 60)}m${(rel % 60).toFixed(0)}s`
}

type SessionFilter = 'all' | 'new' | 'removed' | 'common'
type InnerTab = 'conversations' | 'sessions' | 'ips' | 'protocols'
type ConvFilter = 'all' | 'changed' | 'both' | 'only_base' | 'only_compare'
type ConvSort = 'traffic' | 'delta'

// Modal state type
type ModalState =
  | { kind: 'new_ips';     sessions: CompareSession[]; title: string }
  | { kind: 'removed_ips'; sessions: CompareSession[]; title: string }
  | { kind: 'new_ports';   sessions: CompareSession[]; title: string }

// ── Session detail modal ──────────────────────────────────────────────────
function SessionModal({ state, onClose }: { state: ModalState; onClose: () => void }) {
  return (
    <div className="cmp-modal-overlay" onClick={onClose}>
      <div className="cmp-modal" onClick={e => e.stopPropagation()}>
        <div className="cmp-modal-header">
          <span className="cmp-modal-title">{state.title}</span>
          <button className="cmp-modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="cmp-modal-body">
          {state.sessions.length === 0
            ? <div className="no-data">No sessions</div>
            : (
              <table className="cmp-session-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Packets</th>
                    <th>Bytes</th>
                    <th>RST</th>
                  </tr>
                </thead>
                <tbody>
                  {state.sessions.map(s => {
                    const ts = new Date(s.start_ts * 1000).toISOString().slice(11, 23)
                    return (
                      <tr key={s.session_id}>
                        <td className="mono">{ts}</td>
                        <td className="mono">{s.src_ip}:{s.src_port}</td>
                        <td className="mono">{s.dst_ip}:{s.dst_port}</td>
                        <td><span className="proto-chip">{s.protocol}</span></td>
                        <td>{s.packet_count}</td>
                        <td>{fmtBytes(s.bytes_sent + s.bytes_recv)}</td>
                        <td>{s.rst ? <span className="txt-danger">RST</span> : '—'}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )
          }
        </div>
      </div>
    </div>
  )
}

// ── Session side-by-side ──────────────────────────────────────────────────
function SideBySide({
  result,
  baseFilename,
  compareFilename,
}: {
  result: CompareResult
  baseFilename: string
  compareFilename: string
}) {
  const [filter, setFilter] = useState<SessionFilter>('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const compareKeySet = useMemo(
    () => new Set(result.compare_sessions.map(sessionKey)),
    [result.compare_sessions]
  )
  const baseKeySet = useMemo(
    () => new Set(result.base_sessions.map(sessionKey)),
    [result.base_sessions]
  )

  const baseTs0   = result.base_sessions[0]?.start_ts    ?? 0
  const compareTs0 = result.compare_sessions[0]?.start_ts ?? 0

  // Classify base sessions
  const baseSessions = useMemo(() => result.base_sessions.map(s => ({
    ...s,
    status: compareKeySet.has(sessionKey(s)) ? 'common' : 'removed',
  })), [result.base_sessions, compareKeySet])

  // Classify compare sessions
  const compareSessions = useMemo(() => result.compare_sessions.map(s => ({
    ...s,
    status: baseKeySet.has(sessionKey(s)) ? 'common' : 'new',
  })), [result.compare_sessions, baseKeySet])

  const filteredBase = useMemo(() => {
    if (filter === 'all')     return baseSessions
    if (filter === 'removed') return baseSessions.filter(s => s.status === 'removed')
    if (filter === 'common')  return baseSessions.filter(s => s.status === 'common')
    return [] // 'new' — no new sessions in base
  }, [baseSessions, filter])

  const filteredCompare = useMemo(() => {
    if (filter === 'all')    return compareSessions
    if (filter === 'new')    return compareSessions.filter(s => s.status === 'new')
    if (filter === 'common') return compareSessions.filter(s => s.status === 'common')
    return [] // 'removed' — no removed sessions in compare
  }, [compareSessions, filter])

  const FILTERS: { key: SessionFilter; label: string }[] = [
    { key: 'all',     label: 'All' },
    { key: 'new',     label: 'New only' },
    { key: 'removed', label: 'Removed only' },
    { key: 'common',  label: 'Common only' },
  ]

  return (
    <div className="cmp-sbs-wrap">
      {/* Filter bar */}
      <div className="cmp-filter-bar">
        {FILTERS.map(f => (
          <button
            key={f.key}
            className={`cmp-filter-btn${filter === f.key ? ' active' : ''}`}
            onClick={() => setFilter(f.key)}
          >
            {f.label}
          </button>
        ))}
        <span className="cmp-sbs-hint">Click a session row to expand details</span>
      </div>

      {/* Split view */}
      <div className="cmp-sbs-grid">
        {/* Base column */}
        <div className="cmp-sbs-col">
          <div className="cmp-sbs-col-header base">
            Base: {baseFilename}
            <span className="cmp-sbs-count">{filteredBase.length} sessions</span>
          </div>
          <div className="cmp-sbs-list">
            {filteredBase.length === 0
              ? <div className="no-data">No matching sessions</div>
              : filteredBase.map(s => (
                <SessionRow
                  key={s.session_id}
                  s={s}
                  ts0={baseTs0}
                  expanded={expandedId === s.session_id}
                  onToggle={() => setExpandedId(expandedId === s.session_id ? null : s.session_id)}
                />
              ))
            }
          </div>
        </div>

        {/* Compare column */}
        <div className="cmp-sbs-col">
          <div className="cmp-sbs-col-header compare">
            Compare: {compareFilename}
            <span className="cmp-sbs-count">{filteredCompare.length} sessions</span>
          </div>
          <div className="cmp-sbs-list">
            {filteredCompare.length === 0
              ? <div className="no-data">No matching sessions</div>
              : filteredCompare.map(s => (
                <SessionRow
                  key={s.session_id}
                  s={s}
                  ts0={compareTs0}
                  expanded={expandedId === s.session_id}
                  onToggle={() => setExpandedId(expandedId === s.session_id ? null : s.session_id)}
                />
              ))
            }
          </div>
        </div>
      </div>

      {result.base_session_total > 300 || result.compare_session_total > 300
        ? <div className="cmp-truncate-notice">
            ⚠ Too many sessions — showing up to 300 each (base {result.base_session_total} / compare {result.compare_session_total})
          </div>
        : null
      }
    </div>
  )
}

function SessionRow({
  s, ts0, expanded, onToggle,
}: {
  s: CompareSession & { status: string }
  ts0: number
  expanded: boolean
  onToggle: () => void
}) {
  const badgeClass =
    s.status === 'new'     ? 'cmp-badge-new' :
    s.status === 'removed' ? 'cmp-badge-removed' :
                             'cmp-badge-common'
  const badgeLabel =
    s.status === 'new'     ? 'New' :
    s.status === 'removed' ? 'Removed' : 'Common'

  const duration = s.end_ts - s.start_ts

  return (
    <>
      <div
        className={`cmp-session-row${expanded ? ' expanded' : ''}`}
        onClick={onToggle}
      >
        <span className={`cmp-badge ${badgeClass}`}>{badgeLabel}</span>
        <span className="cmp-row-ts mono">{fmtTs(s.start_ts, ts0)}</span>
        <span className="cmp-row-pair mono">
          {s.src_ip}:{s.src_port}
          <span className="arrow"> → </span>
          {s.dst_ip}:{s.dst_port}
        </span>
        <span className="proto-chip">{s.protocol}</span>
        <span className="cmp-row-bytes">{fmtBytes(s.bytes_sent + s.bytes_recv)}</span>
        {s.rst && <span className="txt-danger rst-chip">RST</span>}
        <span className="cmp-expand-icon">{expanded ? '▲' : '▼'}</span>
      </div>
      {expanded && (
        <div className="cmp-session-detail">
          <div className="cmp-detail-grid">
            <span className="cmp-detail-label">Session ID</span>
            <span className="mono small">{s.session_id}</span>
            <span className="cmp-detail-label">Start</span>
            <span className="mono small">{new Date(s.start_ts * 1000).toISOString().replace('T', ' ').slice(0, 23)}</span>
            <span className="cmp-detail-label">End</span>
            <span className="mono small">{new Date(s.end_ts * 1000).toISOString().replace('T', ' ').slice(0, 23)}</span>
            <span className="cmp-detail-label">Duration</span>
            <span>{duration < 1 ? `${(duration * 1000).toFixed(0)}ms` : `${duration.toFixed(3)}s`}</span>
            <span className="cmp-detail-label">Packets</span>
            <span>{s.packet_count}</span>
            <span className="cmp-detail-label">Sent↑</span>
            <span>{fmtBytes(s.bytes_sent)}</span>
            <span className="cmp-detail-label">Received↓</span>
            <span>{fmtBytes(s.bytes_recv)}</span>
          </div>
        </div>
      )}
    </>
  )
}

// ── Conversation statistical diff ─────────────────────────────────────────
// 같은 통신(IP쌍·포트·프로토콜)을 두 캡처에서 짝지어 통계 차이를 보여준다.
// "서로 다른 상황에서 동일한 통신을 비교"하는 핵심 화면.
function ConvBytesDelta({ delta }: { delta: number }) {
  if (delta === 0) return <span className="cmp-conv-delta zero">±0</span>
  const up = delta > 0
  return (
    <span className={`cmp-conv-delta ${up ? 'up' : 'down'}`}>
      {up ? '+' : '−'}{fmtBytes(Math.abs(delta))} {up ? '▲' : '▼'}
    </span>
  )
}

function Conversations({
  result, baseFilename, compareFilename,
}: {
  result: CompareResult
  baseFilename: string
  compareFilename: string
}) {
  const [filter, setFilter] = useState<ConvFilter>('all')
  const [sort, setSort]     = useState<ConvSort>('traffic')

  const summary = result.conversation_summary

  const rows = useMemo(() => {
    let list = result.conversations
    if (filter === 'changed')      list = list.filter(c => c.status === 'both' && c.byte_delta !== 0)
    else if (filter === 'both')    list = list.filter(c => c.status === 'both')
    else if (filter === 'only_base')    list = list.filter(c => c.status === 'only_a')
    else if (filter === 'only_compare') list = list.filter(c => c.status === 'only_b')
    const sorted = [...list]
    if (sort === 'delta') sorted.sort((a, b) => Math.abs(b.byte_delta) - Math.abs(a.byte_delta))
    else sorted.sort((a, b) => Math.max(b.a_bytes, b.b_bytes) - Math.max(a.a_bytes, a.b_bytes))
    return sorted
  }, [result.conversations, filter, sort])

  const FILTERS: { key: ConvFilter; label: string; count: number }[] = [
    { key: 'all',          label: 'All',          count: summary.total },
    { key: 'changed',      label: 'Changed',      count: summary.changed },
    { key: 'both',         label: 'In both',      count: summary.both },
    { key: 'only_base',    label: 'Base only',    count: summary.only_base },
    { key: 'only_compare', label: 'Compare only', count: summary.only_compare },
  ]

  function statusBadge(c: ConversationDiff) {
    if (c.status === 'only_a') return <span className="cmp-badge cmp-badge-removed">Base only</span>
    if (c.status === 'only_b') return <span className="cmp-badge cmp-badge-new">Compare only</span>
    if (c.byte_delta !== 0)    return <span className="cmp-badge cmp-badge-changed">Changed</span>
    return <span className="cmp-badge cmp-badge-common">Same</span>
  }

  return (
    <div className="cmp-conv-wrap">
      <p className="cmp-conv-intro">
        Pairs the same communication (endpoint pair · port · protocol) across both captures,
        so you can see how identical conversations behaved under different situations.
      </p>

      {/* Summary line */}
      <div className="cmp-conv-summary">
        <span><b>{summary.total}</b> conversations</span>
        <span className="dot">·</span>
        <span className="txt-warn"><b>{summary.changed}</b> changed</span>
        <span className="dot">·</span>
        <span><b>{summary.both}</b> in both</span>
        <span className="dot">·</span>
        <span className="txt-ok"><b>{summary.only_base}</b> base only</span>
        <span className="dot">·</span>
        <span className="txt-danger"><b>{summary.only_compare}</b> compare only</span>
      </div>

      {/* Controls */}
      <div className="cmp-filter-bar">
        {FILTERS.map(f => (
          <button
            key={f.key}
            className={`cmp-filter-btn${filter === f.key ? ' active' : ''}`}
            onClick={() => setFilter(f.key)}
          >
            {f.label} <span className="cmp-filter-cnt">{f.count}</span>
          </button>
        ))}
        <span className="cmp-conv-sort">
          Sort:
          <button className={`cmp-sort-btn${sort === 'traffic' ? ' active' : ''}`} onClick={() => setSort('traffic')}>Traffic</button>
          <button className={`cmp-sort-btn${sort === 'delta' ? ' active' : ''}`} onClick={() => setSort('delta')}>Δ Bytes</button>
        </span>
      </div>

      {/* Table */}
      {rows.length === 0
        ? <div className="no-data">No conversations match this filter</div>
        : (
          <div className="cmp-conv-table-wrap">
            <table className="cmp-conv-table">
              <thead>
                <tr>
                  <th rowSpan={2}>Status</th>
                  <th rowSpan={2}>Conversation</th>
                  <th rowSpan={2}>Proto</th>
                  <th colSpan={3} className="cmp-conv-grp base" title={baseFilename}>Base</th>
                  <th colSpan={3} className="cmp-conv-grp compare" title={compareFilename}>Compare</th>
                  <th rowSpan={2}>Δ Bytes</th>
                </tr>
                <tr>
                  <th>Sess</th><th>Pkts</th><th>Bytes</th>
                  <th>Sess</th><th>Pkts</th><th>Bytes</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(c => (
                  <tr key={c.key} className={c.status === 'both' && c.byte_delta !== 0 ? 'cmp-conv-changed' : ''}>
                    <td>{statusBadge(c)}</td>
                    <td className="mono cmp-conv-pair">
                      {c.ip_a} <span className="arrow">⇄</span> {c.ip_b}
                      <span className="cmp-conv-port">:{c.port}</span>
                    </td>
                    <td><span className="proto-chip">{c.protocol}</span></td>
                    <td className="cmp-conv-num">{c.a_sessions || '—'}</td>
                    <td className="cmp-conv-num">{c.a_packets || '—'}</td>
                    <td className="cmp-conv-num">{c.a_bytes ? fmtBytes(c.a_bytes) : '—'}</td>
                    <td className="cmp-conv-num">{c.b_sessions || '—'}</td>
                    <td className="cmp-conv-num">{c.b_packets || '—'}</td>
                    <td className="cmp-conv-num">{c.b_bytes ? fmtBytes(c.b_bytes) : '—'}</td>
                    <td className="cmp-conv-num"><ConvBytesDelta delta={c.byte_delta} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      }

      {result.conversation_total > result.conversations.length && (
        <div className="cmp-truncate-notice">
          ⚠ Showing top {result.conversations.length} of {result.conversation_total} conversations (by traffic)
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────
export function ComparePanel({ baseUploadId, baseFilename }: Props) {
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState<string | null>(null)
  const [compareFilename, setCompareFilename] = useState<string | null>(null)
  const [result, setResult]   = useState<CompareResult | null>(null)
  const [innerTab, setInnerTab] = useState<InnerTab>('conversations')
  const [modal, setModal]     = useState<ModalState | null>(null)

  const handleFile = useCallback(async (file: File) => {
    if (!ALLOWED.test(file.name)) {
      setError('Supported formats: .pcap · .pcapng · .cap · .har · .log · .txt · .tcpdump')
      return
    }
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const up = await uploadPcap(file)
      await analyzePcap(up.upload_id)
      const r = await compareCaptures(baseUploadId, up.upload_id)
      setCompareFilename(file.name)
      setResult(r)
      setInnerTab('conversations')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [baseUploadId])

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  // Count click handlers
  function openNewIps(r: CompareResult) {
    const ipSet = new Set(r.new_ips)
    const sessions = r.compare_sessions.filter(
      s => ipSet.has(s.src_ip) || ipSet.has(s.dst_ip)
    )
    setModal({ kind: 'new_ips', sessions, title: `New IP sessions (${r.new_ips.length} IPs · ${sessions.length} sessions)` })
  }
  function openRemovedIps(r: CompareResult) {
    const ipSet = new Set(r.removed_ips)
    const sessions = r.base_sessions.filter(
      s => ipSet.has(s.src_ip) || ipSet.has(s.dst_ip)
    )
    setModal({ kind: 'removed_ips', sessions, title: `Removed IP sessions (${r.removed_ips.length} IPs · ${sessions.length} sessions)` })
  }
  function openNewPorts(r: CompareResult) {
    const portSet = new Set(r.new_ports)
    const sessions = r.compare_sessions.filter(s => portSet.has(s.dst_port))
    setModal({ kind: 'new_ports', sessions, title: `New port sessions (${r.new_ports.length} ports · ${sessions.length} sessions)` })
  }

  return (
    <div className="compare-panel">
      {/* Header */}
      <div className="compare-header">
        <div className="compare-file-label">
          <span className="chip chip-file">Base</span>
          <span className="compare-filename">{baseFilename}</span>
        </div>
        <span className="compare-arrow">vs</span>
        <div className="compare-file-label">
          <span className="chip chip-file">Compare</span>
          <span className="compare-filename">{compareFilename ?? 'No file selected'}</span>
        </div>
      </div>

      {/* Upload zone */}
      {!result && !loading && (
        <div
          className="compare-drop-zone"
          onDragOver={(e) => e.preventDefault()}
          onDrop={onDrop}
        >
          <input
            type="file"
            id="compare-input"
            accept=".pcap,.pcapng,.cap,.har,.log,.txt,.tcpdump"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f) }}
            hidden
          />
          <label htmlFor="compare-input" className="compare-drop-label">
            <p className="drop-primary">Drag a file to compare or click to upload</p>
            <p className="drop-hint">After upload, shows side-by-side session comparison · IP/port differences · protocol changes</p>
          </label>
        </div>
      )}

      {loading && (
        <div className="compare-loading">
          <div className="spinner" style={{ width: 28, height: 28 }} />
          <span>Analyzing compare file...</span>
        </div>
      )}

      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠</span>
          <pre className="error-text">{error}</pre>
        </div>
      )}

      {result && compareFilename && (
        <>
          {/* ── At-a-glance verdict: normal vs failure ── */}
          {result.verdict && (
            <div className={`compare-verdict verdict-${result.verdict.verdict.toLowerCase()}`}>
              <span className="compare-verdict-badge">{result.verdict.verdict}</span>
              <span className="compare-verdict-headline">{result.verdict.headline}</span>
              {(result.verdict.newly_failing > 0 || result.verdict.recovered > 0) && (
                <span className="compare-verdict-meta">
                  {result.verdict.newly_failing > 0 && <>▼ {result.verdict.newly_failing} newly failing </>}
                  {result.verdict.recovered > 0 && <>▲ {result.verdict.recovered} recovered</>}
                </span>
              )}
            </div>
          )}

          {/* ── Summary metrics (counts are clickable) ── */}
          <div className="compare-summary-row">
            <div className="compare-metric">
              <div className="compare-metric-val">
                {result.traffic_delta_pct === null
                  ? 'N/A'
                  : `${result.traffic_delta_pct > 0 ? '+' : ''}${result.traffic_delta_pct}%`}
              </div>
              <div className="compare-metric-label">Traffic change</div>
            </div>
            <div className="compare-metric">
              <div className="compare-metric-val">{fmtBytes(result.byte_ratio.a_total ?? 0)}</div>
              <div className="compare-metric-label">Base traffic</div>
            </div>
            <div className="compare-metric">
              <div className="compare-metric-val">{fmtBytes(result.byte_ratio.b_total ?? 0)}</div>
              <div className="compare-metric-label">Compare traffic</div>
            </div>

            {/* Clickable counts */}
            <button
              className="compare-metric clickable"
              onClick={() => openNewIps(result)}
              title="Click to view new IP session list"
            >
              <div className="compare-metric-val level-danger">{result.new_ips.length}</div>
              <div className="compare-metric-label">New IPs ↗</div>
            </button>
            <button
              className="compare-metric clickable"
              onClick={() => openRemovedIps(result)}
              title="Click to view removed IP session list"
            >
              <div className="compare-metric-val level-warn">{result.removed_ips.length}</div>
              <div className="compare-metric-label">Removed IPs ↗</div>
            </button>
            <button
              className="compare-metric clickable"
              onClick={() => openNewPorts(result)}
              title="Click to view new port session list"
            >
              <div className="compare-metric-val">{result.new_ports.length}</div>
              <div className="compare-metric-label">New ports ↗</div>
            </button>
          </div>

          {/* ── Inner tabs ── */}
          <div className="cmp-inner-tabs">
            {(['conversations', 'sessions', 'ips', 'protocols'] as InnerTab[]).map(t => (
              <button
                key={t}
                className={`cmp-inner-tab${innerTab === t ? ' active' : ''}`}
                onClick={() => setInnerTab(t)}
              >
                {{ conversations: '⇆ Conversation diff', sessions: '⇄ Session compare', ips: '⊕ IP / Port', protocols: '◎ Protocol' }[t]}
              </button>
            ))}
          </div>

          {/* ── Conversation statistical diff tab ── */}
          {innerTab === 'conversations' && (
            <Conversations
              result={result}
              baseFilename={baseFilename}
              compareFilename={compareFilename}
            />
          )}

          {/* ── Session side-by-side tab ── */}
          {innerTab === 'sessions' && (
            <SideBySide
              result={result}
              baseFilename={baseFilename}
              compareFilename={compareFilename}
            />
          )}

          {/* ── IP / Port tab ── */}
          {innerTab === 'ips' && (
            <div className="compare-grid">
              <ClickableIpList
                title="New IPs (compare only)"
                ips={result.new_ips}
                variant="danger"
                onClick={() => openNewIps(result)}
              />
              <ClickableIpList
                title="Removed IPs (base only)"
                ips={result.removed_ips}
                variant="warn"
                onClick={() => openRemovedIps(result)}
              />
              <ClickableIpList
                title="Common IPs"
                ips={result.common_ips}
                variant="ok"
              />
              <div className="compare-list-card">
                <div className="compare-list-title">
                  New ports (compare only)
                  {result.new_ports.length > 0 && (
                    <button className="cmp-list-detail-btn" onClick={() => openNewPorts(result)}>
                      View sessions
                    </button>
                  )}
                </div>
                {result.new_ports.length === 0
                  ? <div className="no-data">None</div>
                  : <div className="compare-port-list">
                      {result.new_ports.map((p) => (
                        <span key={p} className="port-chip">{p}</span>
                      ))}
                    </div>
                }
              </div>
            </div>
          )}

          {/* ── Protocol tab ── */}
          {innerTab === 'protocols' && (
            <div className="compare-grid">
              {Object.keys(result.protocol_diff).length === 0
                ? <div className="no-data">No protocol differences</div>
                : (
                  <div className="compare-list-card wide">
                    <div className="compare-list-title">Protocol traffic change (session count)</div>
                    <table className="compare-proto-table">
                      <thead>
                        <tr><th>Protocol</th><th>Base</th><th>Compare</th><th>Change</th></tr>
                      </thead>
                      <tbody>
                        {Object.entries(result.protocol_diff).map(([proto, { a, b }]) => {
                          const delta = b - a
                          return (
                            <tr key={proto}>
                              <td>{proto}</td>
                              <td>{a}</td>
                              <td>{b}</td>
                              <td className={delta > 0 ? 'txt-danger' : delta < 0 ? 'txt-ok' : ''}>
                                {delta > 0 ? '+' : ''}{delta} {delta > 0 ? '▲' : delta < 0 ? '▼' : '—'}
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )
              }
            </div>
          )}

          <button
            className="btn-new-file"
            style={{ marginTop: 16 }}
            onClick={() => { setResult(null); setCompareFilename(null) }}
          >
            Compare with another file
          </button>
        </>
      )}

      {/* Modal */}
      {modal && <SessionModal state={modal} onClose={() => setModal(null)} />}
    </div>
  )
}

function ClickableIpList({
  title, ips, variant, onClick,
}: {
  title: string
  ips: string[]
  variant: 'danger' | 'warn' | 'ok'
  onClick?: () => void
}) {
  return (
    <div className="compare-list-card">
      <div className={`compare-list-title txt-${variant}`}>
        {title}
        {onClick && ips.length > 0 && (
          <button className="cmp-list-detail-btn" onClick={onClick}>
            View sessions
          </button>
        )}
      </div>
      {ips.length === 0
        ? <div className="no-data">None</div>
        : <ul className="compare-ip-list">
            {ips.map((ip) => <li key={ip}>{ip}</li>)}
          </ul>
      }
    </div>
  )
}
