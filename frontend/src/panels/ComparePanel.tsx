import { useState, useCallback, useMemo } from 'react'
import { uploadPcap, analyzePcap, compareCaptures } from '../api'
import type { CompareResult, CompareSession } from '../api'

const ALLOWED = /\.(pcap|pcapng|cap|har|log|txt|tcpdump)$/i

interface Props {
  baseUploadId: string
  baseFilename: string
}

// 세션 매칭 키: 양방향 동일 취급 (IP 쌍 정렬 + dst_port + protocol)
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
type InnerTab = 'sessions' | 'ips' | 'protocols'

// 모달 상태 타입
type ModalState =
  | { kind: 'new_ips';     sessions: CompareSession[]; title: string }
  | { kind: 'removed_ips'; sessions: CompareSession[]; title: string }
  | { kind: 'new_ports';   sessions: CompareSession[]; title: string }

// ── 세션 상세 모달 ────────────────────────────────────────────────────────
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
            ? <div className="no-data">세션 없음</div>
            : (
              <table className="cmp-session-table">
                <thead>
                  <tr>
                    <th>시각</th>
                    <th>출발지</th>
                    <th>목적지</th>
                    <th>프로토콜</th>
                    <th>패킷</th>
                    <th>전송량</th>
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

// ── 세션 사이드바이사이드 ─────────────────────────────────────────────────
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

  // 기준 세션 분류
  const baseSessions = useMemo(() => result.base_sessions.map(s => ({
    ...s,
    status: compareKeySet.has(sessionKey(s)) ? 'common' : 'removed',
  })), [result.base_sessions, compareKeySet])

  // 비교 세션 분류
  const compareSessions = useMemo(() => result.compare_sessions.map(s => ({
    ...s,
    status: baseKeySet.has(sessionKey(s)) ? 'common' : 'new',
  })), [result.compare_sessions, baseKeySet])

  const filteredBase = useMemo(() => {
    if (filter === 'all')     return baseSessions
    if (filter === 'removed') return baseSessions.filter(s => s.status === 'removed')
    if (filter === 'common')  return baseSessions.filter(s => s.status === 'common')
    return [] // 'new' — base에 신규 없음
  }, [baseSessions, filter])

  const filteredCompare = useMemo(() => {
    if (filter === 'all')    return compareSessions
    if (filter === 'new')    return compareSessions.filter(s => s.status === 'new')
    if (filter === 'common') return compareSessions.filter(s => s.status === 'common')
    return [] // 'removed' — compare에 사라진 없음
  }, [compareSessions, filter])

  const FILTERS: { key: SessionFilter; label: string }[] = [
    { key: 'all',     label: '전체' },
    { key: 'new',     label: '신규만' },
    { key: 'removed', label: '사라진만' },
    { key: 'common',  label: '공통만' },
  ]

  return (
    <div className="cmp-sbs-wrap">
      {/* 필터 바 */}
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
        <span className="cmp-sbs-hint">세션 행 클릭 시 상세 펼침</span>
      </div>

      {/* 좌우 분할 */}
      <div className="cmp-sbs-grid">
        {/* 기준 컬럼 */}
        <div className="cmp-sbs-col">
          <div className="cmp-sbs-col-header base">
            기준: {baseFilename}
            <span className="cmp-sbs-count">{filteredBase.length}개 세션</span>
          </div>
          <div className="cmp-sbs-list">
            {filteredBase.length === 0
              ? <div className="no-data">해당 세션 없음</div>
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

        {/* 비교 컬럼 */}
        <div className="cmp-sbs-col">
          <div className="cmp-sbs-col-header compare">
            비교: {compareFilename}
            <span className="cmp-sbs-count">{filteredCompare.length}개 세션</span>
          </div>
          <div className="cmp-sbs-list">
            {filteredCompare.length === 0
              ? <div className="no-data">해당 세션 없음</div>
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
            ⚠ 세션 수가 많아 각 최대 300개만 표시 (기준 {result.base_session_total}개 / 비교 {result.compare_session_total}개)
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
    s.status === 'new'     ? '신규' :
    s.status === 'removed' ? '사라짐' : '공통'

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
            <span className="cmp-detail-label">세션 ID</span>
            <span className="mono small">{s.session_id}</span>
            <span className="cmp-detail-label">시작</span>
            <span className="mono small">{new Date(s.start_ts * 1000).toISOString().replace('T', ' ').slice(0, 23)}</span>
            <span className="cmp-detail-label">종료</span>
            <span className="mono small">{new Date(s.end_ts * 1000).toISOString().replace('T', ' ').slice(0, 23)}</span>
            <span className="cmp-detail-label">지속시간</span>
            <span>{duration < 1 ? `${(duration * 1000).toFixed(0)}ms` : `${duration.toFixed(3)}s`}</span>
            <span className="cmp-detail-label">패킷 수</span>
            <span>{s.packet_count}</span>
            <span className="cmp-detail-label">전송↑</span>
            <span>{fmtBytes(s.bytes_sent)}</span>
            <span className="cmp-detail-label">수신↓</span>
            <span>{fmtBytes(s.bytes_recv)}</span>
          </div>
        </div>
      )}
    </>
  )
}

// ── 메인 컴포넌트 ─────────────────────────────────────────────────────────
export function ComparePanel({ baseUploadId, baseFilename }: Props) {
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState<string | null>(null)
  const [compareFilename, setCompareFilename] = useState<string | null>(null)
  const [result, setResult]   = useState<CompareResult | null>(null)
  const [innerTab, setInnerTab] = useState<InnerTab>('sessions')
  const [modal, setModal]     = useState<ModalState | null>(null)

  const handleFile = useCallback(async (file: File) => {
    if (!ALLOWED.test(file.name)) {
      setError('지원 포맷: .pcap · .pcapng · .cap · .har · .log · .txt · .tcpdump')
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
      setInnerTab('sessions')
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

  // 카운트 클릭 핸들러
  function openNewIps(r: CompareResult) {
    const ipSet = new Set(r.new_ips)
    const sessions = r.compare_sessions.filter(
      s => ipSet.has(s.src_ip) || ipSet.has(s.dst_ip)
    )
    setModal({ kind: 'new_ips', sessions, title: `신규 IP 세션 (${r.new_ips.length}개 IP · ${sessions.length}개 세션)` })
  }
  function openRemovedIps(r: CompareResult) {
    const ipSet = new Set(r.removed_ips)
    const sessions = r.base_sessions.filter(
      s => ipSet.has(s.src_ip) || ipSet.has(s.dst_ip)
    )
    setModal({ kind: 'removed_ips', sessions, title: `사라진 IP 세션 (${r.removed_ips.length}개 IP · ${sessions.length}개 세션)` })
  }
  function openNewPorts(r: CompareResult) {
    const portSet = new Set(r.new_ports)
    const sessions = r.compare_sessions.filter(s => portSet.has(s.dst_port))
    setModal({ kind: 'new_ports', sessions, title: `신규 포트 세션 (${r.new_ports.length}개 포트 · ${sessions.length}개 세션)` })
  }

  return (
    <div className="compare-panel">
      {/* 헤더 */}
      <div className="compare-header">
        <div className="compare-file-label">
          <span className="chip chip-file">기준</span>
          <span className="compare-filename">{baseFilename}</span>
        </div>
        <span className="compare-arrow">vs</span>
        <div className="compare-file-label">
          <span className="chip chip-file">비교</span>
          <span className="compare-filename">{compareFilename ?? '파일 미선택'}</span>
        </div>
      </div>

      {/* 업로드 존 */}
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
            <p className="drop-primary">비교할 파일을 드래그하거나 클릭하여 업로드</p>
            <p className="drop-hint">업로드 후 세션 사이드바이사이드 비교 · IP/포트 차이 · 프로토콜 변화를 표시합니다</p>
          </label>
        </div>
      )}

      {loading && (
        <div className="compare-loading">
          <div className="spinner" style={{ width: 28, height: 28 }} />
          <span>비교 파일 분석 중...</span>
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
          {/* ── 요약 메트릭 (카운트 클릭 가능) ── */}
          <div className="compare-summary-row">
            <div className="compare-metric">
              <div className="compare-metric-val">
                {result.traffic_delta_pct === null
                  ? 'N/A'
                  : `${result.traffic_delta_pct > 0 ? '+' : ''}${result.traffic_delta_pct}%`}
              </div>
              <div className="compare-metric-label">트래픽 증감</div>
            </div>
            <div className="compare-metric">
              <div className="compare-metric-val">{fmtBytes(result.byte_ratio.a_total ?? 0)}</div>
              <div className="compare-metric-label">기준 트래픽</div>
            </div>
            <div className="compare-metric">
              <div className="compare-metric-val">{fmtBytes(result.byte_ratio.b_total ?? 0)}</div>
              <div className="compare-metric-label">비교 트래픽</div>
            </div>

            {/* 클릭 가능 카운트 */}
            <button
              className="compare-metric clickable"
              onClick={() => openNewIps(result)}
              title="클릭하여 신규 IP 세션 목록 보기"
            >
              <div className="compare-metric-val level-danger">{result.new_ips.length}</div>
              <div className="compare-metric-label">신규 IP ↗</div>
            </button>
            <button
              className="compare-metric clickable"
              onClick={() => openRemovedIps(result)}
              title="클릭하여 사라진 IP 세션 목록 보기"
            >
              <div className="compare-metric-val level-warn">{result.removed_ips.length}</div>
              <div className="compare-metric-label">사라진 IP ↗</div>
            </button>
            <button
              className="compare-metric clickable"
              onClick={() => openNewPorts(result)}
              title="클릭하여 신규 포트 세션 목록 보기"
            >
              <div className="compare-metric-val">{result.new_ports.length}</div>
              <div className="compare-metric-label">신규 포트 ↗</div>
            </button>
          </div>

          {/* ── 내부 탭 ── */}
          <div className="cmp-inner-tabs">
            {(['sessions', 'ips', 'protocols'] as InnerTab[]).map(t => (
              <button
                key={t}
                className={`cmp-inner-tab${innerTab === t ? ' active' : ''}`}
                onClick={() => setInnerTab(t)}
              >
                {{ sessions: '⇄ 세션 비교', ips: '⊕ IP / 포트', protocols: '◎ 프로토콜' }[t]}
              </button>
            ))}
          </div>

          {/* ── 세션 사이드바이사이드 탭 ── */}
          {innerTab === 'sessions' && (
            <SideBySide
              result={result}
              baseFilename={baseFilename}
              compareFilename={compareFilename}
            />
          )}

          {/* ── IP / 포트 탭 ── */}
          {innerTab === 'ips' && (
            <div className="compare-grid">
              <ClickableIpList
                title="신규 IP (비교에만 있음)"
                ips={result.new_ips}
                variant="danger"
                onClick={() => openNewIps(result)}
              />
              <ClickableIpList
                title="사라진 IP (기준에만 있음)"
                ips={result.removed_ips}
                variant="warn"
                onClick={() => openRemovedIps(result)}
              />
              <ClickableIpList
                title="공통 IP"
                ips={result.common_ips}
                variant="ok"
              />
              <div className="compare-list-card">
                <div className="compare-list-title">
                  신규 포트 (비교에만 있음)
                  {result.new_ports.length > 0 && (
                    <button className="cmp-list-detail-btn" onClick={() => openNewPorts(result)}>
                      세션 보기
                    </button>
                  )}
                </div>
                {result.new_ports.length === 0
                  ? <div className="no-data">없음</div>
                  : <div className="compare-port-list">
                      {result.new_ports.map((p) => (
                        <span key={p} className="port-chip">{p}</span>
                      ))}
                    </div>
                }
              </div>
            </div>
          )}

          {/* ── 프로토콜 탭 ── */}
          {innerTab === 'protocols' && (
            <div className="compare-grid">
              {Object.keys(result.protocol_diff).length === 0
                ? <div className="no-data">프로토콜 차이 없음</div>
                : (
                  <div className="compare-list-card wide">
                    <div className="compare-list-title">프로토콜 트래픽 변화 (세션 수)</div>
                    <table className="compare-proto-table">
                      <thead>
                        <tr><th>프로토콜</th><th>기준</th><th>비교</th><th>변화</th></tr>
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
            다른 파일과 비교
          </button>
        </>
      )}

      {/* 모달 */}
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
            세션 보기
          </button>
        )}
      </div>
      {ips.length === 0
        ? <div className="no-data">없음</div>
        : <ul className="compare-ip-list">
            {ips.map((ip) => <li key={ip}>{ip}</li>)}
          </ul>
      }
    </div>
  )
}
