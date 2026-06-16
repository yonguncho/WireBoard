import { useEffect, useMemo, useState } from 'react'
import { getHar } from '../api'
import type { HarData, HarEntry } from '../api'

interface Props {
  uploadId: string
  onFlowSelect?: (sessionId: string) => void
}

const PHASES: { key: keyof HarEntry['timings']; label: string; color: string }[] = [
  { key: 'blocked', label: '대기(Blocked)', color: '#94a3b8' },
  { key: 'dns', label: 'DNS', color: '#14b8a6' },
  { key: 'connect', label: '연결(Connect)', color: '#f59e0b' },
  { key: 'ssl', label: 'TLS', color: '#a855f7' },
  { key: 'send', label: '전송(Send)', color: '#ef4444' },
  { key: 'wait', label: '대기응답(TTFB)', color: '#22c55e' },
  { key: 'receive', label: '수신(Receive)', color: '#3b82f6' },
]

function fmtBytes(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}
function fmtMs(ms: number) {
  if (ms >= 1000) return (ms / 1000).toFixed(2) + ' s'
  return ms.toFixed(0) + ' ms'
}
function pathOf(url: string) {
  try {
    const u = new URL(url)
    return (u.pathname || '/') + (u.search || '')
  } catch {
    return url
  }
}
function statusClass(code: number) {
  if (code >= 500) return 'har-st-5xx'
  if (code >= 400) return 'har-st-4xx'
  if (code >= 300) return 'har-st-3xx'
  if (code >= 200) return 'har-st-2xx'
  return 'har-st-na'
}

type SortKey = 'start' | 'time' | 'size'
type Filter = 'all' | '2xx' | '3xx' | '4xx' | '5xx'

export function HarWaterfall({ uploadId, onFlowSelect }: Props) {
  const [data, setData] = useState<HarData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [sort, setSort] = useState<SortKey>('start')
  const [filter, setFilter] = useState<Filter>('all')
  const [q, setQ] = useState('')

  useEffect(() => {
    setData(null); setError(null)
    getHar(uploadId)
      .then(setData)
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [uploadId])

  const rows = useMemo(() => {
    if (!data) return []
    let r = data.entries
    if (filter !== 'all') r = r.filter(e => statusClass(e.status) === `har-st-${filter}`)
    if (q.trim()) {
      const needle = q.trim().toLowerCase()
      r = r.filter(e => e.url.toLowerCase().includes(needle) || e.host.toLowerCase().includes(needle))
    }
    const sorted = [...r]
    if (sort === 'start') sorted.sort((a, b) => a.start_offset_ms - b.start_offset_ms)
    else if (sort === 'time') sorted.sort((a, b) => b.total_ms - a.total_ms)
    else if (sort === 'size') sorted.sort((a, b) => b.resp_size - a.resp_size)
    return sorted
  }, [data, filter, q, sort])

  if (error) return <div className="flow-error">{error}</div>
  if (!data) return <div className="flow-loading"><div className="spinner sm" />HAR 분석 로드 중...</div>
  if (data.count === 0) return <div className="no-data">HAR 요청 데이터 없음</div>

  const totalSpan = Math.max(1, data.summary.total_time_ms)
  const sg = data.summary.status_groups

  return (
    <div className="har-waterfall">
      <div className="har-summary">
        <div className="har-sum-item"><span className="har-sum-num">{data.summary.count}</span><span className="har-sum-lbl">요청</span></div>
        <div className="har-sum-item"><span className="har-sum-num">{fmtBytes(data.summary.total_bytes)}</span><span className="har-sum-lbl">총 전송</span></div>
        <div className="har-sum-item"><span className="har-sum-num">{fmtMs(data.summary.total_time_ms)}</span><span className="har-sum-lbl">총 소요</span></div>
        <div className="har-sum-status">
          {(['2xx', '3xx', '4xx', '5xx'] as const).map(g => (
            sg[g] > 0 && <span key={g} className={`har-sum-badge ${statusClass(g === '2xx' ? 200 : g === '3xx' ? 300 : g === '4xx' ? 400 : 500)}`}>{g} {sg[g]}</span>
          ))}
        </div>
      </div>

      <div className="har-toolbar">
        <div className="har-filters">
          {(['all', '2xx', '3xx', '4xx', '5xx'] as Filter[]).map(f => (
            <button key={f} className={`filter-btn${filter === f ? ' active' : ''}`} onClick={() => setFilter(f)}>
              {f === 'all' ? '전체' : f}
            </button>
          ))}
        </div>
        <input className="har-search" placeholder="URL · 호스트 검색" value={q} onChange={e => setQ(e.target.value)} />
        <div className="har-sorts">
          {([['start', '시작순'], ['time', '느린순'], ['size', '큰순']] as [SortKey, string][]).map(([k, l]) => (
            <button key={k} className={`filter-btn${sort === k ? ' active' : ''}`} onClick={() => setSort(k)}>{l}</button>
          ))}
        </div>
      </div>

      <div className="har-legend">
        {PHASES.map(p => (
          <span key={p.key} className="har-legend-item">
            <span className="har-legend-swatch" style={{ background: p.color }} />{p.label}
          </span>
        ))}
        {onFlowSelect && <span className="har-legend-hint">행 클릭 → 패킷 흐름</span>}
      </div>

      <div className="har-rows">
        {rows.map(e => {
          const leftPct = (e.start_offset_ms / totalSpan) * 100
          const widthPct = Math.max(0.4, (e.total_ms / totalSpan) * 100)
          return (
            <div
              key={e.session_id}
              className={`har-row${onFlowSelect ? ' clickable' : ''}`}
              onClick={() => onFlowSelect?.(e.session_id)}
              title={e.url}
            >
              <span className={`har-method m-${e.method.toLowerCase()}`}>{e.method}</span>
              <span className={`har-status ${statusClass(e.status)}`}>{e.status || '—'}</span>
              <span className="har-url">
                <span className="har-host">{e.host || '—'}</span>
                <span className="har-path">{pathOf(e.url)}</span>
              </span>
              <span className="har-size">{e.resp_size > 0 ? fmtBytes(e.resp_size) : '—'}</span>
              <span className="har-time">{fmtMs(e.total_ms)}</span>
              <span className="har-track">
                <span className="har-bar" style={{ left: `${leftPct}%`, width: `${widthPct}%` }}>
                  {PHASES.map(p => {
                    const v = e.timings[p.key]
                    if (!v || v <= 0) return null
                    const segPct = (v / Math.max(1, e.total_ms)) * 100
                    return <span key={p.key} className="har-seg" style={{ width: `${segPct}%`, background: p.color }} title={`${p.label}: ${fmtMs(v)}`} />
                  })}
                </span>
              </span>
            </div>
          )
        })}
        {rows.length === 0 && <div className="no-data">조건에 맞는 요청 없음</div>}
      </div>
    </div>
  )
}
