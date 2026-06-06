import { useState, useCallback } from 'react'
import { getPackets } from '../api'
import type { PacketEntry } from '../api'

interface Props {
  uploadId: string
  onFlowSelect?: (sessionId: string) => void
}

function fmtRelTs(s: number) {
  return s.toFixed(6)
}

const PROTO_COLOR: Record<string, string> = {
  TCP: '#63b3ed',
  UDP: '#68d391',
  ICMP: '#f6ad55',
  ICMP6: '#f6ad55',
}

function flagClass(flags: string): string {
  if (!flags || flags === '—') return 'flag-none'
  if (flags.includes('RST'))  return 'flag-rst'
  if (flags.includes('SYN') && flags.includes('ACK')) return 'flag-synack'
  if (flags.includes('SYN'))  return 'flag-syn'
  if (flags.includes('FIN'))  return 'flag-fin'
  if (flags.includes('PSH'))  return 'flag-psh'
  return 'flag-ack'
}

interface Filters { src: string; dst: string; proto: string; flags: string }

export function PacketList({ uploadId, onFlowSelect }: Props) {
  const [packets, setPackets] = useState<PacketEntry[]>([])
  const [total, setTotal] = useState(0)
  const [truncated, setTruncated] = useState(false)
  const [offset, setOffset] = useState(0)
  const [loading, setLoading] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [filters, setFilters] = useState<Filters>({ src: '', dst: '', proto: '', flags: '' })
  const [applied, setApplied] = useState<Filters>({ src: '', dst: '', proto: '', flags: '' })

  const limit = 100

  const load = useCallback(async (off: number, f: Filters) => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ offset: String(off), limit: String(limit) })
      if (f.src)   params.set('src_ip', f.src)
      if (f.dst)   params.set('dst_ip', f.dst)
      if (f.proto) params.set('proto',  f.proto)
      if (f.flags) params.set('flags',  f.flags)
      const r = await getPackets(uploadId, params.toString())
      setPackets(r.packets)
      setTotal(r.total)
      setTruncated(r.truncated)
      setOffset(off)
      setLoaded(true)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [uploadId])

  const applyFilter = () => {
    setApplied({ ...filters })
    load(0, filters)
  }

  const clearFilter = () => {
    const empty = { src: '', dst: '', proto: '', flags: '' }
    setFilters(empty)
    setApplied(empty)
    load(0, empty)
  }

  const totalPages  = Math.ceil(total / limit)
  const currentPage = Math.floor(offset / limit) + 1

  if (!loaded) {
    return (
      <div className="packet-list-init">
        <button className="filter-btn" onClick={() => load(0, applied)} disabled={loading}>
          {loading ? '로딩 중...' : '패킷 목록 불러오기'}
        </button>
        <p className="pkt-hint">캡처된 모든 패킷을 타임스탬프 순으로 표시합니다</p>
      </div>
    )
  }

  return (
    <div className="packet-list-wrap">

      {/* 필터 바 */}
      <div className="pkt-filter-bar">
        <input
          className="pkt-filter-input"
          placeholder="출발지 IP"
          value={filters.src}
          onChange={e => setFilters(f => ({ ...f, src: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()}
        />
        <input
          className="pkt-filter-input"
          placeholder="목적지 IP"
          value={filters.dst}
          onChange={e => setFilters(f => ({ ...f, dst: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()}
        />
        <input
          className="pkt-filter-input"
          placeholder="프로토콜"
          value={filters.proto}
          onChange={e => setFilters(f => ({ ...f, proto: e.target.value }))}
          style={{ width: 100 }}
          onKeyDown={e => e.key === 'Enter' && applyFilter()}
        />
        <input
          className="pkt-filter-input"
          placeholder="플래그 (SYN / RST...)"
          value={filters.flags}
          onChange={e => setFilters(f => ({ ...f, flags: e.target.value }))}
          style={{ width: 150 }}
          onKeyDown={e => e.key === 'Enter' && applyFilter()}
        />
        <button className="filter-btn" onClick={applyFilter}>필터</button>
        <button className="filter-btn" style={{ background: '#4a5568' }} onClick={clearFilter}>초기화</button>
        <span className="pkt-total">
          <strong>{total.toLocaleString()}</strong> 패킷
          {truncated && <span className="trunc-badge"> (상위 50,000개만 집계)</span>}
        </span>
      </div>

      {/* 테이블 */}
      <div className="pkt-table-wrap">
        <table className="pkt-global-table">
          <thead>
            <tr>
              <th>No.</th>
              <th>시각(s)</th>
              <th>출발지</th>
              <th>목적지</th>
              <th>Proto</th>
              <th>플래그</th>
              <th>크기</th>
              <th>Seq</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8} className="pkt-empty">로딩 중...</td></tr>
            ) : packets.length === 0 ? (
              <tr><td colSpan={8} className="pkt-empty">패킷 없음</td></tr>
            ) : packets.map((p, i) => {
              const color = PROTO_COLOR[p.proto] ?? '#a0aec0'
              return (
                <tr
                  key={i}
                  className="pkt-global-row"
                  style={{ cursor: onFlowSelect ? 'pointer' : 'default' }}
                  onClick={() => onFlowSelect?.(p.session_id)}
                  title={onFlowSelect ? '클릭: 이 세션의 패킷 흐름 열기' : ''}
                >
                  <td className="mono pkt-no">{p.no}</td>
                  <td className="mono pkt-relts">{fmtRelTs(p.rel_ts)}</td>
                  <td className="mono pkt-addr">
                    {p.src_ip}<span className="port-suffix">:{p.src_port}</span>
                  </td>
                  <td className="mono pkt-addr">
                    {p.dst_ip}<span className="port-suffix">:{p.dst_port}</span>
                  </td>
                  <td>
                    <span className="pkt-proto-badge" style={{ color }}>
                      {p.proto}
                    </span>
                  </td>
                  <td>
                    <span className={`flag-badge ${flagClass(p.flags)}`}>
                      {p.flags || '—'}
                    </span>
                  </td>
                  <td className="mono">{p.length}</td>
                  <td className="mono pkt-seq">
                    {p.proto === 'TCP' && p.seq ? p.seq.toLocaleString() : '—'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* 페이지네이션 */}
      {totalPages > 1 && (
        <div className="pkt-pagination">
          <button
            className="filter-btn"
            disabled={currentPage === 1 || loading}
            onClick={() => load(offset - limit, applied)}
          >◀ 이전</button>
          <span className="pkt-page-info">{currentPage} / {totalPages} 페이지</span>
          <button
            className="filter-btn"
            disabled={currentPage >= totalPages || loading}
            onClick={() => load(offset + limit, applied)}
          >다음 ▶</button>
        </div>
      )}
    </div>
  )
}
