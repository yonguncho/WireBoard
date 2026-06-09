import { useState, useCallback } from 'react'
import { getPackets } from '../api'
import type { PacketEntry } from '../api'

interface Props {
  uploadId: string
  onFlowSelect?: (sessionId: string) => void
}

const PROTO_COLOR: Record<string, string> = {
  TCP: '#63b3ed', UDP: '#68d391', ICMP: '#f6ad55', ICMP6: '#f6ad55',
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

function hexToAscii(hex: string): string {
  return (hex.replace(/\s+/g, '').match(/.{1,2}/g) ?? [])
    .map(b => { const c = parseInt(b, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : '.' })
    .join('')
}

function formatHexDump(hex: string): string {
  const bytes = (hex.replace(/\s+/g, '').match(/.{1,2}/g) ?? []).map(b => parseInt(b, 16))
  return bytes.reduce((lines: string[], _, i) => {
    if (i % 16 !== 0) return lines
    const chunk = bytes.slice(i, i + 16)
    const offset = i.toString(16).padStart(4, '0')
    const hexPart = chunk.map((b, j) => (j === 8 ? ' ' + b.toString(16).padStart(2,'0') : b.toString(16).padStart(2,'0'))).join(' ').padEnd(49)
    const ascii   = chunk.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('')
    lines.push(`${offset}  ${hexPart}  ${ascii}`)
    return lines
  }, []).join('\n')
}

function decodePacketInfo(p: PacketEntry): string {
  const flags    = p.flags || ''
  const isSyn    = flags.includes('SYN') && !flags.includes('ACK')
  const isSynAck = flags.includes('SYN') && flags.includes('ACK')
  const isRst    = flags.includes('RST')
  const isFin    = flags.includes('FIN')

  if (!p.payload_hex || p.payload_len === 0) {
    if (isSyn)    return '연결 요청 (SYN)'
    if (isSynAck) return '연결 수락 (SYN+ACK)'
    if (isRst)    return '연결 강제 종료 (RST)'
    if (isFin)    return '연결 종료 (FIN)'
    return 'ACK'
  }

  const ascii = hexToAscii(p.payload_hex).trimStart()
  const httpReq = ascii.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP\/[\d.]+/)
  if (httpReq) return `HTTP ${httpReq[1]} ${httpReq[2]}`
  const httpRes = ascii.match(/^HTTP\/([\d.]+)\s+(\d+)\s*([^\r\n]*)/)
  if (httpRes)  return `HTTP ${httpRes[2]} ${httpRes[3].trim() || 'OK'}`
  if (p.proto === 'UDP' && (p.src_port === 53 || p.dst_port === 53)) return `DNS ${p.payload_len}B`
  if (p.proto === 'UDP') return `UDP ${p.payload_len}B`
  if (p.proto === 'ICMP' || p.proto === 'ICMP6') return `ICMP ${p.payload_len}B`
  return `데이터 ${p.payload_len}B`
}

interface Filters { src: string; dst: string; proto: string; flags: string }

function ExpandedRow({ p }: { p: PacketEntry }) {
  const ascii = p.payload_hex ? hexToAscii(p.payload_hex) : ''
  const dump  = p.payload_hex ? formatHexDump(p.payload_hex) : ''
  const isHttp = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP\/)/.test(ascii.trimStart())
  return (
    <div className="pkt-expand-body">
      {isHttp ? (
        <pre className="pkt-ascii-body">{ascii}</pre>
      ) : dump ? (
        <pre className="hex-dump-wireshark">{dump}</pre>
      ) : (
        <div className="pkt-expand-nodata">페이로드 없음</div>
      )}
    </div>
  )
}

export function PacketList({ uploadId, onFlowSelect }: Props) {
  const [packets, setPackets]   = useState<PacketEntry[]>([])
  const [total, setTotal]       = useState(0)
  const [truncated, setTruncated] = useState(false)
  const [offset, setOffset]     = useState(0)
  const [loading, setLoading]   = useState(false)
  const [loaded, setLoaded]     = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [filters, setFilters]   = useState<Filters>({ src: '', dst: '', proto: '', flags: '' })
  const [applied, setApplied]   = useState<Filters>({ src: '', dst: '', proto: '', flags: '' })

  const limit = 100

  const load = useCallback(async (off: number, f: Filters) => {
    setLoading(true); setExpanded(null); setLoadError(null)
    try {
      const params = new URLSearchParams({ offset: String(off), limit: String(limit) })
      if (f.src)   params.set('src_ip', f.src)
      if (f.dst)   params.set('dst_ip', f.dst)
      if (f.proto) params.set('proto', f.proto)
      if (f.flags) params.set('flags', f.flags)
      const r = await getPackets(uploadId, params.toString())
      setPackets(r.packets); setTotal(r.total); setTruncated(r.truncated); setOffset(off); setLoaded(true)
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setLoadError(msg)
      console.error('패킷 로드 실패:', msg)
    }
    finally { setLoading(false) }
  }, [uploadId])

  const applyFilter = () => { setApplied({ ...filters }); load(0, filters) }
  const clearFilter = () => {
    const empty = { src: '', dst: '', proto: '', flags: '' }
    setFilters(empty); setApplied(empty); load(0, empty)
  }
  const applyPreset = (preset: Partial<Filters>) => {
    const next = { src: '', dst: '', proto: '', flags: '', ...preset }
    setFilters(next); setApplied(next); load(0, next)
  }

  const totalPages  = Math.ceil(total / limit)
  const currentPage = Math.floor(offset / limit) + 1

  if (loadError && !loaded) return (
    <div className="packet-list-init">
      <div className="pkt-load-error">⚠ 패킷 로드 실패: {loadError}</div>
      <button className="filter-btn" style={{ marginTop: 8 }} onClick={() => load(0, applied)}>
        다시 시도
      </button>
    </div>
  )

  if (!loaded) return (
    <div className="packet-list-init">
      <button className="filter-btn" onClick={() => load(0, applied)} disabled={loading}>
        {loading ? '로딩 중...' : '패킷 목록 불러오기'}
      </button>
      <p className="pkt-hint">캡처된 모든 패킷을 타임스탬프 순으로 표시합니다 · 행 클릭 시 HEX 덤프 확인 가능</p>
    </div>
  )

  return (
    <div className="packet-list-wrap">
      {loadError && (
        <div className="pkt-load-error" style={{ marginBottom: 8 }}>⚠ 필터 적용 실패: {loadError}</div>
      )}
      {/* 프리셋 필터 버튼 */}
      <div className="pkt-preset-bar">
        <span className="pkt-preset-label">빠른 필터:</span>
        {([
          ['RST 연결', { flags: 'RST' }],
          ['SYN 스캔', { flags: 'SYN', proto: 'TCP' }],
          ['TCP', { proto: 'TCP' }],
          ['UDP', { proto: 'UDP' }],
          ['ICMP', { proto: 'ICMP' }],
        ] as [string, Partial<Filters>][]).map(([label, preset]) => (
          <button key={label} className="pkt-preset-btn" onClick={() => applyPreset(preset)}>
            {label}
          </button>
        ))}
        {(applied.src || applied.dst || applied.proto || applied.flags) && (
          <button className="pkt-preset-btn pkt-preset-clear" onClick={clearFilter}>✕ 초기화</button>
        )}
      </div>

      {/* 필터 바 */}
      <div className="pkt-filter-bar">
        <input className="pkt-filter-input" placeholder="출발지 IP" value={filters.src} style={{ width: 130 }}
          onChange={e => setFilters(f => ({ ...f, src: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()} />
        <input className="pkt-filter-input" placeholder="목적지 IP" value={filters.dst} style={{ width: 130 }}
          onChange={e => setFilters(f => ({ ...f, dst: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()} />
        <input className="pkt-filter-input" placeholder="프로토콜" value={filters.proto} style={{ width: 90 }}
          onChange={e => setFilters(f => ({ ...f, proto: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()} />
        <input className="pkt-filter-input" placeholder="플래그 (SYN, RST...)" value={filters.flags} style={{ width: 140 }}
          onChange={e => setFilters(f => ({ ...f, flags: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()} />
        <button className="filter-btn" onClick={applyFilter}>필터</button>
        <button className="filter-btn" style={{ background: '#4a5568' }} onClick={clearFilter}>초기화</button>
        <span className="pkt-total">
          <strong>{total.toLocaleString()}</strong> 패킷
          {truncated && <span className="trunc-badge"> (상위 50,000만 집계)</span>}
        </span>
      </div>

      {/* 테이블 */}
      <div className="pkt-table-wrap">
        <table className="pkt-global-table">
          <thead>
            <tr>
              <th>No.</th><th>시각(s)</th><th>출발지</th><th>목적지</th>
              <th>Proto</th><th>플래그</th><th>크기</th><th>Seq</th><th>정보</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={9} className="pkt-empty">로딩 중...</td></tr>
            ) : packets.length === 0 ? (
              <tr><td colSpan={9} className="pkt-empty">패킷 없음</td></tr>
            ) : packets.map((p, i) => {
              const color   = PROTO_COLOR[p.proto] ?? '#a0aec0'
              const isOpen  = expanded === i
              const hasData = !!p.payload_hex && p.payload_len > 0
              const info    = decodePacketInfo(p)
              return (
                <>
                  <tr
                    key={`r${i}`}
                    className={`pkt-global-row${isOpen ? ' pkt-row-expanded' : ''}`}
                    style={{ cursor: 'pointer' }}
                    onClick={() => {
                      setExpanded(isOpen ? null : i)