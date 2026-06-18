import { useState, useCallback, useEffect } from 'react'
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
    if (isSyn)    return 'Connection request (SYN)'
    if (isSynAck) return 'Connection accepted (SYN+ACK)'
    if (isRst)    return 'Connection reset (RST)'
    if (isFin)    return 'Connection closed (FIN)'
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
  return `Data ${p.payload_len}B`
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
        <div className="pkt-expand-nodata">No payload</div>
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
      console.error('Failed to load packets:', msg)
    }
    finally { setLoading(false) }
  }, [uploadId])

  // 패킷 리스트는 진입 즉시 자동 로드 (버튼 클릭 불필요)
  useEffect(() => { load(0, { src: '', dst: '', proto: '', flags: '' }) }, [load])

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
      <div className="pkt-load-error">⚠ Failed to load packets: {loadError}</div>
      <button className="filter-btn" style={{ marginTop: 8 }} onClick={() => load(0, applied)}>
        Retry
      </button>
    </div>
  )

  if (!loaded) return (
    <div className="packet-list-init">
      <div className="spinner sm" /> Loading packets...
    </div>
  )

  return (
    <div className="packet-list-wrap">
      {loadError && (
        <div className="pkt-load-error" style={{ marginBottom: 8 }}>⚠ Failed to apply filter: {loadError}</div>
      )}
      {/* Preset filter buttons */}
      <div className="pkt-preset-bar">
        <span className="pkt-preset-label">Quick filter:</span>
        {([
          ['RST connections', { flags: 'RST' }],
          ['SYN scan', { flags: 'SYN', proto: 'TCP' }],
          ['TCP', { proto: 'TCP' }],
          ['UDP', { proto: 'UDP' }],
          ['ICMP', { proto: 'ICMP' }],
        ] as [string, Partial<Filters>][]).map(([label, preset]) => (
          <button key={label} className="pkt-preset-btn" onClick={() => applyPreset(preset)}>
            {label}
          </button>
        ))}
        {(applied.src || applied.dst || applied.proto || applied.flags) && (
          <button className="pkt-preset-btn pkt-preset-clear" onClick={clearFilter}>✕ Clear</button>
        )}
      </div>

      {/* Filter bar */}
      <div className="pkt-filter-bar">
        <input className="pkt-filter-input" placeholder="Source IP" value={filters.src} style={{ width: 130 }}
          onChange={e => setFilters(f => ({ ...f, src: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()} />
        <input className="pkt-filter-input" placeholder="Destination IP" value={filters.dst} style={{ width: 130 }}
          onChange={e => setFilters(f => ({ ...f, dst: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()} />
        <input className="pkt-filter-input" placeholder="Protocol" value={filters.proto} style={{ width: 90 }}
          onChange={e => setFilters(f => ({ ...f, proto: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()} />
        <input className="pkt-filter-input" placeholder="Flags (SYN, RST...)" value={filters.flags} style={{ width: 140 }}
          onChange={e => setFilters(f => ({ ...f, flags: e.target.value }))}
          onKeyDown={e => e.key === 'Enter' && applyFilter()} />
        <button className="filter-btn" onClick={applyFilter}>Filter</button>
        <button className="filter-btn" style={{ background: '#4a5568' }} onClick={clearFilter}>Clear</button>
        <span className="pkt-total">
          <strong>{total.toLocaleString()}</strong> Packets
          {truncated && <span className="trunc-badge"> (top 50,000 only)</span>}
        </span>
      </div>

      {/* Table */}
      <div className="pkt-table-wrap">
        <table className="pkt-global-table">
          <thead>
            <tr>
              <th>No.</th><th>Time(s)</th><th>Source</th><th>Destination</th>
              <th>Proto</th><th>Flags</th><th>Size</th><th>Seq</th><th>Info</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={9} className="pkt-empty">Loading...</td></tr>
            ) : packets.length === 0 ? (
              <tr><td colSpan={9} className="pkt-empty">No packets</td></tr>
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
                      if (onFlowSelect && !isOpen) onFlowSelect(p.session_id)
                    }}
                    title={hasData ? 'Click: HEX dump / open session' : 'Click: open session'}
                  >
                    <td className="mono pkt-no">{p.no}</td>
                    <td className="mono pkt-relts">{p.rel_ts.toFixed(6)}</td>
                    <td className="mono pkt-addr">{p.src_ip}<span className="port-suffix">:{p.src_port}</span></td>
                    <td className="mono pkt-addr">{p.dst_ip}<span className="port-suffix">:{p.dst_port}</span></td>
                    <td><span className="pkt-proto-badge" style={{ color }}>{p.proto}</span></td>
                    <td><span className={`flag-badge ${flagClass(p.flags)}`}>{p.flags || '—'}</span></td>
                    <td className="mono">{p.length}</td>
                    <td className="mono pkt-seq">{p.proto === 'TCP' && p.seq != null ? p.seq.toLocaleString() : '—'}</td>
                    <td className="pkt-info-cell">
                      {info}
                      {hasData && <span className="hex-expand-hint">{isOpen ? ' ▲' : ' ▼'}</span>}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="pkt-expand-row" key={`e${i}`}>
                      <td colSpan={9}><ExpandedRow p={p} /></td>
                    </tr>
                  )}
                </>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="pkt-pagination">
          <button className="filter-btn" disabled={currentPage === 1 || loading} onClick={() => load(offset - limit, applied)}>
            ◀ Previous
          </button>
          <span className="pkt-page-info">Page {currentPage} / {totalPages}</span>
          <button className="filter-btn" disabled={currentPage >= totalPages || loading} onClick={() => load(offset + limit, applied)}>
            Next ▶
          </button>
        </div>
      )}
    </div>
  )
}