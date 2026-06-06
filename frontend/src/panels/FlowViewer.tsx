import { useEffect, useState, useMemo } from 'react'
import { getFlow } from '../api'
import type { FlowData, FlowPacket } from '../api'

function hexToAscii(hex: string): string {
  const bytes = hex.replace(/\s+/g, '').match(/.{1,2}/g) ?? []
  return bytes.map(b => {
    const code = parseInt(b, 16)
    return (code >= 32 && code < 127) || code === 9 || code === 10 || code === 13
      ? String.fromCharCode(code) : '.'
  }).join('')
}

function isHttpContent(text: string): boolean {
  return /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP\/[12])/.test(text.trimStart())
}

function ReplayView({ packets }: { packets: FlowPacket[] }) {
  const segments = useMemo(() => {
    return packets
      .filter(p => p.payload_hex && p.payload_len > 0)
      .map(p => ({ dir: p.direction, text: hexToAscii(p.payload_hex!) }))
      .filter(s => s.text.trim().length > 0)
  }, [packets])

  if (!segments.length) return <div className="replay-empty">재생할 페이로드 없음</div>

  const hasHttp = segments.some(s => isHttpContent(s.text))

  return (
    <div className="replay-view">
      {hasHttp && <div className="replay-badge">HTTP 세션 감지됨</div>}
      {segments.map((seg, i) => (
        <div key={i} className={`replay-segment ${seg.dir === 'fwd' ? 'replay-fwd' : 'replay-rev'}`}>
          <div className="replay-dir-label">{seg.dir === 'fwd' ? '→ 클라이언트 송신' : '← 서버 응답'}</div>
          <pre className="replay-text">{seg.text}</pre>
        </div>
      ))}
    </div>
  )
}

interface Props {
  uploadId: string
  sessionId: string
  onClose: () => void
}

function fmtBytes(b: number) {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

function fmtRelTs(s: number) {
  if (s < 1) return '+' + (s * 1000).toFixed(1) + ' ms'
  return '+' + s.toFixed(3) + ' s'
}

function FlagBadge({ flags }: { flags: string }) {
  if (!flags || flags === '—') return <span className="flag-badge flag-none">—</span>
  const cls =
    flags.includes('RST') ? 'flag-rst' :
    flags.includes('SYN') && flags.includes('ACK') ? 'flag-synack' :
    flags.includes('SYN') ? 'flag-syn' :
    flags.includes('FIN') ? 'flag-fin' :
    flags.includes('PSH') ? 'flag-psh' : 'flag-ack'
  return <span className={`flag-badge ${cls}`}>{flags}</span>
}

function PacketRow({ pkt, idx, base }: { pkt: FlowPacket; idx: number; base: string }) {
  const [expanded, setExpanded] = useState(false)
  const isFwd = pkt.direction === 'fwd'
  return (
    <>
      <tr
        className={`pkt-row ${isFwd ? 'pkt-fwd' : 'pkt-rev'}`}
        onClick={() => pkt.payload_hex && setExpanded(v => !v)}
        style={{ cursor: pkt.payload_hex ? 'pointer' : 'default' }}
      >
        <td className="mono pkt-num">{idx + 1}</td>
        <td className="mono pkt-relts">{idx === 0 ? '0.000 s' : fmtRelTs(pkt.rel_ts)}</td>
        <td className="pkt-dir">{isFwd
          ? <span className="dir-fwd">→ {base}</span>
          : <span className="dir-rev">← {base}</span>}
        </td>
        <td><FlagBadge flags={pkt.flags} /></td>
        <td className="mono">{pkt.proto === 'TCP' ? pkt.seq.toLocaleString() : '—'}</td>
        <td className="mono">{pkt.proto === 'TCP' ? pkt.ack.toLocaleString() : '—'}</td>
        <td className="mono">{pkt.length}</td>
        <td className="mono pkt-payload-len">{pkt.payload_len > 0 ? pkt.payload_len : '—'}</td>
      </tr>
      {expanded && pkt.payload_hex && (
        <tr className="pkt-hex-row">
          <td colSpan={8}>
            <div className="hex-dump">{pkt.payload_hex}</div>
          </td>
        </tr>
      )}
    </>
  )
}

export function FlowViewer({ uploadId, sessionId, onClose }: Props) {
  const [data, setData] = useState<FlowData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [view, setView] = useState<'packets' | 'replay'>('packets')

  useEffect(() => {
    setData(null); setError(null)
    getFlow(uploadId, sessionId)
      .then(setData)
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
  }, [uploadId, sessionId])

  const s = data?.session

  return (
    <div className="flow-overlay" onClick={onClose}>
      <div className="flow-panel" onClick={e => e.stopPropagation()}>

        {/* 헤더 */}
        <div className="flow-panel-header">
          <div className="flow-title">
            {s ? (
              <span className="flow-tuple">
                <span className="flow-src">{s.src_ip}:{s.src_port}</span>
                <span className="flow-arrow"> → </span>
                <span className="flow-dst">{s.dst_ip}:{s.dst_port}</span>
                <span className="flow-proto-badge">{s.protocol}</span>
                {s.rst && <span className="flow-rst-badge">RST</span>}
              </span>
            ) : '세션 로드 중...'}
          </div>
          <button className="flow-close-btn" onClick={onClose}>✕</button>
        </div>

        {/* 통계 바 */}
        {s && (
          <div className="flow-stats-bar">
            <span><strong>{data.packet_count.toLocaleString()}</strong> 패킷{data.truncated && <span className="trunc-badge"> (상위 200 표시)</span>}</span>
            <span>↑ {fmtBytes(s.bytes_sent)}</span>
            <span>↓ {fmtBytes(s.bytes_recv)}</span>
            <span>⏱ {s.duration_s.toFixed(3)} s</span>
            <div className="flow-view-tabs">
              <button className={`flow-tab ${view === 'packets' ? 'active' : ''}`} onClick={() => setView('packets')}>패킷</button>
              <button className={`flow-tab ${view === 'replay' ? 'active' : ''}`} onClick={() => setView('replay')}>재생</button>
            </div>
          </div>
        )}

        {/* 에러 */}
        {error && <div className="flow-error">{error}</div>}

        {/* 로딩 */}
        {!data && !error && <div className="flow-loading"><div className="spinner sm" />로드 중...</div>}

        {/* 패킷 테이블 */}
        {data && view === 'packets' && data.packets.length > 0 && s && (
          <div className="flow-table-wrap">
            <table className="flow-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>상대 시각</th>
                  <th>방향</th>
                  <th>플래그</th>
                  <th>Seq</th>
                  <th>Ack</th>
                  <th>Length</th>
                  <th>Payload</th>
                </tr>
              </thead>
              <tbody>
                {data.packets.map((p, i) => (
                  <PacketRow key={i} pkt={p} idx={i} base={`${s.dst_ip}:${s.dst_port}`} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* 세션 재생 */}
        {data && view === 'replay' && (
          <ReplayView packets={data.packets} />
        )}

        {data && data.packets.length === 0 && (
          <div className="flow-no-packets">
            패킷 데이터 없음 (pcap 이외 포맷은 패킷 뷰어를 지원하지 않습니다)
          </div>
        )}
      </div>
    </div>
  )
}
