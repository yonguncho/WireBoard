import { useMemo, useState } from 'react'
import type { SessionHealth } from '../api'

interface Node { id: string; x: number; y: number; isInternal: boolean; sessionCount: number }
interface Edge {
  src: string; dst: string
  count: number
  bytes: number
  hasRst: boolean
  protocols: Set<string>
}

interface TooltipState {
  x: number; y: number
  src: string; dst: string
  count: number
  bytes: number
  protocols: string
}

interface Props { sessions: SessionHealth[] }

const MAX_NODES = 30
const W = 720
const H = 420
const R = Math.min(W, H) / 2 - 50

function isPrivateIp(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|fe80:|::1)/.test(ip)
}

function fmtBytes(b: number): string {
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

export function FlowGraph({ sessions }: Props) {
  const [tooltip, setTooltip] = useState<TooltipState | null>(null)

  const { nodes, edges, truncated } = useMemo(() => {
    const nodeSet = new Set<string>()
    const ipSessions = new Map<string, number>()
    const edgeMap = new Map<string, Edge>()

    for (const s of sessions) {
      nodeSet.add(s.src_ip)
      nodeSet.add(s.dst_ip)
      ipSessions.set(s.src_ip, (ipSessions.get(s.src_ip) ?? 0) + 1)
      ipSessions.set(s.dst_ip, (ipSessions.get(s.dst_ip) ?? 0) + 1)

      const key = [s.src_ip, s.dst_ip].sort().join('→')
      const existing = edgeMap.get(key)
      if (existing) {
        existing.count++
        existing.bytes += s.bytes_sent + s.bytes_recv
        if (s.rst) existing.hasRst = true
        existing.protocols.add(s.protocol)
      } else {
        edgeMap.set(key, {
          src: s.src_ip, dst: s.dst_ip,
          count: 1,
          bytes: s.bytes_sent + s.bytes_recv,
          hasRst: s.rst ?? false,
          protocols: new Set([s.protocol]),
        })
      }
    }

    const allIps = [...nodeSet]
    const truncated = Math.max(0, allIps.length - MAX_NODES)
    // 세션 수 많은 순으로 상위 MAX_NODES만 표시
    const visible = allIps
      .sort((a, b) => (ipSessions.get(b) ?? 0) - (ipSessions.get(a) ?? 0))
      .slice(0, MAX_NODES)
    const visibleSet = new Set(visible)

    const nodes: Node[] = visible.map((ip, i) => {
      const angle = (2 * Math.PI * i) / visible.length - Math.PI / 2
      return {
        id: ip,
        x: W / 2 + R * Math.cos(angle),
        y: H / 2 + R * Math.sin(angle),
        isInternal: isPrivateIp(ip),
        sessionCount: ipSessions.get(ip) ?? 0,
      }
    })

    const edges = [...edgeMap.values()].filter(
      e => visibleSet.has(e.src) && visibleSet.has(e.dst)
    )

    return { nodes, edges, truncated }
  }, [sessions])

  if (!nodes.length) return <div className="fg-empty">표시할 통신 흐름 없음</div>

  const nodeMap = new Map(nodes.map(n => [n.id, n]))

  return (
    <div className="fg-wrap">
      <div className="fg-title">
        통신 흐름 그래프
        {truncated > 0 && <span className="fg-truncated"> (상위 {MAX_NODES}개 IP — {truncated}개 생략)</span>}
      </div>
      <svg className="fg-svg" viewBox={`0 0 ${W} ${H}`}>
        {edges.map((e, i) => {
          const a = nodeMap.get(e.src)
          const b = nodeMap.get(e.dst)
          if (!a || !b) return null
          const isUdp = e.protocols.has('UDP') && !e.protocols.has('TCP')
          const stroke = e.hasRst ? '#ef4444' : '#2d4a6e'
          const width = Math.min(5, 1 + Math.log10(1 + e.bytes / 1e3))
          return (
            <line
              key={i}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={stroke}
              strokeWidth={width}
              strokeDasharray={isUdp ? '5 4' : undefined}
              opacity={0.75}
              style={{ cursor: 'pointer' }}
              onMouseEnter={ev => {
                const rect = (ev.target as SVGLineElement).ownerSVGElement?.getBoundingClientRect()
                setTooltip({
                  x: ev.clientX - (rect?.left ?? 0),
                  y: ev.clientY - (rect?.top ?? 0),
                  src: e.src, dst: e.dst,
                  count: e.count,
                  bytes: e.bytes,
                  protocols: [...e.protocols].join(', '),
                })
              }}
              onMouseLeave={() => setTooltip(null)}
            />
          )
        })}
        {nodes.map(n => (
          <g key={n.id}>
            <circle
              cx={n.x} cy={n.y}
              r={Math.min(14, 6 + Math.log2(1 + n.sessionCount))}
              fill={n.isInternal ? '#22c55e' : '#a78bfa'}
              stroke={n.isInternal ? '#2d6a4f' : '#6b21a8'}
              strokeWidth={1.5}
            />
            <text
              x={n.x} y={n.y - 16}
              textAnchor="middle"
              fontSize={9}
              fill="currentColor"
              fontFamily="monospace"
            >
              {n.id}
            </text>
          </g>
        ))}
      </svg>
      {tooltip && (
        <div className="fg-tooltip" style={{ left: tooltip.x + 12, top: tooltip.y + 12 }}>
          <div className="fg-tt-pair">{tooltip.src} ↔ {tooltip.dst}</div>
          <div>{tooltip.count}개 세션 · {fmtBytes(tooltip.bytes)}</div>
          <div>{tooltip.protocols}</div>
        </div>
      )}
      <div className="fg-legend">
        <span className="fg-legend-item"><span className="fg-dot fg-dot-int" /> 내부 IP</span>
        <span className="fg-legend-item"><span className="fg-dot fg-dot-ext" /> 외부 IP</span>
        <span className="fg-legend-item"><span className="fg-line fg-line-tcp" /> TCP</span>
        <span className="fg-legend-item"><span className="fg-line fg-line-udp" /> UDP</span>
        <span className="fg-legend-item"><span className="fg-line fg-line-rst" /> RST 포함</span>
      </div>
    </div>
  )
}
