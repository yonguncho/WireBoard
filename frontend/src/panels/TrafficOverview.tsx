import { useState, useEffect, useCallback } from 'react'
import { getNetworkHealth } from '../api'
import type { PanelData, NetworkHealthData, SessionHealth } from '../api'

interface Props {
  uploadId: string
  panels: PanelData
  sessionCount: number
  onGoTab: (tab: string) => void
  onFlowSelect: (sessionId: string) => void
}

interface StatCard {
  label: string
  value: number
  tone: 'ok' | 'warn' | 'bad'
  tab: string
  hint: string
}

function StatStrip({ cards, onGo }: { cards: StatCard[]; onGo: (tab: string) => void }) {
  return (
    <div className="to-stat-strip">
      {cards.map(c => (
        <button key={c.label} className={`to-stat to-stat-${c.tone}`} title={c.hint} onClick={() => onGo(c.tab)}>
          <span className="to-stat-num">{c.value.toLocaleString()}</span>
          <span className="to-stat-lbl">{c.label}</span>
        </button>
      ))}
    </div>
  )
}

function scoreColor(s: number) {
  return s >= 80 ? '#22c55e' : s >= 50 ? '#f59e0b' : '#ef4444'
}

function ProblemSessions({ sessions, total, onFlowSelect, onSeeAll }: {
  sessions: SessionHealth[]
  total: number
  onFlowSelect: (id: string) => void
  onSeeAll: () => void
}) {
  if (total === 0) {
    return <div className="to-clean">✓ No sessions with connection delays or anomalies detected.</div>
  }
  return (
    <div className="to-table-wrap">
      <table className="to-table">
        <thead>
          <tr>
            <th>Score</th><th>Source</th><th></th><th>Destination</th>
            <th>Proto</th><th>RTT</th><th>Cause</th>
          </tr>
        </thead>
        <tbody>
          {sessions.map(s => (
            <tr key={s.session_id} className="to-row" onClick={() => onFlowSelect(s.session_id)} title="Click to open the session flow">
              <td><span className="to-score-pill" style={{ background: scoreColor(s.score) }}>{s.score}</span></td>
              <td className="mono to-addr">{s.src_ip}:{s.src_port}</td>
              <td className="mono to-arrow">→</td>
              <td className="mono to-addr">{s.dst_ip}:{s.dst_port}</td>
              <td><span className="to-proto">{s.protocol}</span></td>
              <td className="mono">{s.rtt_ms !== null ? `${s.rtt_ms.toFixed(1)} ms` : '—'}</td>
              <td className="to-cause">{s.root_cause}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <button className="to-seeall" onClick={onSeeAll}>
        View all {total} problem session{total === 1 ? '' : 's'} in Investigate →
      </button>
    </div>
  )
}

// 접속한 호스트(도메인) — TLS SNI + DNS 질의 도메인 집계
function HostsContacted({ panels }: { panels: PanelData }) {
  const counts = new Map<string, { tls: number; dns: number }>()
  for (const e of panels.panel7_tls?.entries ?? []) {
    if (!e.sni) continue
    const cur = counts.get(e.sni) ?? { tls: 0, dns: 0 }
    cur.tls += 1
    counts.set(e.sni, cur)
  }
  for (const d of panels.panel8_dns ?? []) {
    if (!d.domain || d.nxdomain) continue
    const cur = counts.get(d.domain) ?? { tls: 0, dns: 0 }
    cur.dns += 1
    counts.set(d.domain, cur)
  }
  const rows = [...counts.entries()]
    .map(([host, c]) => ({ host, ...c, total: c.tls + c.dns }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 12)

  if (rows.length === 0) return <div className="no-data">No host names observed (no DNS/TLS SNI)</div>
  return (
    <table className="mini-table full-width">
      <thead><tr><th>Host / Domain</th><th>HTTPS (SNI)</th><th>DNS</th></tr></thead>
      <tbody>
        {rows.map(r => (
          <tr key={r.host}>
            <td className="mono">{r.host}</td>
            <td>{r.tls > 0 ? r.tls : '—'}</td>
            <td>{r.dns > 0 ? r.dns : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function TrafficOverview({ uploadId, panels, sessionCount, onGoTab, onFlowSelect }: Props) {
  const [health, setHealth] = useState<NetworkHealthData | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setHealth(await getNetworkHealth(uploadId))
    } catch {
      setHealth(null)
    } finally {
      setLoading(false)
    }
  }, [uploadId])

  useEffect(() => { load() }, [load])

  const anomalies = panels.panel5_anomalies
  const noResponse = health?.failure_summary?.no_response ?? 0
  const slowResponse = health?.failure_summary?.slow_response ?? 0

  // 문제 세션: 점수 낮은 순(통신 지연·핸드셰이크 실패·재전송 과다)
  // Overview는 미리보기(top 5)만 — 전체 인터랙티브 목록은 Investigate › Sessions(SessionExplorer)
  const problemAll = (health?.sessions ?? [])
    .filter(s => s.status !== 'Healthy')
    .sort((a, b) => a.score - b.score)
  const problemTop = problemAll.slice(0, 5)

  const cards: StatCard[] = [
    { label: 'Total Sessions', value: health?.total_sessions ?? sessionCount, tone: 'ok', tab: 'sessions', hint: 'All observed TCP/UDP sessions' },
    { label: 'No Response', value: noResponse, tone: noResponse > 0 ? 'bad' : 'ok', tab: 'health', hint: 'SYN sent but no reply (timeout / half-open)' },
    { label: 'Slow Response', value: slowResponse, tone: slowResponse > 0 ? 'warn' : 'ok', tab: 'health', hint: 'High latency / delayed sessions' },
    { label: 'Retransmits', value: anomalies.retransmit_count, tone: anomalies.retransmit_count > 0 ? 'warn' : 'ok', tab: 'health', hint: 'Retransmitted TCP segments (packet loss)' },
    { label: 'Malformed', value: anomalies.malformed_count, tone: anomalies.malformed_count > 0 ? 'warn' : 'ok', tab: 'sessions', hint: 'Malformed / truncated packets' },
    { label: 'RST', value: anomalies.rst_count, tone: anomalies.rst_count > 0 ? 'warn' : 'ok', tab: 'health', hint: 'TCP reset packets (refused / aborted)' },
  ]

  return (
    <div className="to-wrap">
      <StatStrip cards={cards} onGo={onGoTab} />

      <div className="panel-card wide">
        <div className="panel-card-title">
          Top Problem Sessions <span className="to-preview-tag">preview</span>
          {health && <span className="to-overall"> · overall health {health.overall_score}/100</span>}
        </div>
        <div className="panel-card-body">
          {loading ? (
            <div className="to-loading"><div className="spinner sm" /> Diagnosing connection health (RTT · handshake · retransmit)...</div>
          ) : (
            <ProblemSessions
              sessions={problemTop}
              total={problemAll.length}
              onFlowSelect={onFlowSelect}
              onSeeAll={() => onGoTab('sessions')}
            />
          )}
        </div>
      </div>

      <div className="overview-bottom-row">
        <div className="panel-card">
          <div className="panel-card-title">Hosts Contacted (DNS + TLS SNI)</div>
          <div className="panel-card-body"><HostsContacted panels={panels} /></div>
        </div>
      </div>
    </div>
  )
}
