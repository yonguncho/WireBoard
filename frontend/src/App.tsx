import { useState, useCallback } from 'react'
import { uploadPcap, analyzePcap, getPanels, filterSessions } from './api'
import type { PanelData } from './api'
import { Panel1Ip } from './panels/Panel1Ip'
import { Panel2Protocol } from './panels/Panel2Protocol'
import { Panel3Timeline } from './panels/Panel3Timeline'
import { Panel4Http } from './panels/Panel4Http'
import { Panel5Anomalies } from './panels/Panel5Anomalies'
import { Panel6IpRanking } from './panels/Panel6IpRanking'
import { Panel7Tls } from './panels/Panel7Tls'
import { Panel8Dns } from './panels/Panel8Dns'
import { Panel9Conversations } from './panels/Panel9Conversations'
import { Panel10Attacks } from './panels/Panel10Attacks'
import './App.css'

const ALLOWED = /\.(pcap|pcapng|cap|har|log|txt|tcpdump)$/i

type Tab = 'overview' | 'traffic' | 'security' | 'protocol'

interface UploadMeta {
  uploadId: string
  filename: string
  sessionCount: number
  sourceType: string
}

// ── Icons ──────────────────────────────────────────────────────────────────
function IconWave() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  )
}

function IconUpload() {
  return (
    <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  )
}

// ── Main App ───────────────────────────────────────────────────────────────
export default function App() {
  const [meta, setMeta] = useState<UploadMeta | null>(null)
  const [panels, setPanels] = useState<PanelData | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadingMsg, setLoadingMsg] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [filterQuery, setFilterQuery] = useState('')
  const [filterResult, setFilterResult] = useState<{ filter_expr: string; matched_count: number } | null>(null)
  const [dragging, setDragging] = useState(false)
  const [targetIp, setTargetIp] = useState('')
  const [tab, setTab] = useState<Tab>('overview')

  const handleFile = useCallback(async (file: File) => {
    if (!ALLOWED.test(file.name)) {
      setError('지원 포맷: .pcap · .pcapng · .cap · .har · .log · .txt · .tcpdump')
      return
    }
    setLoading(true)
    setLoadingMsg('파일 업로드 중...')
    setError(null)
    setPanels(null)
    setMeta(null)
    setFilterResult(null)
    try {
      const up = await uploadPcap(file)
      if (up.parse_warnings?.length) {
        console.warn('Parse warnings:', up.parse_warnings)
      }
      setLoadingMsg(`${up.session_count.toLocaleString()}개 세션 분석 중...`)
      await analyzePcap(up.upload_id, targetIp.trim() || undefined)
      setLoadingMsg('패널 로드 중...')
      const data = await getPanels(up.upload_id)
      setMeta({ uploadId: up.upload_id, filename: file.name, sessionCount: up.session_count, sourceType: up.source_type })
      setPanels(data)
      setTab('overview')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
      setLoadingMsg('')
    }
  }, [targetIp])

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  const runFilter = async () => {
    if (!meta?.uploadId || !filterQuery.trim()) return
    try {
      const r = await filterSessions(meta.uploadId, filterQuery)
      setFilterResult({ filter_expr: r.filter_expr, matched_count: r.matched_count })
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="app">

      {/* ── Header ── */}
      <header className="header">
        <div className="header-brand">
          <IconWave />
          <span className="header-logo">WireBoard</span>
          <span className="header-ver">v5.1</span>
        </div>
        {meta && (
          <div className="header-file-info">
            <span className="chip chip-file">{meta.filename}</span>
            <span className="chip chip-sessions">{meta.sessionCount.toLocaleString()} 세션</span>
            <span className="chip chip-src">{meta.sourceType.toUpperCase()}</span>
            <button className="btn-new-file" onClick={() => { setMeta(null); setPanels(null); setError(null) }}>
              새 파일
            </button>
          </div>
        )}
        {!meta && <span className="header-tagline">PCAP 네트워크 분석 대시보드</span>}
      </header>

      {/* ── Upload Page ── */}
      {!meta && !loading && (
        <main className="upload-page">
          <div
            className={`drop-zone${dragging ? ' dragging' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
          >
            <input
              type="file"
              id="pcap-input"
              accept=".pcap,.pcapng,.cap,.har,.log,.txt,.tcpdump"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f) }}
              hidden
            />
            <label htmlFor="pcap-input" className="drop-label">
              <div className="drop-icon-wrap">
                <IconUpload />
              </div>
              <p className="drop-primary">파일을 드래그하거나 클릭하여 업로드</p>
              <p className="drop-hint">.pcap &nbsp;·&nbsp; .pcapng &nbsp;·&nbsp; .har &nbsp;·&nbsp; .log &nbsp;·&nbsp; .txt &nbsp;·&nbsp; .tcpdump &nbsp;·&nbsp; 최대 50 MB</p>
            </label>
          </div>

          <div className="target-ip-row">
            <label htmlFor="target-ip" className="ip-label">분석 대상 IP <span className="optional">(선택 — 비우면 자동 감지)</span></label>
            <input
              id="target-ip"
              className="ip-input"
              placeholder="예: 192.168.1.10"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
            />
          </div>

          {error && (
            <div className="error-banner">
              <span className="error-icon">⚠</span>
              <pre className="error-text">{error}</pre>
            </div>
          )}
        </main>
      )}

      {/* ── Loading ── */}
      {loading && (
        <div className="loading-page">
          <div className="spinner" />
          <p className="loading-msg">{loadingMsg}</p>
        </div>
      )}

      {/* ── Dashboard ── */}
      {panels && meta && (
        <div className="dashboard">

          {/* Summary Bar */}
          <div className="summary-bar">
            <StatCard label="세션" value={meta.sessionCount.toLocaleString()} />
            <StatCard label="IP 주소" value={countUniqueIps(panels)} />
            <StatCard
              label="공격 탐지"
              value={panels.panel10_attacks.length.toString()}
              level={panels.panel10_attacks.length > 0 ? 'danger' : 'ok'}
            />
            <StatCard
              label="RST 패킷"
              value={panels.panel5_anomalies.rst_count.toLocaleString()}
              level={panels.panel5_anomalies.rst_count > 100 ? 'warn' : 'ok'}
            />
            <StatCard
              label="재전송"
              value={panels.panel5_anomalies.retransmit_count.toLocaleString()}
              level={panels.panel5_anomalies.retransmit_count > 100 ? 'warn' : 'ok'}
            />
            <div className="filter-bar">
              <input
                className="filter-input"
                placeholder='필터: "192.168.1.10 DNS" 또는 "port 443"'
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && runFilter()}
              />
              <button className="filter-btn" onClick={runFilter}>적용</button>
              {filterResult && (
                <span className="filter-result">
                  <code>{filterResult.filter_expr}</code> · <strong>{filterResult.matched_count}</strong>개 매치
                </span>
              )}
            </div>
          </div>

          {error && (
            <div className="error-banner inline">
              <span className="error-icon">⚠</span>
              <pre className="error-text">{error}</pre>
            </div>
          )}

          {/* Tab Nav */}
          <nav className="tab-nav">
            {(Object.entries(TAB_META) as [Tab, { label: string; icon: string }][]).map(([key, { label, icon }]) => (
              <button
                key={key}
                className={`tab-btn${tab === key ? ' active' : ''}`}
                onClick={() => setTab(key)}
              >
                <span className="tab-icon">{icon}</span>
                {label}
              </button>
            ))}
          </nav>

          {/* Panel Grid */}
          <div className="panel-grid">
            {tab === 'overview' && <>
              <PCard title="IP 트래픽 랭킹">
                <Panel1Ip data={panels.panel1_ip} />
              </PCard>
              <PCard title="프로토콜 분포">
                <Panel2Protocol data={panels.panel2_protocol} />
              </PCard>
              <PCard title="이상 지표">
                <Panel5Anomalies data={panels.panel5_anomalies} />
              </PCard>
            </>}

            {tab === 'traffic' && <>
              <PCard title="트래픽 타임라인" wide>
                <Panel3Timeline data={panels.panel3_timeline} uploadId={meta.uploadId} />
              </PCard>
              <PCard title="IP 순위표 (클릭 → 드릴다운)">
                <Panel6IpRanking data={panels.panel6_ip_ranking} uploadId={meta.uploadId} />
              </PCard>
              <PCard title="상위 대화 목록">
                <Panel9Conversations data={panels.panel9_conversations} />
              </PCard>
            </>}

            {tab === 'security' && <>
              <PCard title="공격 탐지 결과" wide>
                <Panel10Attacks data={panels.panel10_attacks} />
              </PCard>
              <PCard title="이상 지표">
                <Panel5Anomalies data={panels.panel5_anomalies} />
              </PCard>
              <PCard title="TLS 세션">
                <Panel7Tls data={panels.panel7_tls} />
              </PCard>
            </>}

            {tab === 'protocol' && <>
              <PCard title="HTTP 상태 코드">
                <Panel4Http data={panels.panel4_http} />
              </PCard>
              <PCard title="DNS 쿼리">
                <Panel8Dns data={panels.panel8_dns} />
              </PCard>
              <PCard title="TLS 세션">
                <Panel7Tls data={panels.panel7_tls} />
              </PCard>
            </>}
          </div>

        </div>
      )}
    </div>
  )
}

// ── Sub-components ─────────────────────────────────────────────────────────

function StatCard({ label, value, level = 'neutral' }: { label: string; value: string; level?: 'ok' | 'warn' | 'danger' | 'neutral' }) {
  return (
    <div className={`stat-card level-${level}`}>
      <div className="stat-val">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

function PCard({ title, children, wide }: { title: string; children: React.ReactNode; wide?: boolean }) {
  return (
    <div className={`panel-card${wide ? ' wide' : ''}`}>
      <div className="panel-card-title">{title}</div>
      <div className="panel-card-body">{children}</div>
    </div>
  )
}

function countUniqueIps(panels: PanelData): string {
  return panels.panel6_ip_ranking.length.toString()
}

const TAB_META: Record<Tab, { label: string; icon: string }> = {
  overview:  { label: '개요',     icon: '◈' },
  traffic:   { label: '트래픽',   icon: '↗' },
  security:  { label: '보안',     icon: '⚡' },
  protocol:  { label: '프로토콜', icon: '◎' },
}
