import { useState, useCallback, useEffect } from 'react'
import { uploadPcap, analyzePcap, getPanels, filterSessions, getSummary, exportJson, exportPdf, exportIoc } from './api'
import type { PanelData, SummaryData } from './api'
import { NarrativeSummary } from './panels/NarrativeSummary'
import { AttackTimeline } from './panels/AttackTimeline'
import { DefensePanel } from './panels/DefensePanel'
import { FlowViewer } from './panels/FlowViewer'
import { PacketList } from './panels/PacketList'
import { ComparePanel } from './panels/ComparePanel'
import { GeoIpPanel } from './panels/GeoIpPanel'
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
import { YaraPanel } from './panels/YaraPanel'
import { NetworkHealthPanel } from './panels/NetworkHealthPanel'
import './App.css'

const ALLOWED = /\.(pcap|pcapng|cap|har|log|txt|tcpdump)$/i

type Tab = 'analysis' | 'traffic' | 'protocol' | 'packets' | 'health' | 'compare' | 'geoip' | 'yara'

interface UploadMeta {
  uploadId: string
  filename: string
  sessionCount: number
  sourceType: string
}

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

export default function App() {
  const [meta, setMeta] = useState<UploadMeta | null>(null)
  const [panels, setPanels] = useState<PanelData | null>(null)
  const [summary, setSummary] = useState<SummaryData | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadingMsg, setLoadingMsg] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [filterQuery, setFilterQuery] = useState('')
  const [filterResult, setFilterResult] = useState<{ filter_expr: string; matched_count: number } | null>(null)
  const [dragging, setDragging] = useState(false)
  const [targetIp, setTargetIp] = useState('')
  const [tab, setTab] = useState<Tab>('analysis')
  const [flowSessionId, setFlowSessionId] = useState<string | null>(null)
  const [theme, setTheme] = useState<'dark' | 'light'>(() =>
    (localStorage.getItem('wb-theme') as 'dark' | 'light') ?? 'dark'
  )

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('wb-theme', theme)
  }, [theme])

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
    setSummary(null)
    setFilterResult(null)
    try {
      const up = await uploadPcap(file)
      if (up.parse_warnings?.length) console.warn('Parse warnings:', up.parse_warnings)

      setLoadingMsg(`${up.session_count.toLocaleString()}개 세션 공격 탐지 중...`)
      await analyzePcap(up.upload_id, targetIp.trim() || undefined)

      setLoadingMsg('분석 요약 생성 중...')
      const [data, sum] = await Promise.all([
        getPanels(up.upload_id),
        getSummary(up.upload_id),
      ])

      setMeta({ uploadId: up.upload_id, filename: file.name, sessionCount: up.session_count, sourceType: up.source_type })
      setPanels(data)
      setSummary(sum)
      setTab('analysis')
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
      {/* Header */}
      <header className="header">
        <div className="header-brand">
          <IconWave />
          <span className="header-logo">WireBoard</span>
          <span className="header-ver">v5.5.0</span>
        </div>
        {meta && (
          <div className="header-file-info">
            <span className="chip chip-file">{meta.filename}</span>
            <span className="chip chip-sessions">{meta.sessionCount.toLocaleString()} 세션</span>
            <span className="chip chip-src">{meta.sourceType.toUpperCase()}</span>
            <button className="btn-export" title="JSON 내보내기" onClick={() => exportJson(meta.uploadId).catch(e => setError(e.message))}>
              ↓ JSON
            </button>
            <button className="btn-export" title="PDF 리포트" onClick={() => exportPdf(meta.uploadId).catch(e => setError(e.message))}>
              ↓ PDF
            </button>
            <button className="btn-export" title="IOC 내보내기 (CSV)" onClick={async () => {
              try {
                const blob = await exportIoc(meta.uploadId)
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = `ioc_${meta.uploadId.slice(0, 8)}.csv`
                a.click()
                URL.revokeObjectURL(url)
              } catch (e) {
                setError(e instanceof Error ? e.message : String(e))
              }
            }}>
              ↓ IOC
            </button>
            <button className="btn-new-file" onClick={() => { setMeta(null); setPanels(null); setSummary(null); setError(null) }}>
              새 파일
            </button>
          </div>
        )}
        {!meta && <span className="header-tagline">PCAP 공격/방어 분석 도구</span>}
        <button
          className="theme-toggle"
          onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
        >
          {theme === 'dark' ? '☀ 라이트' : '◑ 다크'}
        </button>
      </header>

      {/* Upload Page */}
      {!meta && !loading && (
        <main className="upload-page">
          <div className="upload-hero">
            <h1 className="upload-hero-title">네트워크 공격을 한눈에 분석하세요</h1>
            <p className="upload-hero-sub">pcap 파일을 업로드하면 공격 유형, 출발지, 방어 권고를 자동으로 분석합니다</p>
          </div>
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
              <div className="drop-icon-wrap"><IconUpload /></div>
              <p className="drop-primary">파일을 드래그하거나 클릭하여 업로드</p>
              <p className="drop-hint">.pcap &nbsp;·&nbsp; .pcapng &nbsp;·&nbsp; .har &nbsp;·&nbsp; .log &nbsp;·&nbsp; 최대 50 MB</p>
            </label>
          </div>
          <div className="target-ip-row">
            <label htmlFor="target-ip" className="ip-label">분석 대상 IP <span className="optional">(선택 — 비우면 자동 감지)</span></label>
            <input id="target-ip" className="ip-input" placeholder="예: 192.168.1.10" value={targetIp} onChange={(e) => setTargetIp(e.target.value)} />
          </div>
          {error && (
            <div className="error-banner">
              <span className="error-icon">⚠</span>
              <pre className="error-text">{error}</pre>
            </div>
          )}
        </main>
      )}

      {/* Loading */}
      {loading && (
        <div className="loading-page">
          <div className="spinner" />
          <p className="loading-msg">{loadingMsg}</p>
        </div>
      )}

      {/* Flow Viewer 오버레이 */}
      {flowSessionId && meta && (
        <FlowViewer
          uploadId={meta.uploadId}
          sessionId={flowSessionId}
          onClose={() => setFlowSessionId(null)}
        />
      )}

      {/* Dashboard */}
      {panels && meta && summary && (
        <div className="dashboard">

          {/* Narrative Summary — 항상 최상단 */}
          <div className="summary-section">
            <NarrativeSummary data={summary} />
          </div>

          {/* Summary Stats Bar */}
          <div className="summary-bar">
            <StatCard label="세션" value={meta.sessionCount.toLocaleString()} />
            <StatCard label="IP" value={panels.panel6_ip_ranking.length.toString()} />
            <StatCard
              label="공격 탐지"
              value={panels.panel10_attacks.length.toString()}
              level={panels.panel10_attacks.length > 0 ? 'danger' : 'ok'}
            />
            <StatCard
              label="RST"
              value={panels.panel5_anomalies.rst_count.toLocaleString()}
              level={panels.panel5_anomalies.rst_count > 100 ? 'warn' : 'ok'}
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

          {/* Tab Content */}
          <div className="panel-grid">

            {/* 분석 탭 — 공격 타임라인 + 방어 권고 + 공격 상세 */}
            {tab === 'analysis' && (
              <>
                <div className="attack-defense-row">
                  <PCard title="공격 타임라인">
                    <AttackTimeline events={summary.attack_timeline} />
                  </PCard>
                  <DefensePanel
                    recommendations={summary.recommendations}
                    attackerIps={summary.attacker_ips}
                    victimIps={summary.victim_ips}
                  />
                </div>
                <PCard title="공격 탐지 상세" wide>
                  <Panel10Attacks data={panels.panel10_attacks} />
                </PCard>
                <PCard title="이상 지표">
                  <Panel5Anomalies data={panels.panel5_anomalies} />
                </PCard>
                <PCard title="TLS 세션">
                  <Panel7Tls data={panels.panel7_tls} />
                </PCard>
              </>
            )}

            {/* 트래픽 탭 */}
            {tab === 'traffic' && (
              <>
                <PCard title="트래픽 타임라인" wide>
                  <Panel3Timeline data={panels.panel3_timeline} uploadId={meta.uploadId} />
                </PCard>
                <PCard title="IP 순위 (클릭 → 드릴다운)">
                  <Panel6IpRanking
                    data={panels.panel6_ip_ranking}
                    uploadId={meta.uploadId}
                    onFlowSelect={setFlowSessionId}
                  />
                </PCard>
                <PCard title="IP 트래픽 차트">
                  <Panel1Ip data={panels.panel1_ip} />
                </PCard>
                <PCard title="상위 대화 (클릭 → 세션)">
                  <Panel9Conversations
                    data={panels.panel9_conversations}
                    uploadId={meta.uploadId}
                    onFlowSelect={setFlowSessionId}
                  />
                </PCard>
              </>
            )}

            {/* 프로토콜 탭 */}
            {tab === 'protocol' && (
              <>
                <PCard title="프로토콜 분포">
                  <Panel2Protocol data={panels.panel2_protocol} />
                </PCard>
                <PCard title="HTTP 상태 코드">
                  <Panel4Http data={panels.panel4_http} />
                </PCard>
                <PCard title="DNS 쿼리">
                  <Panel8Dns data={panels.panel8_dns} />
                </PCard>
                <PCard title="TLS 세션">
                  <Panel7Tls data={panels.panel7_tls} />
                </PCard>
              </>
            )}

            {/* 패킷 뷰어 탭 */}
            {tab === 'packets' && (
              <div className="panel-card wide">
                <div className="panel-card-title">Wireshark 스타일 패킷 뷰어</div>
                <div className="panel-card-body">
                  <PacketList
                    uploadId={meta.uploadId}
                    onFlowSelect={setFlowSessionId}
                  />
                </div>
              </div>
            )}

            {/* 통신 상태 진단 탭 */}
            {tab === 'health' && (
              <div className="panel-card wide">
                <div className="panel-card-title">통신 상태 진단 (RTT · 재전송 · 핸드셰이크)</div>
                <div className="panel-card-body">
                  <NetworkHealthPanel uploadId={meta.uploadId} />
                </div>
              </div>
            )}

            {/* 비교 탭 */}
            {tab === 'compare' && (
              <div className="panel-card wide">
                <div className="panel-card-title">캡처 비교 분석</div>
                <div className="panel-card-body">
                  <ComparePanel
                    baseUploadId={meta.uploadId}
                    baseFilename={meta.filename}
                  />
                </div>
              </div>
            )}

            {/* GeoIP 탭 */}
            {tab === 'geoip' && (
              <div className="panel-card wide">
                <div className="panel-card-title">공격자 IP 지리 분포</div>
                <div className="panel-card-body">
                  <GeoIpPanel uploadId={meta.uploadId} />
                </div>
              </div>
            )}

            {/* YARA 탭 */}
            {tab === 'yara' && (
              <div className="panel-card wide">
                <div className="panel-card-title">YARA 서명 탐지</div>
                <div className="panel-card-body">
                  <YaraPanel uploadId={meta.uploadId} />
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

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

const TAB_META: Record<Tab, { label: string; icon: string }> = {
  analysis: { label: '공격 분석', icon: '⚡' },
  traffic:  { label: '트래픽',   icon: '↗' },
  protocol: { label: '프로토콜', icon: '◎' },
  packets:  { label: '패킷 뷰어', icon: '📦' },
  health:   { label: '통신 진단', icon: '🩺' },
  compare:  { label: '비교 분석', icon: '⇄' },
  geoip:    { label: 'GeoIP',    icon: '🌏' },
  yara:     { label: 'YARA',     icon: '🔍' },
}
