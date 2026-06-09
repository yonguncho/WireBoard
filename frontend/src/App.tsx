import { useState, useCallback, useEffect } from 'react'
import { uploadPcap, analyzePcap, getPanels, getSummary, exportJson, exportPdf, exportIoc } from './api'
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
import { SessionExplorer } from './panels/SessionExplorer'
import './App.css'

const ALLOWED = /\.(pcap|pcapng|cap|har|log|txt|tcpdump)$/i

type Layer = 'overview' | 'investigate' | 'output'
type InvTab = 'sessions' | 'traffic' | 'protocol' | 'health' | 'geoip' | 'yara'

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

// ── Protocol Hierarchy ────────────────────────────────────────────────────────

function ProtocolHierarchy({ data }: { data: PanelData }) {
  const dist = data.panel2_protocol.distribution
  const ports = data.panel2_protocol.top_ports
  const total = Object.values(dist).reduce((a, b) => a + b, 0)
  if (total === 0) return <div className="ph-empty">프로토콜 데이터 없음</div>

  const sorted = Object.entries(dist).sort(([, a], [, b]) => b - a)
  const maxCount = sorted[0]?.[1] ?? 1

  return (
    <div className="ph-tree">
      <div className="ph-section-title">프로토콜 분포</div>
      {sorted.map(([proto, count]) => {
        const pct = ((count / total) * 100).toFixed(1)
        return (
          <div key={proto} className="ph-row">
            <span className="ph-proto">{proto}</span>
            <div className="ph-bar-wrap">
              <div className="ph-bar" style={{ width: `${(count / maxCount) * 100}%` }} />
            </div>
            <span className="ph-count">{count.toLocaleString()}</span>
            <span className="ph-pct">{pct}%</span>
          </div>
        )
      })}
      {ports.length > 0 && (
        <>
          <div className="ph-section-title" style={{ marginTop: 16 }}>상위 포트</div>
          {ports.slice(0, 10).map(p => (
            <div key={p.port} className="ph-row ph-port-row">
              <span className="ph-proto">:{p.port}</span>
              <div className="ph-bar-wrap">
                <div className="ph-bar ph-bar-port" style={{ width: `${(p.count / (ports[0]?.count ?? 1)) * 100}%` }} />
              </div>
              <span className="ph-count">{p.count.toLocaleString()}</span>
            </div>
          ))}
        </>
      )}
    </div>
  )
}

// ── Risk Badge ────────────────────────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const cfg: Record<string, { color: string; label: string }> = {
    HIGH:   { color: '#ef4444', label: '고위험' },
    MEDIUM: { color: '#f59e0b', label: '중위험' },
    LOW:    { color: '#22c55e', label: '저위험' },
    CLEAN:  { color: '#3b82f6', label: '정상' },
  }
  const c = cfg[level] ?? cfg.CLEAN
  return (
    <div className="risk-badge-wrap">
      <span className="risk-badge" style={{ background: c.color }}>{c.label}</span>
    </div>
  )
}

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [meta, setMeta] = useState<UploadMeta | null>(null)
  const [panels, setPanels] = useState<PanelData | null>(null)
  const [summary, setSummary] = useState<SummaryData | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadingMsg, setLoadingMsg] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [targetIp, setTargetIp] = useState('')
  const [layer, setLayer] = useState<Layer>('overview')
  const [invTab, setInvTab] = useState<InvTab>('sessions')
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
      setLayer('overview')
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

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-brand">
          <IconWave />
          <span className="header-logo">WireBoard</span>
          <span className="header-ver">v6.0</span>
        </div>
        {meta && (
          <div className="header-file-info">
            <span className="chip chip-file">{meta.filename}</span>
            <span className="chip chip-sessions">{meta.sessionCount.toLocaleString()} 세션</span>
            <span className="chip chip-src">{meta.sourceType.toUpperCase()}</span>
            <button className="btn-export" title="JSON 내보내기" onClick={() => exportJson(meta.uploadId).catch(e => setError(e.message))}>↓ JSON</button>
            <button className="btn-export" title="PDF 리포트" onClick={() => exportPdf(meta.uploadId).catch(e => setError(e.message))}>↓ PDF</button>
            <button className="btn-export" title="IOC 내보내기 (CSV)" onClick={async () => {
              try {
                const blob = await exportIoc(meta.uploadId)
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url; a.download = `ioc_${meta.uploadId.slice(0, 8)}.csv`; a.click()
                URL.revokeObjectURL(url)
              } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
            }}>↓ IOC</button>
            <button className="btn-new-file" onClick={() => { setMeta(null); setPanels(null); setSummary(null); setError(null) }}>새 파일</button>
          </div>
        )}
        {!meta && <span className="header-tagline">PCAP 공격/방어 분석 도구</span>}
        <button className="theme-toggle" onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}>
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
            <input type="file" id="pcap-input" accept=".pcap,.pcapng,.cap,.har,.log,.txt,.tcpdump"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f) }} hidden />
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
          {error && (
            <div className="error-banner inline">
              <span className="error-icon">⚠</span>
              <pre className="error-text">{error}</pre>
            </div>
          )}

          {/* Layer Navigation */}
          <nav className="layer-nav">
            <button className={`layer-btn${layer === 'overview' ? ' active' : ''}`} onClick={() => setLayer('overview')}>
              <span>▤</span> 현황
            </button>
            <button className={`layer-btn${layer === 'investigate' ? ' active' : ''}`} onClick={() => setLayer('investigate')}>
              <span>🔬</span> 조사
            </button>
            <button className={`layer-btn${layer === 'output' ? ' active' : ''}`} onClick={() => setLayer('output')}>
              <span>⇄</span> 출력
            </button>
          </nav>

          {/* Investigate Sub-nav */}
          {layer === 'investigate' && (
            <nav className="sub-nav">
              {([ ['sessions','세션/패킷'], ['traffic','트래픽'], ['protocol','프로토콜'], ['health','통신진단'], ['geoip','GeoIP'], ['yara','YARA'] ] as [InvTab, string][]).map(([key, label]) => (
                <button key={key} className={`sub-btn${invTab === key ? ' active' : ''}`} onClick={() => setInvTab(key)}>
                  {label}
                </button>
              ))}
            </nav>
          )}

          {/* Content */}
          <div className="panel-grid">

            {/* ── 현황 레이어 ─────────────────────────────────────────────── */}
            {layer === 'overview' && (
              <>
                <div className="overview-header-row">
                  <RiskBadge level={summary.risk_level} />
                  <div className="overview-quick-stats">
                    <span className="qs-item"><span className="qs-num">{meta.sessionCount.toLocaleString()}</span><span className="qs-lbl">세션</span></span>
                    <span className="qs-item"><span className="qs-num" style={{ color: '#ef4444' }}>{panels.panel10_attacks.length}</span><span className="qs-lbl">공격 탐지</span></span>
                    <span className="qs-item"><span className="qs-num" style={{ color: '#f59e0b' }}>{panels.panel5_anomalies.rst_count}</span><span className="qs-lbl">RST</span></span>
                    <span className="qs-item"><span className="qs-num" style={{ color: '#f59e0b' }}>{panels.panel5_anomalies.retransmit_count}</span><span className="qs-lbl">재전송</span></span>
                  </div>
                </div>

                <div className="summary-section">
                  <NarrativeSummary data={summary} />
                </div>

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

                <div className="overview-bottom-row">
                  <PCard title="이상 지표">
                    <Panel5Anomalies data={panels.panel5_anomalies} />
                  </PCard>
                  <PCard title="IP 트래픽">
                    <Panel1Ip data={panels.panel1_ip} />
                  </PCard>
                  <PCard title="프로토콜 분포">
                    <Panel2Protocol data={panels.panel2_protocol} />
                  </PCard>
                </div>
              </>
            )}

            {/* ── 조사 레이어 ─────────────────────────────────────────────── */}
            {layer === 'investigate' && invTab === 'sessions' && (
              <div className="panel-card wide" style={{ padding: 0, overflow: 'hidden' }}>
                <SessionExplorer
                  uploadId={meta.uploadId}
                  panels={panels}
                  sessionCount={meta.sessionCount}
                  onFlowSelect={setFlowSessionId}
                />
              </div>
            )}

            {layer === 'investigate' && invTab === 'sessions' && (
              <div className="panel-card wide">
                <div className="panel-card-title">Wireshark 스타일 패킷 뷰어</div>
                <div className="panel-card-body">
                  <PacketList uploadId={meta.uploadId} onFlowSelect={setFlowSessionId} />
                </div>
              </div>
            )}

            {layer === 'investigate' && invTab === 'traffic' && (
              <>
                <PCard title="트래픽 타임라인" wide>
                  <Panel3Timeline data={panels.panel3_timeline} uploadId={meta.uploadId} />
                </PCard>
                <PCard title="IP 순위 (클릭 → 드릴다운)">
                  <Panel6IpRanking data={panels.panel6_ip_ranking} uploadId={meta.uploadId} onFlowSelect={setFlowSessionId} />
                </PCard>
                <PCard title="상위 대화 (클릭 → 세션)">
                  <Panel9Conversations data={panels.panel9_conversations} uploadId={meta.uploadId} onFlowSelect={setFlowSessionId} />
                </PCard>
              </>
            )}

            {layer === 'investigate' && invTab === 'protocol' && (
              <>
                <PCard title="프로토콜 계층">
                  <ProtocolHierarchy data={panels} />
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

            {layer === 'investigate' && invTab === 'health' && (
              <div className="panel-card wide">
                <div className="panel-card-title">통신 상태 진단 (RTT · 재전송 · 핸드셰이크)</div>
                <div className="panel-card-body">
                  <NetworkHealthPanel uploadId={meta.uploadId} />
                </div>
              </div>
            )}

            {layer === 'investigate' && invTab === 'geoip' && (
              <div className="panel-card wide">
                <div className="panel-card-title">공격자 IP 지리 분포</div>
                <div className="panel-card-body">
                  <GeoIpPanel uploadId={meta.uploadId} />
                </div>
              </div>
            )}

            {layer === 'investigate' && invTab === 'yara' && (
              <div className="panel-card wide">
                <div className="panel-card-title">YARA 서명 탐지</div>
                <div className="panel-card-body">
                  <YaraPanel uploadId={meta.uploadId} />
                </div>
              </div>
            )}

            {/* ── 출력 레이어 ─────────────────────────────────────────────── */}
            {layer === 'output' && (
              <div className="panel-card wide">
                <div className="panel-card-title">캡처 비교 분석</div>
                <div className="panel-card-body">
                  <ComparePanel baseUploadId={meta.uploadId} baseFilename={meta.filename} />
                </div>
              </div>
            )}

          </div>
        </div>
      )}
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
