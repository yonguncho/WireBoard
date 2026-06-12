import { useState, useCallback, useEffect, useRef } from 'react'
import { uploadPcap, analyzePcap, getPanels, getSummary, exportJson, exportPdf, exportIoc } from './api'
import type { PanelData, SummaryData } from './api'
import { subscribeToast } from './toast'
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

interface RecentEntry {
  filename: string
  sessionCount: number
  riskLevel: string
  attackCount: number
  analyzedAt: number
}

const RECENT_KEY = 'wb-recent-files'

function loadRecent(): RecentEntry[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY)
    if (!raw) return []
    const arr = JSON.parse(raw)
    return Array.isArray(arr) ? arr.slice(0, 5) : []
  } catch { return [] }
}

function saveRecent(entry: RecentEntry): RecentEntry[] {
  const list = [entry, ...loadRecent().filter(e => e.filename !== entry.filename)].slice(0, 5)
  try { localStorage.setItem(RECENT_KEY, JSON.stringify(list)) } catch { /* ignore */ }
  return list
}

// ── 단축키 도움말 ─────────────────────────────────────────────────────────────

const SHORTCUTS: [string, string][] = [
  ['Ctrl + K', '커맨드 팔레트 (이동 · 액션 검색)'],
  ['1 / 2 / 3', '현황 · 조사 · 출력 레이어 전환'],
  ['T', '다크 / 라이트 테마 전환'],
  ['N', '새 파일 업로드로 돌아가기'],
  ['?', '단축키 도움말 열기/닫기'],
  ['Esc', '오버레이 · 패킷 뷰어 닫기'],
]

function ShortcutHelp({ onClose }: { onClose: () => void }) {
  return (
    <div className="sc-overlay" onClick={onClose}>
      <div className="sc-modal" onClick={e => e.stopPropagation()}>
        <div className="sc-title">키보드 단축키</div>
        {SHORTCUTS.map(([key, desc]) => (
          <div key={key} className="sc-row">
            <span className="sc-key">{key}</span>
            <span className="sc-desc">{desc}</span>
          </div>
        ))}
        <button className="sc-close" onClick={onClose}>닫기 (Esc)</button>
      </div>
    </div>
  )
}

// ── 커맨드 팔레트 ─────────────────────────────────────────────────────────────

interface CmdItem {
  id: string
  label: string
  section: string
  hint?: string
  keywords?: string
  run: () => void
}

function CommandPalette({ items, onClose }: { items: CmdItem[]; onClose: () => void }) {
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => { inputRef.current?.focus() }, [])

  const needle = q.trim().toLowerCase()
  const filtered = needle
    ? items.filter(it => (it.label + ' ' + (it.keywords ?? '')).toLowerCase().includes(needle))
    : items
  const active = Math.min(idx, Math.max(0, filtered.length - 1))

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { onClose(); return }
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx(i => Math.min(i + 1, filtered.length - 1)); return }
    if (e.key === 'ArrowUp') { e.preventDefault(); setIdx(i => Math.max(i - 1, 0)); return }
    if (e.key === 'Enter' && filtered[active]) {
      onClose()
      filtered[active].run()
    }
  }

  let lastSection = ''
  return (
    <div className="cp-overlay" onClick={onClose}>
      <div className="cp-modal" onClick={e => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="cp-input"
          placeholder="이동하거나 실행할 작업 검색..."
          value={q}
          onChange={e => { setQ(e.target.value); setIdx(0) }}
          onKeyDown={onKey}
        />
        <div className="cp-list">
          {filtered.length === 0 && <div className="cp-empty">일치하는 항목 없음</div>}
          {filtered.map((it, i) => {
            const showSection = it.section !== lastSection
            lastSection = it.section
            return (
              <div key={it.id}>
                {showSection && <div className="cp-section">{it.section}</div>}
                <div
                  className={`cp-item${i === active ? ' cp-active' : ''}`}
                  onMouseEnter={() => setIdx(i)}
                  onClick={() => { onClose(); it.run() }}
                >
                  <span className="cp-label">{it.label}</span>
                  {it.hint && <span className="cp-hint">{it.hint}</span>}
                </div>
              </div>
            )
          })}
        </div>
        <div className="cp-footer">
          <span><kbd>↑↓</kbd> 이동</span>
          <span><kbd>Enter</kbd> 실행</span>
          <span><kbd>Esc</kbd> 닫기</span>
        </div>
      </div>
    </div>
  )
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
  const [toast, setToast] = useState<string | null>(null)
  const [showHelp, setShowHelp] = useState(false)
  const [showPalette, setShowPalette] = useState(false)
  const [loadStep, setLoadStep] = useState(0)
  const [recent, setRecent] = useState<RecentEntry[]>(loadRecent)
  const toastTimer = useRef<number | undefined>(undefined)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('wb-theme', theme)
  }, [theme])

  useEffect(() => subscribeToast(msg => {
    setToast(msg)
    window.clearTimeout(toastTimer.current)
    toastTimer.current = window.setTimeout(() => setToast(null), 1800)
  }), [])

  const handleFile = useCallback(async (file: File) => {
    if (!ALLOWED.test(file.name)) {
      setError('지원 포맷: .pcap · .pcapng · .cap · .har · .log · .txt · .tcpdump')
      return
    }
    setLoading(true)
    setLoadStep(0)
    setLoadingMsg('파일 업로드 중...')
    setError(null)
    setPanels(null)
    setMeta(null)
    setSummary(null)
    try {
      const up = await uploadPcap(file)
      if (up.parse_warnings?.length) console.warn('Parse warnings:', up.parse_warnings)

      setLoadStep(1)
      setLoadingMsg(`${up.session_count.toLocaleString()}개 세션 공격 탐지 중...`)
      await analyzePcap(up.upload_id, targetIp.trim() || undefined)

      setLoadStep(2)
      setLoadingMsg('분석 요약 생성 중...')
      const [data, sum] = await Promise.all([
        getPanels(up.upload_id),
        getSummary(up.upload_id),
      ])

      setMeta({ uploadId: up.upload_id, filename: file.name, sessionCount: up.session_count, sourceType: up.source_type })
      setPanels(data)
      setSummary(sum)
      setLayer('overview')
      setRecent(saveRecent({
        filename: file.name,
        sessionCount: up.session_count,
        riskLevel: sum.risk_level,
        attackCount: data.panel10_attacks.length,
        analyzedAt: Date.now(),
      }))
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

  const resetToUpload = useCallback(() => {
    setMeta(null); setPanels(null); setSummary(null); setError(null)
  }, [])

  // 전역 키보드 단축키 — 입력 필드 포커스 중에는 비활성 (Ctrl+K 제외)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault()
        setShowPalette(v => !v)
        return
      }
      const tag = (e.target as HTMLElement)?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (e.ctrlKey || e.metaKey || e.altKey) return

      if (e.key === 'Escape') {
        if (showPalette) { setShowPalette(false); return }
        if (showHelp) { setShowHelp(false); return }
        if (flowSessionId) { setFlowSessionId(null); return }
        return
      }
      if (e.key === '?') { setShowHelp(v => !v); return }
      if (e.key === 't' || e.key === 'T') { setTheme(t => t === 'dark' ? 'light' : 'dark'); return }

      if (!meta) return
      if (e.key === '1') setLayer('overview')
      else if (e.key === '2') setLayer('investigate')
      else if (e.key === '3') setLayer('output')
      else if (e.key === 'n' || e.key === 'N') resetToUpload()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [meta, showHelp, showPalette, flowSessionId, resetToUpload])

  const paletteItems: CmdItem[] = [
    ...(meta ? [
      { id: 'go-overview', label: '현황 레이어', section: '이동', hint: '1', keywords: 'overview layer dashboard', run: () => setLayer('overview') },
      { id: 'go-sessions', label: '조사 › 세션/패킷', section: '이동', hint: '2', keywords: 'investigate session packet wireshark', run: () => { setLayer('investigate'); setInvTab('sessions') } },
      { id: 'go-traffic', label: '조사 › 트래픽', section: '이동', keywords: 'traffic timeline ip ranking conversation', run: () => { setLayer('investigate'); setInvTab('traffic') } },
      { id: 'go-protocol', label: '조사 › 프로토콜', section: '이동', keywords: 'protocol http dns tls', run: () => { setLayer('investigate'); setInvTab('protocol') } },
      { id: 'go-health', label: '조사 › 통신진단', section: '이동', keywords: 'health rtt retransmit handshake diagnose', run: () => { setLayer('investigate'); setInvTab('health') } },
      { id: 'go-geoip', label: '조사 › GeoIP', section: '이동', keywords: 'geoip geo location country', run: () => { setLayer('investigate'); setInvTab('geoip') } },
      { id: 'go-yara', label: '조사 › YARA', section: '이동', keywords: 'yara signature malware', run: () => { setLayer('investigate'); setInvTab('yara') } },
      { id: 'go-output', label: '출력 › 캡처 비교', section: '이동', hint: '3', keywords: 'output compare diff', run: () => setLayer('output') },
      { id: 'export-json', label: 'JSON 내보내기', section: '액션', keywords: 'export json download', run: () => exportJson(meta.uploadId).catch(e => setError(e.message)) },
      { id: 'export-pdf', label: 'PDF 리포트 내보내기', section: '액션', keywords: 'export pdf report download', run: () => exportPdf(meta.uploadId).catch(e => setError(e.message)) },
      { id: 'new-file', label: '새 파일 업로드', section: '액션', hint: 'N', keywords: 'new upload reset', run: resetToUpload },
    ] : []),
    { id: 'toggle-theme', label: `${theme === 'dark' ? '라이트' : '다크'} 테마로 전환`, section: '설정', hint: 'T', keywords: 'theme dark light toggle', run: () => setTheme(t => t === 'dark' ? 'light' : 'dark') },
    { id: 'show-help', label: '키보드 단축키 도움말', section: '설정', hint: '?', keywords: 'shortcut help keyboard', run: () => setShowHelp(true) },
  ]

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
            <button className="btn-new-file" title="단축키 N" onClick={resetToUpload}>새 파일</button>
          </div>
        )}
        {!meta && <span className="header-tagline">PCAP 공격/방어 분석 도구</span>}
        <button className="theme-toggle" title="단축키 ?" onClick={() => setShowHelp(v => !v)}>⌨ 단축키</button>
        <button className="theme-toggle" title="단축키 T" onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}>
          {theme === 'dark' ? '☀ 라이트' : '◑ 다크'}
        </button>
      </header>

      {/* 전역 토스트 */}
      {toast && <div className="toast">{toast}</div>}

      {/* 단축키 도움말 */}
      {showHelp && <ShortcutHelp onClose={() => setShowHelp(false)} />}

      {/* 커맨드 팔레트 */}
      {showPalette && <CommandPalette items={paletteItems} onClose={() => setShowPalette(false)} />}

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
          {recent.length > 0 && (
            <div className="recent-files">
              <div className="recent-title">최근 분석</div>
              {recent.map(r => (
                <div key={r.filename + r.analyzedAt} className="recent-row">
                  <span className="recent-name mono">{r.filename}</span>
                  <span className="recent-meta">{r.sessionCount.toLocaleString()} 세션</span>
                  <span className={`recent-risk risk-${r.riskLevel.toLowerCase()}`}>
                    {r.riskLevel}{r.attackCount > 0 ? ` · 공격 ${r.attackCount}` : ''}
                  </span>
                  <span className="recent-time">{new Date(r.analyzedAt).toLocaleString('ko-KR', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
                </div>
              ))}
            </div>
          )}
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
          <div className="load-steps">
            {['업로드', '공격 탐지', '요약 생성'].map((label, i) => (
              <div key={label} className={`load-step${i < loadStep ? ' done' : i === loadStep ? ' active' : ''}`}>
                <span className="load-step-dot">{i < loadStep ? '✓' : i + 1}</span>
                <span className="load-step-label">{label}</span>
                {i < 2 && <span className="load-step-line" />}
              </div>
            ))}
          </div>
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
              <span>▤</span> 현황 <kbd className="nav-kbd">1</kbd>
            </button>
            <button className={`layer-btn${layer === 'investigate' ? ' active' : ''}`} onClick={() => setLayer('investigate')}>
              <span>🔬</span> 조사 <kbd className="nav-kbd">2</kbd>
            </button>
            <button className={`layer-btn${layer === 'output' ? ' active' : ''}`} onClick={() => setLayer('output')}>
              <span>⇄</span> 출력 <kbd className="nav-kbd">3</kbd>
            </button>
            <button className="palette-hint" onClick={() => setShowPalette(true)}>
              <kbd className="nav-kbd">Ctrl K</kbd> 빠른 이동
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
                  <div className="stat-strip">
                    <div className="stat-card">
                      <span className="stat-num">{meta.sessionCount.toLocaleString()}</span>
                      <span className="stat-lbl">세션</span>
                    </div>
                    <div className={`stat-card${panels.panel10_attacks.length > 0 ? ' stat-danger' : ''}`}>
                      <span className="stat-num">{panels.panel10_attacks.length}</span>
                      <span className="stat-lbl">공격 탐지</span>
                    </div>
                    <div className={`stat-card${summary.attacker_ips.length > 0 ? ' stat-danger' : ''}`}>
                      <span className="stat-num">{summary.attacker_ips.length}</span>
                      <span className="stat-lbl">공격 IP</span>
                    </div>
                    <div className={`stat-card${panels.panel5_anomalies.rst_count > 0 ? ' stat-warn' : ''}`}>
                      <span className="stat-num">{panels.panel5_anomalies.rst_count.toLocaleString()}</span>
                      <span className="stat-lbl">RST</span>
                    </div>
                    <div className={`stat-card${panels.panel5_anomalies.retransmit_count > 0 ? ' stat-warn' : ''}`}>
                      <span className="stat-num">{panels.panel5_anomalies.retransmit_count.toLocaleString()}</span>
                      <span className="stat-lbl">재전송</span>
                    </div>
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
