import { useState, useCallback, useEffect, useRef } from 'react'
import { uploadPcap, analyzePcap, getPanels, getSummary, exportJson, exportPdf, exportIoc, downloadConvertedPcap } from './api'
import type { PanelData, SummaryData } from './api'
import { subscribeToast } from './toast'
import { FlowViewer } from './panels/FlowViewer'
import { PacketList } from './panels/PacketList'
import { ComparePanel } from './panels/ComparePanel'
import { GeoIpPanel } from './panels/GeoIpPanel'
import { Panel1Ip } from './panels/Panel1Ip'
import { Panel3Timeline } from './panels/Panel3Timeline'
import { Panel4Http } from './panels/Panel4Http'
import { Panel6IpRanking } from './panels/Panel6IpRanking'
import { Panel7Tls } from './panels/Panel7Tls'
import { Panel8Dns } from './panels/Panel8Dns'
import { Panel9Conversations } from './panels/Panel9Conversations'
import { YaraPanel } from './panels/YaraPanel'
import { NetworkHealthPanel } from './panels/NetworkHealthPanel'
import { SessionExplorer } from './panels/SessionExplorer'
import { HarWaterfall } from './panels/HarWaterfall'
import { TrafficOverview } from './panels/TrafficOverview'
import './App.css'

const ALLOWED = /\.(pcap|pcapng|cap|har|log|txt|tcpdump)$/i

type Layer = 'overview' | 'investigate' | 'output'
type InvTab = 'sessions' | 'traffic' | 'protocol' | 'health' | 'geoip' | 'yara' | 'har'

interface UploadMeta {
  uploadId: string
  filename: string
  sessionCount: number
  sourceType: string
  pcapAvailable: boolean
  convertHint?: string
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

// ── Keyboard shortcut help ─────────────────────────────────────────────────────────────

const SHORTCUTS: [string, string][] = [
  ['Ctrl + K', 'Command palette (search navigation · actions)'],
  ['1 / 2 / 3', 'Switch Overview · Investigate · Output layers'],
  ['T', 'Toggle dark / light theme'],
  ['N', 'Back to new file upload'],
  ['?', 'Open/close shortcut help'],
  ['Esc', 'Close overlay · packet viewer'],
]

function ShortcutHelp({ onClose }: { onClose: () => void }) {
  return (
    <div className="sc-overlay" onClick={onClose}>
      <div className="sc-modal" onClick={e => e.stopPropagation()}>
        <div className="sc-title">Keyboard Shortcuts</div>
        {SHORTCUTS.map(([key, desc]) => (
          <div key={key} className="sc-row">
            <span className="sc-key">{key}</span>
            <span className="sc-desc">{desc}</span>
          </div>
        ))}
        <button className="sc-close" onClick={onClose}>Close (Esc)</button>
      </div>
    </div>
  )
}

// ── Command palette ─────────────────────────────────────────────────────────────

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
          placeholder="Search to navigate or run an action..."
          value={q}
          onChange={e => { setQ(e.target.value); setIdx(0) }}
          onKeyDown={onKey}
        />
        <div className="cp-list">
          {filtered.length === 0 && <div className="cp-empty">No matching items</div>}
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
          <span><kbd>↑↓</kbd> Navigate</span>
          <span><kbd>Enter</kbd> Run</span>
          <span><kbd>Esc</kbd> Close</span>
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

// 잘 알려진 포트 → {애플리케이션 프로토콜명, 전송계층} 매핑
const WELL_KNOWN_PORT: Record<number, { name: string; transport: 'TCP' | 'UDP' }> = {
  80:   { name: 'HTTP',    transport: 'TCP' },
  443:  { name: 'HTTPS / TLS', transport: 'TCP' },
  8080: { name: 'HTTP-alt', transport: 'TCP' },
  8443: { name: 'HTTPS-alt', transport: 'TCP' },
  22:   { name: 'SSH',     transport: 'TCP' },
  21:   { name: 'FTP',     transport: 'TCP' },
  23:   { name: 'Telnet',  transport: 'TCP' },
  25:   { name: 'SMTP',    transport: 'TCP' },
  587:  { name: 'SMTP (submission)', transport: 'TCP' },
  465:  { name: 'SMTPS',   transport: 'TCP' },
  110:  { name: 'POP3',    transport: 'TCP' },
  143:  { name: 'IMAP',    transport: 'TCP' },
  993:  { name: 'IMAPS',   transport: 'TCP' },
  3389: { name: 'RDP',     transport: 'TCP' },
  445:  { name: 'SMB',     transport: 'TCP' },
  139:  { name: 'NetBIOS', transport: 'TCP' },
  3306: { name: 'MySQL',   transport: 'TCP' },
  5432: { name: 'PostgreSQL', transport: 'TCP' },
  6379: { name: 'Redis',   transport: 'TCP' },
  53:   { name: 'DNS',     transport: 'UDP' },
  67:   { name: 'DHCP',    transport: 'UDP' },
  68:   { name: 'DHCP',    transport: 'UDP' },
  123:  { name: 'NTP',     transport: 'UDP' },
  161:  { name: 'SNMP',    transport: 'UDP' },
  137:  { name: 'NetBIOS-NS', transport: 'UDP' },
  138:  { name: 'NetBIOS-DGM', transport: 'UDP' },
  1900: { name: 'SSDP',    transport: 'UDP' },
  5353: { name: 'mDNS',    transport: 'UDP' },
  500:  { name: 'IKE / IPsec', transport: 'UDP' },
  4500: { name: 'IPsec NAT-T', transport: 'UDP' },
}

const TRANSPORT_COLOR: Record<string, string> = {
  TCP: '#63b3ed', UDP: '#68d391', ICMP: '#f6ad55', ICMP6: '#f6ad55', Other: '#a0aec0',
}

function ProtocolHierarchy({ data }: { data: PanelData }) {
  const dist = data.panel2_protocol.distribution
  const ports = data.panel2_protocol.top_ports
  const total = Object.values(dist).reduce((a, b) => a + b, 0)
  if (total === 0) return <div className="ph-empty">No protocol data</div>

  // 전송계층(TCP/UDP/ICMP...) 하위에 애플리케이션 프로토콜(포트)을 중첩
  const transports = Object.entries(dist).sort(([, a], [, b]) => b - a)
  const appsByTransport: Record<string, { label: string; port: number; count: number }[]> = {}
  for (const p of ports) {
    const known = WELL_KNOWN_PORT[p.port]
    const t = known?.transport ?? 'TCP'
    const label = known?.name ?? `Port ${p.port}`
    ;(appsByTransport[t] ??= []).push({ label, port: p.port, count: p.count })
  }
  for (const t of Object.keys(appsByTransport)) {
    appsByTransport[t].sort((a, b) => b.count - a.count)
  }

  const pct = (n: number) => ((n / total) * 100).toFixed(1)

  return (
    <div className="ph-tree">
      <div className="ph-node ph-root">
        <span className="ph-icon">▣</span>
        <span className="ph-name">Frame</span>
        <span className="ph-meta">{total.toLocaleString()} packets · 100%</span>
      </div>
      <div className="ph-node ph-l1">
        <span className="ph-connector" />
        <span className="ph-icon">⬡</span>
        <span className="ph-name">Ethernet · IP</span>
        <span className="ph-meta">{total.toLocaleString()}</span>
      </div>

      {transports.map(([proto, count]) => {
        const apps = appsByTransport[proto] ?? []
        const color = TRANSPORT_COLOR[proto] ?? TRANSPORT_COLOR.Other
        return (
          <div key={proto} className="ph-branch">
            <div className="ph-node ph-l2">
              <span className="ph-connector" />
              <span className="ph-badge" style={{ background: color }}>{proto}</span>
              <div className="ph-bar-wrap">
                <div className="ph-bar" style={{ width: `${(count / total) * 100}%`, background: color }} />
              </div>
              <span className="ph-count">{count.toLocaleString()}</span>
              <span className="ph-pct">{pct(count)}%</span>
            </div>
            {apps.slice(0, 8).map(a => (
              <div key={`${proto}-${a.port}`} className="ph-node ph-l3">
                <span className="ph-connector ph-connector-app" />
                <span className="ph-app-name">{a.label}</span>
                <span className="ph-app-port">:{a.port}</span>
                <span className="ph-count">{a.count.toLocaleString()}</span>
                <span className="ph-pct">{pct(a.count)}%</span>
              </div>
            ))}
          </div>
        )
      })}
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
  const [globalDrag, setGlobalDrag] = useState(false)
  const toastTimer = useRef<number | undefined>(undefined)
  const dragDepth = useRef(0)

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
      setError('Supported formats: .pcap · .pcapng · .cap · .har · .log · .txt · .tcpdump')
      return
    }
    setLoading(true)
    setLoadStep(0)
    setLoadingMsg('Uploading file...')
    setError(null)
    setPanels(null)
    setMeta(null)
    setSummary(null)
    try {
      const up = await uploadPcap(file)
      if (up.parse_warnings?.length) console.warn('Parse warnings:', up.parse_warnings)

      setLoadStep(1)
      setLoadingMsg(`Analyzing patterns across ${up.session_count.toLocaleString()} sessions...`)
      await analyzePcap(up.upload_id, targetIp.trim() || undefined)

      setLoadStep(2)
      setLoadingMsg('Generating analysis summary...')
      const [data, sum] = await Promise.all([
        getPanels(up.upload_id),
        getSummary(up.upload_id),
      ])

      // FortiGate/tcpdump text logs convert to a downloadable .pcap only when they
      // contain a hex packet dump (verbose 6). Explain when conversion wasn't possible.
      const convertHint = (!up.pcap_available && (up.source_type === 'fortigate' || up.source_type === 'tcpdump'))
        ? "This log was parsed for analysis, but it has no hex packet dump, so a .pcap file could not be produced. To enable .pcap conversion & download, re-capture with verbose 6 — e.g. 'diagnose sniffer packet <interface> \"<filter>\" 6 0 l' on FortiGate, or 'tcpdump -XX ...'."
        : undefined
      setMeta({ uploadId: up.upload_id, filename: file.name, sessionCount: up.session_count, sourceType: up.source_type, pcapAvailable: !!up.pcap_available, convertHint })
      setPanels(data)
      setSummary(sum)
      // HAR 입력은 Waterfall 이 가장 유용하므로 해당 뷰를 먼저 보여준다.
      if (up.source_type === 'har') {
        setLayer('investigate')
        setInvTab('har')
      } else {
        setLayer('overview')
      }
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

  // Even in the dashboard state, dropping a file anywhere on screen starts a new analysis
  useEffect(() => {
    if (!meta || loading) return
    const hasFiles = (e: DragEvent) => e.dataTransfer?.types.includes('Files')
    const onDragEnter = (e: DragEvent) => {
      if (!hasFiles(e)) return
      dragDepth.current++
      setGlobalDrag(true)
    }
    const onDragLeave = (e: DragEvent) => {
      if (!hasFiles(e)) return
      dragDepth.current = Math.max(0, dragDepth.current - 1)
      if (dragDepth.current === 0) setGlobalDrag(false)
    }
    const onDragOver = (e: DragEvent) => { if (hasFiles(e)) e.preventDefault() }
    const onDrop = (e: DragEvent) => {
      if (!hasFiles(e)) return
      e.preventDefault()
      dragDepth.current = 0
      setGlobalDrag(false)
      const f = e.dataTransfer?.files[0]
      if (f) handleFile(f)
    }
    window.addEventListener('dragenter', onDragEnter)
    window.addEventListener('dragleave', onDragLeave)
    window.addEventListener('dragover', onDragOver)
    window.addEventListener('drop', onDrop)
    return () => {
      window.removeEventListener('dragenter', onDragEnter)
      window.removeEventListener('dragleave', onDragLeave)
      window.removeEventListener('dragover', onDragOver)
      window.removeEventListener('drop', onDrop)
      dragDepth.current = 0
      setGlobalDrag(false)
    }
  }, [meta, loading, handleFile])


  // Global keyboard shortcuts — disabled while an input field is focused (except Ctrl+K)
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
      { id: 'go-overview', label: 'Overview layer', section: 'Navigate', hint: '1', keywords: 'overview layer dashboard', run: () => setLayer('overview') },
      { id: 'go-sessions', label: 'Investigate › Sessions/Packets', section: 'Navigate', hint: '2', keywords: 'investigate session packet wireshark', run: () => { setLayer('investigate'); setInvTab('sessions') } },
      { id: 'go-traffic', label: 'Investigate › Traffic', section: 'Navigate', keywords: 'traffic timeline ip ranking conversation', run: () => { setLayer('investigate'); setInvTab('traffic') } },
      { id: 'go-protocol', label: 'Investigate › Protocol', section: 'Navigate', keywords: 'protocol http dns tls', run: () => { setLayer('investigate'); setInvTab('protocol') } },
      { id: 'go-health', label: 'Investigate › Health Diagnostics', section: 'Navigate', keywords: 'health rtt retransmit handshake diagnose', run: () => { setLayer('investigate'); setInvTab('health') } },
      { id: 'go-geoip', label: 'Investigate › GeoIP', section: 'Navigate', keywords: 'geoip geo location country', run: () => { setLayer('investigate'); setInvTab('geoip') } },
      { id: 'go-yara', label: 'Investigate › YARA', section: 'Navigate', keywords: 'yara signature malware', run: () => { setLayer('investigate'); setInvTab('yara') } },
      { id: 'go-output', label: 'Output › Capture Comparison', section: 'Navigate', hint: '3', keywords: 'output compare diff', run: () => setLayer('output') },
      { id: 'export-json', label: 'Export JSON', section: 'Actions', keywords: 'export json download', run: () => exportJson(meta.uploadId).catch(e => setError(e.message)) },
      { id: 'export-pdf', label: 'Export PDF Report', section: 'Actions', keywords: 'export pdf report download', run: () => exportPdf(meta.uploadId).catch(e => setError(e.message)) },
      { id: 'new-file', label: 'Upload New File', section: 'Actions', hint: 'N', keywords: 'new upload reset', run: resetToUpload },
    ] : []),
    { id: 'toggle-theme', label: `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`, section: 'Settings', hint: 'T', keywords: 'theme dark light toggle', run: () => setTheme(t => t === 'dark' ? 'light' : 'dark') },
    { id: 'show-help', label: 'Keyboard shortcut help', section: 'Settings', hint: '?', keywords: 'shortcut help keyboard', run: () => setShowHelp(true) },
  ]

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-brand">
          <IconWave />
          <span className="header-logo">WireBoard</span>
          <span className="header-ver">v7.3.0</span>
        </div>
        {meta && (
          <div className="header-file-info">
            <span className="chip chip-file">{meta.filename}</span>
            <span className="chip chip-sessions">{meta.sessionCount.toLocaleString()} sessions</span>
            <span className="chip chip-src">{meta.sourceType.toUpperCase()}</span>
            <button className="btn-export" title="Export JSON" onClick={() => exportJson(meta.uploadId).catch(e => setError(e.message))}>↓ JSON</button>
            <button className="btn-export" title="PDF Report" onClick={() => exportPdf(meta.uploadId).catch(e => setError(e.message))}>↓ PDF</button>
            <button className="btn-export" title="Export IOC (CSV)" onClick={async () => {
              try {
                const blob = await exportIoc(meta.uploadId)
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url; a.download = `ioc_${meta.uploadId.slice(0, 8)}.csv`; a.click()
                URL.revokeObjectURL(url)
              } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
            }}>↓ IOC</button>
            {meta.pcapAvailable && (
              <button className="btn-export btn-pcap" title="Download this log converted to a Wireshark-openable .pcap file" onClick={() => downloadConvertedPcap(meta.uploadId).catch(e => setError(e instanceof Error ? e.message : String(e)))}>↓ PCAP</button>
            )}
            <button className="btn-new-file" title="Shortcut N" onClick={resetToUpload}>New File</button>
          </div>
        )}
        {!meta && <span className="header-tagline">PCAP Network Analysis Tool</span>}
        <a className="theme-toggle" href="https://apo-tool.lemonsqueezy.com/checkout/buy/80fcbece-5f38-4dee-87aa-c5c949c172f2" target="_blank" rel="noopener noreferrer" title="Get WireBoard License">💳 Get License</a>
        <button className="theme-toggle" title="Shortcut ?" onClick={() => setShowHelp(v => !v)}>⌨ Shortcuts</button>
        <button className="theme-toggle" title="Shortcut T" onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}>
          {theme === 'dark' ? '☀ Light' : '◑ Dark'}
        </button>
      </header>

      {/* Top loading progress bar */}
      {loading && <div className="top-progress" />}

      {/* FortiGate/tcpdump verbose-3 → no hex dump → explain why .pcap download is unavailable */}
      {meta?.convertHint && (
        <div className="convert-hint" role="status">
          <span className="convert-hint-icon">ℹ</span>
          <span>{meta.convertHint}</span>
        </div>
      )}

      {/* Global drop overlay — dropping a file in the dashboard state starts a new analysis */}
      {globalDrag && (
        <div className="global-drop-overlay">
          <div className="global-drop-box">
            <IconUpload />
            <p>Drop here to analyze a new file</p>
          </div>
        </div>
      )}

      {/* Global toast */}
      {toast && <div className="toast">{toast}</div>}

      {/* Keyboard shortcut help */}
      {showHelp && <ShortcutHelp onClose={() => setShowHelp(false)} />}

      {/* Command palette */}
      {showPalette && <CommandPalette items={paletteItems} onClose={() => setShowPalette(false)} />}

      {/* Upload Page */}
      {!meta && !loading && (
        <main className="upload-page">
          <div className="upload-hero">
            <h1 className="upload-hero-title">Analyze network traffic at a glance</h1>
            <p className="upload-hero-sub">Upload a pcap file to automatically analyze sessions, protocols, and anomalous patterns</p>
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
              <p className="drop-primary">Drag a file or click to upload</p>
              <p className="drop-hint">.pcap / .pcapng &nbsp;·&nbsp; up to 50 MB &nbsp;|&nbsp; .har / .log / .txt &nbsp;·&nbsp; up to 200 MB</p>
            </label>
          </div>
          <div className="feature-cards">
            <div className="feature-card">
              <span className="feature-icon">🔒</span>
              <span className="feature-title">100% Offline Analysis</span>
              <span className="feature-desc">Files are processed locally only and never sent anywhere</span>
            </div>
            <div className="feature-card">
              <span className="feature-icon">⚡</span>
              <span className="feature-title">Automatic Anomaly Detection</span>
              <span className="feature-desc">Maps port scans, DDoS, data exfiltration, and more to MITRE ATT&CK</span>
            </div>
            <div className="feature-card">
              <span className="feature-icon">📄</span>
              <span className="feature-title">One-Click Report</span>
              <span className="feature-desc">Instantly export as PDF report, JSON, or IOC CSV</span>
            </div>
          </div>
          <div className="target-ip-row">
            <label htmlFor="target-ip" className="ip-label">Target IP <span className="optional">(optional — auto-detected if left blank)</span></label>
            <input id="target-ip" className="ip-input" placeholder="e.g. 192.168.1.10" value={targetIp} onChange={(e) => setTargetIp(e.target.value)} />
          </div>
          {recent.length > 0 && (
            <div className="recent-files">
              <div className="recent-title">Recent Analyses</div>
              {recent.map(r => (
                <div key={r.filename + r.analyzedAt} className="recent-row">
                  <span className="recent-name mono">{r.filename}</span>
                  <span className="recent-meta">{r.sessionCount.toLocaleString()} sessions</span>
                  <span className={`recent-risk risk-${r.riskLevel.toLowerCase()}`}>
                    {r.riskLevel}{r.attackCount > 0 ? ` · ${r.attackCount} events` : ''}
                  </span>
                  <span className="recent-time">{new Date(r.analyzedAt).toLocaleString('en-US', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
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
            {['Upload', 'Pattern Analysis', 'Summary'].map((label, i) => (
              <div key={label} className={`load-step${i < loadStep ? ' done' : i === loadStep ? ' active' : ''}`}>
                <span className="load-step-dot">{i < loadStep ? '✓' : i + 1}</span>
                <span className="load-step-label">{label}</span>
                {i < 2 && <span className="load-step-line" />}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Flow Viewer overlay */}
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
              <span>▤</span> Overview <kbd className="nav-kbd">1</kbd>
            </button>
            <button className={`layer-btn${layer === 'investigate' ? ' active' : ''}`} onClick={() => setLayer('investigate')}>
              <span>🔬</span> Investigate <kbd className="nav-kbd">2</kbd>
            </button>
            <button className={`layer-btn${layer === 'output' ? ' active' : ''}`} onClick={() => setLayer('output')}>
              <span>⇄</span> Output <kbd className="nav-kbd">3</kbd>
            </button>
            <button className="palette-hint" onClick={() => setShowPalette(true)}>
              <kbd className="nav-kbd">Ctrl K</kbd> Quick Navigate
            </button>
          </nav>

          {/* Investigate Sub-nav */}
          {layer === 'investigate' && (
            <nav className="sub-nav">
              {(([ ...(meta.sourceType === 'har' ? [['har','HAR Waterfall']] : []), ['sessions','Sessions/Packets'], ['traffic','Traffic'], ['protocol','Protocol'], ['health','Health Diagnostics'], ['geoip','GeoIP'], ['yara','YARA'] ] as [InvTab, string][])).map(([key, label]) => (
                <button key={key} className={`sub-btn${invTab === key ? ' active' : ''}`} onClick={() => setInvTab(key)}>
                  {label}
                </button>
              ))}
            </nav>
          )}

          {/* Content */}
          <div className="panel-grid">

            {/* ── Overview layer ─────────────────────────────────────────────── */}
            {layer === 'overview' && (
              <>
                <TrafficOverview
                  uploadId={meta.uploadId}
                  panels={panels}
                  sessionCount={meta.sessionCount}
                  onGoTab={(tab) => { setLayer('investigate'); setInvTab(tab as InvTab) }}
                  onFlowSelect={setFlowSessionId}
                />

                <div className="overview-bottom-row">
                  <PCard title="Top Talkers (IP Traffic)">
                    <Panel1Ip data={panels.panel1_ip} />
                  </PCard>
                  <PCard title="Protocol Hierarchy">
                    <ProtocolHierarchy data={panels} />
                  </PCard>
                  <PCard title="HTTP Status">
                    <Panel4Http data={panels.panel4_http} />
                  </PCard>
                </div>
              </>
            )}

            {/* ── Investigate layer ─────────────────────────────────────────────── */}
            {layer === 'investigate' && invTab === 'sessions' && (
              <div className="panel-card wide">
                <div className="panel-card-title">Packet List (timestamp order · click a row for HEX/session)</div>
                <div className="panel-card-body">
                  <PacketList uploadId={meta.uploadId} onFlowSelect={setFlowSessionId} />
                </div>
              </div>
            )}

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

            {layer === 'investigate' && invTab === 'traffic' && (
              <>
                <PCard title="Traffic Timeline" wide>
                  <Panel3Timeline data={panels.panel3_timeline} uploadId={meta.uploadId} />
                </PCard>
                <PCard title="IP Ranking (click → drill down)">
                  <Panel6IpRanking data={panels.panel6_ip_ranking} uploadId={meta.uploadId} onFlowSelect={setFlowSessionId} />
                </PCard>
                <PCard title="Top Conversations (click → session)">
                  <Panel9Conversations data={panels.panel9_conversations} uploadId={meta.uploadId} onFlowSelect={setFlowSessionId} />
                </PCard>
              </>
            )}

            {layer === 'investigate' && invTab === 'protocol' && (
              <>
                <PCard title="Protocol Hierarchy">
                  <ProtocolHierarchy data={panels} />
                </PCard>
                <PCard title="HTTP Status Codes">
                  <Panel4Http data={panels.panel4_http} />
                </PCard>
                <PCard title="DNS Queries">
                  <Panel8Dns data={panels.panel8_dns} />
                </PCard>
                <PCard title="TLS Sessions">
                  <Panel7Tls data={panels.panel7_tls} />
                </PCard>
              </>
            )}

            {layer === 'investigate' && invTab === 'health' && (
              <div className="panel-card wide">
                <div className="panel-card-title">Communication Health Diagnostics (RTT · Retransmits · Handshake)</div>
                <div className="panel-card-body">
                  <NetworkHealthPanel uploadId={meta.uploadId} />
                </div>
              </div>
            )}

            {layer === 'investigate' && invTab === 'geoip' && (
              <div className="panel-card wide">
                <div className="panel-card-title">Source IP Geographic Distribution</div>
                <div className="panel-card-body">
                  <GeoIpPanel uploadId={meta.uploadId} />
                </div>
              </div>
            )}

            {layer === 'investigate' && invTab === 'yara' && (
              <div className="panel-card wide">
                <div className="panel-card-title">YARA Signature Detection</div>
                <div className="panel-card-body">
                  <YaraPanel uploadId={meta.uploadId} />
                </div>
              </div>
            )}

            {layer === 'investigate' && invTab === 'har' && meta.sourceType === 'har' && (
              <div className="panel-card wide">
                <div className="panel-card-title">HAR Request Waterfall (Timing · Status · Size)</div>
                <div className="panel-card-body">
                  <HarWaterfall uploadId={meta.uploadId} onFlowSelect={setFlowSessionId} />
                </div>
              </div>
            )}

            {/* ── Output layer ─────────────────────────────────────────────── */}
            {layer === 'output' && (
              <div className="panel-card wide">
                <div className="panel-card-title">Capture Comparison Analysis</div>
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
