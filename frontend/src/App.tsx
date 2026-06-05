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

const ALLOWED_EXTENSIONS = /\.(pcap|pcapng|cap|har|log|txt|tcpdump)$/i

export default function App() {
  const [uploadId, setUploadId] = useState<string | null>(null)
  const [panels, setPanels] = useState<PanelData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [filterQuery, setFilterQuery] = useState('')
  const [filterResult, setFilterResult] = useState<{ filter_expr: string; matched_count: number } | null>(null)
  const [dragging, setDragging] = useState(false)
  const [targetIp, setTargetIp] = useState('')

  const handleFile = useCallback(async (file: File) => {
    if (!ALLOWED_EXTENSIONS.test(file.name)) {
      setError('지원하는 파일: .pcap .pcapng .cap .har .log .txt .tcpdump')
      return
    }
    setLoading(true)
    setError(null)
    setPanels(null)
    setUploadId(null)
    setFilterResult(null)
    try {
      const { upload_id } = await uploadPcap(file)
      await analyzePcap(upload_id, targetIp.trim() || undefined)
      const data = await getPanels(upload_id)
      setUploadId(upload_id)
      setPanels(data)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [targetIp])

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  const runFilter = async () => {
    if (!uploadId || !filterQuery.trim()) return
    try {
      const r = await filterSessions(uploadId, filterQuery)
      setFilterResult({ filter_expr: r.filter_expr, matched_count: r.matched_count })
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <div className="app">
      <header className="header">
        <span className="logo">WireBoard</span>
        <span className="version">v5.0</span>
        <span className="tagline">PCAP 패킷 분석 대시보드</span>
      </header>

      <section className="target-ip-bar">
        <label htmlFor="target-ip-input">분석 대상 IP (선택, 비우면 자동 감지)</label>
        <input
          id="target-ip-input"
          className="filter-input"
          placeholder="예: 192.168.1.10"
          value={targetIp}
          onChange={(e) => setTargetIp(e.target.value)}
        />
      </section>

      <section
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
          {loading ? '⏳ 분석 중...' : dragging ? '📂 여기에 놓으세요' : '📁 파일을 드래그하거나 클릭하세요'}
        </label>
        {uploadId && <div className="upload-id">✅ upload_id: {uploadId}</div>}
      </section>

      {error && <div className="error-banner">⚠️ {error}</div>}

      {uploadId && (
        <section className="filter-bar">
          <input
            className="filter-input"
            placeholder='예: "192.168.1.10에서 오는 DNS 요청" 또는 "port 443"'
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runFilter()}
          />
          <button className="filter-btn" onClick={runFilter}>필터 적용</button>
          {filterResult && (
            <span className="filter-result">
              <code>{filterResult.filter_expr}</code> — <strong>{filterResult.matched_count}</strong>개 매치
            </span>
          )}
        </section>
      )}

      {panels && (
        <div className="panels-grid">
          <div className="panel"><h3>Panel 1 · IP 랭킹</h3><Panel1Ip data={panels.panel1_ip} /></div>
          <div className="panel"><h3>Panel 2 · 프로토콜 분포</h3><Panel2Protocol data={panels.panel2_protocol} /></div>
          <div className="panel panel-wide"><h3>Panel 3 · 트래픽 타임라인</h3><Panel3Timeline data={panels.panel3_timeline} uploadId={uploadId ?? undefined} /></div>
          <div className="panel"><h3>Panel 4 · HTTP 상태 코드</h3><Panel4Http data={panels.panel4_http} /></div>
          <div className="panel"><h3>Panel 5 · 이상 지표</h3><Panel5Anomalies data={panels.panel5_anomalies} /></div>
          <div className="panel"><h3>Panel 6 · IP 순위표</h3><Panel6IpRanking data={panels.panel6_ip_ranking} uploadId={uploadId ?? undefined} /></div>
          <div className="panel"><h3>Panel 7 · TLS 세션</h3><Panel7Tls data={panels.panel7_tls} /></div>
          <div className="panel"><h3>Panel 8 · DNS 쿼리</h3><Panel8Dns data={panels.panel8_dns} /></div>
          <div className="panel panel-wide"><h3>Panel 9 · 대화 목록</h3><Panel9Conversations data={panels.panel9_conversations} /></div>
          <div className="panel panel-wide"><h3>Panel 10 · 공격 탐지 결과</h3><Panel10Attacks data={panels.panel10_attacks} /></div>
        </div>
      )}
    </div>
  )
}
