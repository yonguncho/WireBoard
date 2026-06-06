import { useState, useCallback } from 'react'
import { uploadPcap, analyzePcap, compareCaptures } from '../api'
import type { CompareResult } from '../api'

const ALLOWED = /\.(pcap|pcapng|cap|har|log|txt|tcpdump)$/i

interface Props {
  baseUploadId: string
  baseFilename: string
}

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)} KB`
  return `${n} B`
}

export function ComparePanel({ baseUploadId, baseFilename }: Props) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [compareFilename, setCompareFilename] = useState<string | null>(null)
  const [result, setResult] = useState<CompareResult | null>(null)

  const handleFile = useCallback(async (file: File) => {
    if (!ALLOWED.test(file.name)) {
      setError('지원 포맷: .pcap · .pcapng · .cap · .har · .log · .txt · .tcpdump')
      return
    }
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const up = await uploadPcap(file)
      await analyzePcap(up.upload_id)
      const r = await compareCaptures(baseUploadId, up.upload_id)
      setCompareFilename(file.name)
      setResult(r)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [baseUploadId])

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }, [handleFile])

  return (
    <div className="compare-panel">
      <div className="compare-header">
        <div className="compare-file-label">
          <span className="chip chip-file">기준</span>
          <span className="compare-filename">{baseFilename}</span>
        </div>
        <span className="compare-arrow">vs</span>
        <div className="compare-file-label">
          <span className="chip chip-file">비교</span>
          <span className="compare-filename">{compareFilename ?? '파일 미선택'}</span>
        </div>
      </div>

      {!result && !loading && (
        <div
          className="compare-drop-zone"
          onDragOver={(e) => e.preventDefault()}
          onDrop={onDrop}
        >
          <input
            type="file"
            id="compare-input"
            accept=".pcap,.pcapng,.cap,.har,.log,.txt,.tcpdump"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f) }}
            hidden
          />
          <label htmlFor="compare-input" className="compare-drop-label">
            <p className="drop-primary">비교할 파일을 드래그하거나 클릭하여 업로드</p>
            <p className="drop-hint">분석 후 두 캡처의 IP · 포트 · 트래픽 차이를 표시합니다</p>
          </label>
        </div>
      )}

      {loading && (
        <div className="compare-loading">
          <div className="spinner" style={{ width: 28, height: 28 }} />
          <span>비교 파일 분석 중...</span>
        </div>
      )}

      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠</span>
          <pre className="error-text">{error}</pre>
        </div>
      )}

      {result && (
        <div className="compare-results">
          {/* 트래픽 요약 */}
          <div className="compare-summary-row">
            <div className="compare-metric">
              <div className="compare-metric-val">
                {result.traffic_delta_pct === null
                  ? 'N/A'
                  : `${result.traffic_delta_pct > 0 ? '+' : ''}${result.traffic_delta_pct}%`}
              </div>
              <div className="compare-metric-label">트래픽 증감</div>
            </div>
            <div className="compare-metric">
              <div className="compare-metric-val">{fmt(result.byte_ratio.a_total ?? 0)}</div>
              <div className="compare-metric-label">기준 트래픽</div>
            </div>
            <div className="compare-metric">
              <div className="compare-metric-val">{fmt(result.byte_ratio.b_total ?? 0)}</div>
              <div className="compare-metric-label">비교 트래픽</div>
            </div>
            <div className="compare-metric">
              <div className="compare-metric-val level-danger">{result.new_ips.length}</div>
              <div className="compare-metric-label">신규 IP</div>
            </div>
            <div className="compare-metric">
              <div className="compare-metric-val">{result.new_ports.length}</div>
              <div className="compare-metric-label">신규 포트</div>
            </div>
          </div>

          <div className="compare-grid">
            {/* 신규 IP */}
            <IpList title="신규 IP (비교에만 있음)" ips={result.new_ips} variant="danger" />

            {/* 사라진 IP */}
            <IpList title="사라진 IP (기준에만 있음)" ips={result.removed_ips} variant="warn" />

            {/* 공통 IP */}
            <IpList title="공통 IP" ips={result.common_ips} variant="ok" />

            {/* 신규 포트 */}
            <div className="compare-list-card">
              <div className="compare-list-title">신규 포트 (비교에만 있음)</div>
              {result.new_ports.length === 0
                ? <div className="no-data">없음</div>
                : <div className="compare-port-list">
                    {result.new_ports.map((p) => (
                      <span key={p} className="port-chip">{p}</span>
                    ))}
                  </div>
              }
            </div>

            {/* 프로토콜 차이 */}
            {Object.keys(result.protocol_diff).length > 0 && (
              <div className="compare-list-card wide">
                <div className="compare-list-title">프로토콜 트래픽 변화 (bytes)</div>
                <table className="compare-proto-table">
                  <thead>
                    <tr><th>프로토콜</th><th>기준</th><th>비교</th><th>변화</th></tr>
                  </thead>
                  <tbody>
                    {Object.entries(result.protocol_diff).map(([proto, { a, b }]) => {
                      const delta = b - a
                      return (
                        <tr key={proto}>
                          <td>{proto}</td>
                          <td>{fmt(a)}</td>
                          <td>{fmt(b)}</td>
                          <td className={delta > 0 ? 'txt-danger' : delta < 0 ? 'txt-ok' : ''}>
                            {delta > 0 ? '+' : ''}{fmt(Math.abs(delta))} {delta > 0 ? '▲' : delta < 0 ? '▼' : '—'}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <button
            className="btn-new-file"
            style={{ marginTop: 16 }}
            onClick={() => { setResult(null); setCompareFilename(null) }}
          >
            다른 파일과 비교
          </button>
        </div>
      )}
    </div>
  )
}

function IpList({ title, ips, variant }: { title: string; ips: string[]; variant: 'danger' | 'warn' | 'ok' }) {
  return (
    <div className="compare-list-card">
      <div className={`compare-list-title txt-${variant}`}>{title}</div>
      {ips.length === 0
        ? <div className="no-data">없음</div>
        : <ul className="compare-ip-list">
            {ips.map((ip) => <li key={ip}>{ip}</li>)}
          </ul>
      }
    </div>
  )
}
