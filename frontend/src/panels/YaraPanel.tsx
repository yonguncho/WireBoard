import { useEffect, useState } from 'react'
import { getCaptureToken } from '../api'

interface YaraMatch {
  rule: string
  description: string
  severity: string
  mitre: string
  session_id: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  matched_strings: string[]
}

interface Props { uploadId: string }

const SEV_COLOR: Record<string, string> = {
  critical: '#fc8181',
  high: '#f6ad55',
  medium: '#f6e05e',
  low: '#48bb78',
}

export function YaraPanel({ uploadId }: Props) {
  const [data, setData] = useState<{ available: boolean; match_count: number; matches: YaraMatch[] } | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!uploadId) return
    const token = getCaptureToken(uploadId)
    fetch(`/api/yara/${uploadId}`, { headers: token ? { 'X-Upload-Token': token } : {} })
      .then(r => r.json())
      .then(setData)
      .catch(e => setError(String(e)))
  }, [uploadId])

  if (error) return <div className="no-data">Failed to load YARA: {error}</div>
  if (!data) return <div className="no-data">Scanning with YARA...</div>
  if (!data.available) return (
    <div className="no-data">
      The yara-python package is not installed, so YARA detection is unavailable.<br/>
      <code>pip install yara-python</code>
    </div>
  )
  if (!data.matches.length) return <div className="no-data" style={{color: '#48bb78'}}>✓ No YARA matches — no known malicious patterns detected</div>

  return (
    <div>
      <div style={{ marginBottom: 8, fontWeight: 600, fontSize: 13 }}>
        {data.match_count} YARA matches found
      </div>
      <table className="mini-table">
        <thead>
          <tr><th>Rule</th><th>Severity</th><th>MITRE</th><th>Session</th><th>Description</th></tr>
        </thead>
        <tbody>
          {data.matches.map((m, i) => (
            <tr key={i}>
              <td style={{ fontWeight: 600, color: SEV_COLOR[m.severity] ?? '#e2e8f0' }}>{m.rule}</td>
              <td>
                <span className="severity-badge" style={{ background: SEV_COLOR[m.severity] ?? '#718096', color: '#1a1d23', padding: '1px 6px', borderRadius: 4, fontSize: 10, fontWeight: 700 }}>
                  {m.severity.toUpperCase()}
                </span>
              </td>
              <td className="mono" style={{ fontSize: 11 }}>{m.mitre}</td>
              <td className="mono" style={{ fontSize: 11 }}>{m.src_ip}:{m.src_port} → {m.dst_ip}:{m.dst_port}</td>
              <td style={{ fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{m.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
