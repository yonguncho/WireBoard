import { useState, useCallback } from 'react'
import { PlotlyChart } from './PlotlyChart'
import { addAnnotation } from '../api'
import type { BucketEntry } from '../api'

interface Marker { start_ts: number; end_ts: number; comment: string }

interface Props {
  data: { buckets: BucketEntry[] }
  uploadId?: string
}

export function Panel3Timeline({ data, uploadId }: Props) {
  const [markers, setMarkers] = useState<Marker[]>([])
  const [pendingRange, setPendingRange] = useState<[number, number] | null>(null)
  const [comment, setComment] = useState('')

  const buckets = data.buckets ?? []
  if (!buckets.length) return <div className="no-data">데이터 없음</div>

  const xs: string[] = []
  const ys: number[] = []
  for (const b of buckets) {
    xs.push(new Date(b.ts * 1000).toISOString())
    ys.push(b.bytes)
  }

  // 저장된 마커를 차트 shape으로 변환
  const shapes = markers.flatMap((m) => [
    {
      type: 'line' as const,
      x0: new Date(m.start_ts * 1000).toISOString(),
      x1: new Date(m.start_ts * 1000).toISOString(),
      y0: 0, y1: 1, yref: 'paper' as const,
      line: { color: '#f6e05e', width: 1.5, dash: 'dot' as const },
    },
    {
      type: 'line' as const,
      x0: new Date(m.end_ts * 1000).toISOString(),
      x1: new Date(m.end_ts * 1000).toISOString(),
      y0: 0, y1: 1, yref: 'paper' as const,
      line: { color: '#f6e05e', width: 1.5, dash: 'dot' as const },
    },
  ])

  const annotations = markers.map((m) => ({
    x: new Date(((m.start_ts + m.end_ts) / 2) * 1000).toISOString(),
    y: 1, yref: 'paper' as const,
    text: m.comment,
    showarrow: false,
    font: { color: '#f6e05e', size: 11 },
    bgcolor: 'rgba(0,0,0,0.6)',
    borderpad: 2,
  }))

  const onRelayout = useCallback((e: Record<string, unknown>) => {
    if (!uploadId) return
    const x0 = e['xaxis.range[0]'] as string | undefined
    const x1 = e['xaxis.range[1]'] as string | undefined
    if (x0 && x1) {
      const t0 = new Date(x0).getTime() / 1000
      const t1 = new Date(x1).getTime() / 1000
      if (t1 - t0 > 0.5) setPendingRange([t0, t1])
    }
  }, [uploadId])

  const saveMarker = async () => {
    if (!pendingRange || !uploadId || !comment.trim()) return
    const [t0, t1] = pendingRange
    try {
      await addAnnotation(uploadId, t0, t1, comment.trim())
      setMarkers((prev) => [...prev, { start_ts: t0, end_ts: t1, comment: comment.trim() }])
    } catch (_) { /* ignore */ }
    setPendingRange(null)
    setComment('')
  }

  return (
    <div style={{ position: 'relative' }}>
      <PlotlyChart
        data={[{
          type: 'scatter' as const,
          mode: 'lines' as const,
          x: xs, y: ys,
          fill: 'tozeroy' as const,
          line: { color: '#4299e1', width: 1.5 },
          fillcolor: 'rgba(66,153,225,0.15)',
        }]}
        layout={{
          xaxis: { title: { text: '시간' }, type: 'date' },
          yaxis: { title: { text: 'bytes' } },
          shapes,
          annotations,
          dragmode: 'zoom' as const,
        }}
        height={240}
        onRelayout={onRelayout}
      />
      {pendingRange && (
        <div className="marker-modal">
          <span style={{ fontSize: 12, color: '#a0aec0' }}>
            {new Date(pendingRange[0] * 1000).toLocaleTimeString()} –{' '}
            {new Date(pendingRange[1] * 1000).toLocaleTimeString()}
          </span>
          <input
            className="filter-input"
            placeholder="코멘트 입력..."
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && saveMarker()}
            autoFocus
          />
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="filter-btn" onClick={saveMarker}>저장</button>
            <button className="filter-btn" style={{ background: '#4a5568' }} onClick={() => setPendingRange(null)}>취소</button>
          </div>
        </div>
      )}
    </div>
  )
}
