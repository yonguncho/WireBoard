import { useState, useCallback, useEffect } from 'react'
import { PlotlyChart } from './PlotlyChart'
import { addAnnotation, getAnnotations } from '../api'
import type { BucketEntry, Annotation } from '../api'

interface Props {
  data: { buckets: BucketEntry[] }
  uploadId?: string
}

export function Panel3Timeline({ data, uploadId }: Props) {
  const [markers, setMarkers] = useState<Annotation[]>([])
  const [pendingRange, setPendingRange] = useState<[number, number] | null>(null)
  const [comment, setComment] = useState('')
  const [saveErr, setSaveErr] = useState<string | null>(null)

  useEffect(() => {
    if (!uploadId) return
    getAnnotations(uploadId).then(setMarkers).catch((e) => {
      console.warn(JSON.stringify({ event: 'load_annotations_failed', error: (e as Error)?.message }))
    })
  }, [uploadId])

  const buckets = data.buckets ?? []
  if (!buckets.length) return <div className="no-data">No data</div>

  const xs: string[] = []
  const ys: number[] = []
  const errs: number[] = []
  for (const b of buckets) {
    xs.push(new Date(b.ts * 1000).toISOString())
    ys.push(b.bytes)
    errs.push(b.errors ?? 0)
  }
  const hasErrors = errs.some(e => e > 0)

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

  const chartAnnotations = markers.map((m) => ({
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
    setSaveErr(null)
    try {
      await addAnnotation(uploadId, t0, t1, comment.trim())
      setMarkers((prev) => [...prev, { upload_id: uploadId, start_ts: t0, end_ts: t1, comment: comment.trim() }])
    } catch (e) {
      setSaveErr(e instanceof Error ? e.message : 'Save failed')
      console.warn(JSON.stringify({ event: 'save_annotation_failed', error: (e as Error)?.message }))
    }
    setPendingRange(null)
    setComment('')
  }

  return (
    <div style={{ position: 'relative' }}>
      <PlotlyChart
        data={[
          {
            type: 'scatter' as const,
            mode: 'lines' as const,
            name: 'Traffic',
            x: xs, y: ys,
            fill: 'tozeroy' as const,
            line: { color: '#4299e1', width: 1.5 },
            fillcolor: 'rgba(66,153,225,0.15)',
          },
          // 오류 오버레이 — "언제부터 RST/무응답이 급증했나" (2차 y축)
          ...(hasErrors ? [{
            type: 'bar' as const,
            name: 'Errors (RST + no-reply)',
            x: xs, y: errs,
            yaxis: 'y2' as const,
            marker: { color: 'rgba(252,67,67,0.55)' },
          }] : []),
        ]}
        layout={{
          xaxis: { title: { text: 'Time' }, type: 'date' },
          yaxis: { title: { text: 'bytes' } },
          ...(hasErrors ? { yaxis2: { title: { text: 'errors' }, overlaying: 'y' as const, side: 'right' as const, showgrid: false, rangemode: 'tozero' as const } } : {}),
          showlegend: hasErrors,
          legend: { orientation: 'h' as const, y: 1.12, font: { size: 10 } },
          shapes,
          annotations: chartAnnotations,
          dragmode: 'zoom' as const,
        }}
        height={240}
        onRelayout={onRelayout}
      />
      {pendingRange && (
        <div className="marker-backdrop" onClick={() => { setPendingRange(null); setSaveErr(null) }}>
        <div className="marker-modal" onClick={e => e.stopPropagation()}>
          <span style={{ fontSize: 12, color: '#a0aec0' }}>
            {new Date(pendingRange[0] * 1000).toLocaleTimeString()} –{' '}
            {new Date(pendingRange[1] * 1000).toLocaleTimeString()}
          </span>
          <input
            className="filter-input"
            placeholder="Enter a comment..."
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && saveMarker()}
            autoFocus
          />
          {saveErr && <span style={{ color: '#fc8181', fontSize: 12 }}>{saveErr}</span>}
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="filter-btn" onClick={saveMarker}>Save</button>
            <button className="filter-btn" style={{ background: '#4a5568' }} onClick={() => { setPendingRange(null); setSaveErr(null) }}>Cancel</button>
          </div>
        </div>
        </div>
      )}
      {uploadId && markers.length > 0 && (
        <div className="annotation-list">
          <div className="annotation-list-title">Saved Markers ({markers.length})</div>
          <ul className="annotation-items">
            {markers.map((m, i) => (
              <li key={i} className="annotation-item">
                <span className="annotation-time">
                  {new Date(m.start_ts * 1000).toLocaleTimeString()} – {new Date(m.end_ts * 1000).toLocaleTimeString()}
                </span>
                <span className="annotation-comment">{m.comment}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
