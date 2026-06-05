interface Props { data: { rst_count: number; malformed_count: number; retransmit_count: number } }

function Metric({ label, value, threshold }: { label: string; value: number; threshold: number }) {
  const level = value === 0 ? 'ok' : value >= threshold ? 'high' : 'med'
  return (
    <div className={`metric-card metric-${level}`}>
      <div className="metric-val">{value.toLocaleString()}</div>
      <div className="metric-label">{label}</div>
    </div>
  )
}

export function Panel5Anomalies({ data }: Props) {
  const d = data ?? { rst_count: 0, malformed_count: 0, retransmit_count: 0 }
  return (
    <div className="metrics-row">
      <Metric label="RST 패킷" value={d.rst_count} threshold={100} />
      <Metric label="Malformed" value={d.malformed_count} threshold={10} />
      <Metric label="재전송" value={d.retransmit_count} threshold={100} />
    </div>
  )
}
