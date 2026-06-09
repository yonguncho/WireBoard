import { useState, useCallback } from 'react'
import { getNetworkHealth } from '../api'
import type { NetworkHealthData, SessionHealth } from '../api'

const ICMP_LABEL_KR: Record<string, string> = {
  ttl_expired:      'TTL 만료',
  fragment_timeout: '단편화 재조립 타임아웃',
  net_unreachable:  '네트워크 도달 불가',
  host_unreachable: '호스트 도달 불가',
  port_unreachable: '포트 도달 불가',
  admin_prohibited: '관리자 차단',
  unreachable:      '도달 불가',
}

function icmpLabelKr(label: string | undefined): string {
  return label ? (ICMP_LABEL_KR[label] ?? label) : '—'
}

interface Props { uploadId: string }

function scoreColor(s: number) {
  return s >= 80 ? '#22c55e' : s >= 50 ? '#f59e0b' : '#ef4444'
}

function ScoreCircle({ score, status }: { score: number; status: string }) {
  const c = scoreColor(score)
  return (
    <div className="nh-score-circle" style={{ borderColor: c }}>
      <span className="nh-score-num" style={{ color: c }}>{score}</span>
      <span className="nh-score-label">{status}</span>
    </div>
  )
}

function SessionRow({ s, onSelect, selected }: { s: SessionHealth; selected: boolean; onSelect: () => void }) {
  const c = scoreColor(s.score)
  return (
    <tr className={`nh-session-row${selected ? ' nh-row-selected' : ''}`} onClick={onSelect}>
      <td><span className="nh-score-pill" style={{ background: c, color: '#0a0a0a' }}>{s.score}</span></td>
      <td><span className={`nh-status-badge nh-status-${s.status}`}>{s.status}</span></td>
      <td className="mono nh-addr">{s.src_ip}:{s.src_port}</td>
      <td className="mono nh-arrow">→</td>
      <td className="mono nh-addr">{s.dst_ip}:{s.dst_port}</td>
      <td><span className="nh-proto">{s.protocol}</span></td>
      <td className="mono nh-handshake">{s.handshake}</td>
      <td className="mono">{s.rtt_ms !== null ? `${s.rtt_ms.toFixed(1)} ms` : '—'}</td>
      <td className="mono">{s.retransmit_count > 0 ? <span style={{ color: '#f59e0b' }}>{s.retransmit_count} ({(s.retransmit_rate * 100).toFixed(1)}%)</span> : '—'}</td>
      <td className="nh-root-cause">{s.root_cause}</td>
    </tr>
  )
}

function SessionDetail({ s }: { s: SessionHealth }) {
  return (
    <div className="nh-detail">
      <div className="nh-detail-header">
        <span className="mono">{s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}</span>
        <span className="nh-proto">{s.protocol}</span>
        <ScoreCircle score={s.score} status={s.status} />
      </div>

      <div className="nh-detail-grid">
        <div className="nh-detail-card">
          <div className="nh-detail-card-title">연결 정보</div>
          <div className="nh-detail-row"><span>핸드셰이크</span><span className="mono">{s.handshake}</span></div>
          <div className="nh-detail-row"><span>RTT</span><span className="mono">{s.rtt_ms !== null ? `${s.rtt_ms.toFixed(2)} ms` : '—'}</span></div>
          <div className="nh-detail-row"><span>종료 방식</span><span className="mono">{s.close_type}</span></div>
          <div className="nh-detail-row"><span>RST 유형</span><span className="mono">{s.rst_type}</span></div>
        </div>
        <div className="nh-detail-card">
          <div className="nh-detail-card-title">트래픽</div>
          <div className="nh-detail-row"><span>패킷 수</span><span className="mono">{s.packet_count.toLocaleString()}</span></div>
          <div className="nh-detail-row"><span>송신</span><span className="mono">{s.bytes_sent.toLocaleString()} B</span></div>
          <div className="nh-detail-row"><span>수신</span><span className="mono">{s.bytes_recv.toLocaleString()} B</span></div>
          <div className="nh-detail-row"><span>세션 시간</span><span className="mono">{s.duration_s.toFixed(3)} s</span></div>
        </div>
        <div className="nh-detail-card">
          <div className="nh-detail-card-title">재전송</div>
          <div className="nh-detail-row"><span>횟수</span><span className="mono">{s.retransmit_count}</span></div>
          <div className="nh-detail-row"><span>비율</span><span className="mono">{(s.retransmit_rate * 100).toFixed(2)}%</span></div>