import { useMemo, useState } from 'react'
import type { SessionHealth } from '../api'

interface Node { id: string; x: number; y: number; isInternal: boolean; sessionCount: number }
interface Edge {
  src: string; dst: string
  count: number
  bytes: number
  hasRst: boolean
  protocols: Set<string>
}

interface TooltipState {
  x: number; y: number
  src: string; dst: string
























    const key = [s.src_ip, s.dst_ip].sort().join('→')
    const existing = edgeMap.get(key)
    if (existing) {
      existing.count++
      existing.bytes += s.bytes_sent + s.bytes_recv
      if (s.rst) existing.hasRst = true
      existing.protocols.add(s.protocol)
    } else {
      edgeMap.set(key, {
        src: s.src_ip, dst: s.dst_ip,
        count: 1,
        bytes: s.bytes_sent + s.bytes_recv,
        hasRst: s.rst ?? false,
        protocols: new Set([s.protocol]),
      })
    }
  }

  const allIps = [...nodeSet]
  const truncated = Math.max(0, allIps.length - MAX_NODES)