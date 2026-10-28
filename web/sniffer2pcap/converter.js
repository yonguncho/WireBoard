// FortiGate `diagnose sniffer packet` 텍스트 → libpcap 변환 코어.
// DOM 의존성 없음: 브라우저 Web Worker 와 Node 테스트에서 같은 코드를 쓴다.
//
// 설계 메모
// - 패킷 경계는 hex 오프셋 0x0000 줄이다. 헤더 줄은 "다음 패킷"의 시각·인터페이스만 제공한다.
//   그래서 알 수 없는 형식의 헤더가 끼어도 hex 블록끼리 섞이지 않는다.
// - 오프셋이 연속되지 않으면(줄 유실) 그 패킷은 버리고 실패로 집계한다. 추측으로 메우지 않는다.
// - 링크타입은 패킷 바이트로 판정한다. Fortinet 문서상 verbose 3/6 은 "이더넷부터(가능한 경우)",
//   2/5 는 "IP부터"라서, verbose 3/6 이라도 터널 인터페이스 등은 이더넷 헤더가 없을 수 있다.
// - 가짜 MAC 은 만들지 않는다. 이더넷이 없는 패킷이 섞이면 RAW IP(101)로 내보낸다.

export const LINKTYPE_ETHERNET = 1;
export const LINKTYPE_RAW = 101;
const SNAPLEN = 262144;
const MAX_EXAMPLES = 8;

const ANSI_RE = /\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]/g;
// SecureCRT / MobaXterm 등이 줄마다 붙이는 "[2026-10-29 10:11:12] " 류 접두사
const LINE_PREFIX_RE = /^\[[^\]]{4,40}\]\s?/;
const CMD_RE = /\bdiag\w*\s+sni\w*\s+pac\w*\s+(\S+)(?:\s+('[^']*'|"[^"]*"|\S+))?(?:\s+(\d))?(?:\s+(\d+))?(?:\s+([al]))?/i;
const ABS_HDR_RE = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})\.(\d{1,9})\s+(.*)$/;
const REL_HDR_RE = /^(\d{1,10})\.(\d{1,9})\s+(.*)$/;
const IFACE_RE = /^(\S+)\s+(in|out|--)\s+(.*)$/;
const PKT_DESC_RE = /->|\barp\b|who-has|\b802\.1q\b|\bllc\b|\bstp\b/i;
const HEX_LINE_RE = /^0x([0-9a-fA-F]{4,8}):?[\t ]+(.*)$/;
const HEX_TOKEN_RE = /^[0-9a-fA-F]+$/;
const RECEIVED_RE = /^(\d+)\s+packets? received by filter/i;
const NOISE_RE = /^(interfaces=\[|filters=\[|\d+\s+packets? dropped|pcap_|=~=~=|--More--)/i;
// CLI 프롬프트 "FGT60F # ...", "FGT (vdom) $ ..." — 스니퍼가 끝났다는 신호
const PROMPT_RE = /^[\w.-]+(?:\s\([\w.-]+\))?\s?[#$]\s?/;

const KNOWN_ETHERTYPES = new Set([0x0800, 0x86dd, 0x0806, 0x8035, 0x8100, 0x88a8, 0x8847, 0x8848, 0x8863, 0x8864, 0x88cc, 0x888e, 0x8809]);

/** 입력 바이트 → 문자열. PowerShell 트랜스크립트(UTF-16)도 받는다. */
export function decodeInput(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (u8.length >= 2 && u8[0] === 0xff && u8[1] === 0xfe) return new TextDecoder('utf-16le').decode(u8.subarray(2));
  if (u8.length >= 2 && u8[0] === 0xfe && u8[1] === 0xff) return new TextDecoder('utf-16be').decode(u8.subarray(2));
  return new TextDecoder('utf-8').decode(u8);
}

function cleanLine(raw) {
  let s = raw.indexOf('\x1b') >= 0 ? raw.replace(ANSI_RE, '') : raw;
  // 백스페이스 편집 흔적 제거 ("ab\bc" → "ac")
  while (s.indexOf('\b') >= 0) s = s.replace(/[^\b]?\b/, '');
  s = s.trim();
  if (s.charAt(0) === '[') s = s.replace(LINE_PREFIX_RE, '').trim();
  return s;
}

function fracToUsec(frac) {
  return parseInt((frac + '000000').slice(0, 6), 10);
}

function parseHeader(s, baseSec) {
  let m = ABS_HDR_RE.exec(s);
  let sec, usec, rest, mode;
  if (m) {
    sec = Math.floor(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000);
    usec = fracToUsec(m[7]);
    rest = m[8];
    mode = 'absolute';
  } else {
    m = REL_HDR_RE.exec(s);
    if (!m) return null;
    rest = m[3];
    // 상대시간 줄은 숫자로 시작하는 잡음과 헷갈리므로 패킷 설명처럼 보일 때만 인정
    if (!IFACE_RE.test(rest) && !PKT_DESC_RE.test(rest)) return null;
    sec = baseSec + parseInt(m[1], 10);
    usec = fracToUsec(m[2]);
    mode = 'relative';
  }
  const im = IFACE_RE.exec(rest);
  return {
    sec, usec, mode,
    iface: im ? im[1] : null,
    dir: im ? im[2] : null,
    desc: im ? im[3] : rest,
  };
}

/** hex 줄 본문 → {bytes, partial}. partial=true 는 줄이 중간에 잘렸다는 뜻. */
function parseHexBody(body) {
  // 오른쪽 ASCII 열은 탭 또는 2칸 이상 공백으로 구분된다
  const cut = body.search(/\t| {2,}/);
  const hexPart = cut >= 0 ? body.slice(0, cut) : body;
  const out = [];
  let partial = false;
  for (const tok of hexPart.split(' ')) {
    if (!tok) continue;
    if (!HEX_TOKEN_RE.test(tok) || tok.length > 4) break;
    if (tok.length % 2) { partial = true; break; }
    for (let i = 0; i < tok.length; i += 2) out.push(parseInt(tok.substr(i, 2), 16));
    if (out.length >= 16) break;
  }
  return { bytes: out, partial };
}

function ipLength(d, o, version) {
  if (d.length - o < 20) return 0;
  const v = d[o] >> 4;
  if (version && v !== version) return 0;
  if (v === 4) {
    const ihl = (d[o] & 0x0f) * 4;
    if (ihl < 20) return 0;
    const tl = (d[o + 2] << 8) | d[o + 3];
    return tl >= ihl ? tl : 0;
  }
  if (v === 6) {
    if (d.length - o < 40) return 0;
    return 40 + ((d[o + 4] << 8) | d[o + 5]);
  }
  return 0;
}

/** 패킷 바이트 판정: 이더넷 프레임인지, 헤더 없는 IP 데이터그램인지. */
export function classify(d, preferIp = false) {
  let ethHdr = 0, ethType = -1, ethIpLen = 0;
  if (d.length >= 14) {
    let o = 12;
    ethType = (d[12] << 8) | d[13];
    while ((ethType === 0x8100 || ethType === 0x88a8) && d.length >= o + 6) {
      o += 4;
      ethType = (d[o] << 8) | d[o + 1];
    }
    ethHdr = o + 2;
    if (ethType === 0x0800) ethIpLen = ipLength(d, ethHdr, 4);
    else if (ethType === 0x86dd) ethIpLen = ipLength(d, ethHdr, 6);
  }
  const rawIpLen = ipLength(d, 0, 0);
  const asEth = () => ({ kind: 'eth', ipOffset: ethHdr, wireLen: Math.max(d.length, ethHdr + ethIpLen) });
  const asIp = () => ({ kind: 'ip', ipOffset: 0, wireLen: Math.max(d.length, rawIpLen) });
  if (preferIp && rawIpLen) return asIp();
  if (ethIpLen) return asEth();
  if (rawIpLen) return asIp();
  if (KNOWN_ETHERTYPES.has(ethType)) return { kind: 'eth', ipOffset: -1, wireLen: d.length };
  return { kind: 'unknown', ipOffset: -1, wireLen: d.length };
}

/**
 * 스니퍼 텍스트 전체 → { packets, summary }.
 * options.baseTime: 상대시간 로그의 시작 시각(epoch 초). 기본 0.
 */
export function convertSnifferText(text, options = {}) {
  const baseSec = Math.floor(Number(options.baseTime) || 0);
  const packets = [];
  const failures = [];
  let failureCount = 0;
  const summary = {
    packets: 0,
    headerLines: 0,
    headersWithoutHex: 0,
    noiseLines: 0,
    truncatedPackets: 0,
    command: null,
    verbose: null,
    timestampOption: null,
    reportedCount: null,
    timeModes: new Set(),
  };

  let pending = null;   // 다음 hex 블록에 붙일 헤더
  let cur = null;       // 조립 중인 패킷
  let lineNo = 0;

  const fail = (line, reason, textSample) => {
    failureCount++;
    if (failures.length < MAX_EXAMPLES) failures.push({ line, reason, text: textSample.slice(0, 160) });
  };

  const flush = () => {
    if (!cur) return;
    const c = cur;
    cur = null;
    if (c.bad) { fail(c.bad.line, c.bad.reason, c.bad.text); return; }
    const data = Uint8Array.from(c.bytes);
    const verbose = summary.verbose;
    const cls = classify(data, verbose === 2 || verbose === 5);
    const truncated = cls.wireLen > data.length;
    if (truncated) summary.truncatedPackets++;
    packets.push({
      sec: c.hdr.sec, usec: c.hdr.usec, iface: c.hdr.iface, dir: c.hdr.dir,
      data, kind: cls.kind, ipOffset: cls.ipOffset, wireLen: cls.wireLen, truncated, line: c.hdr.line,
    });
  };

  let start = 0;
  const len = text.length;
  while (start <= len) {
    let end = text.indexOf('\n', start);
    if (end < 0) end = len;
    const raw = text.slice(start, end);
    start = end + 1;
    lineNo++;
    if (end === len && raw === '') break;

    const s = cleanLine(raw);
    if (!s) continue;

    const hm = HEX_LINE_RE.exec(s);
    if (hm) {
      const off = parseInt(hm[1], 16);
      const { bytes, partial } = parseHexBody(hm[2]);
      if (off === 0) {
        flush();
        if (pending) cur = { hdr: pending, bytes: [], partialAt: 0, bad: null };
        else cur = { bytes: [], bad: { line: lineNo, reason: 'hex dump without a packet header line', text: s } };
        pending = null;
      } else if (!cur) {
        fail(lineNo, 'hex line outside a packet (log starts mid-packet?)', s);
        continue;
      }
      if (cur.bad) continue;
      if (off !== cur.bytes.length || cur.partialAt) {
        cur.bad = {
          line: lineNo,
          reason: cur.partialAt
            ? `hex line ${cur.partialAt} was cut off, packet dropped`
            : `missing hex lines (expected offset 0x${cur.bytes.length.toString(16).padStart(4, '0')}, got 0x${hm[1]})`,
          text: s,
        };
        continue;
      }
      for (const b of bytes) cur.bytes.push(b);
      if (partial) cur.partialAt = lineNo;
      continue;
    }

    const hdr = parseHeader(s, baseSec);
    if (hdr) {
      flush();
      if (pending) summary.headersWithoutHex++;
      hdr.line = lineNo;
      pending = hdr;
      summary.headerLines++;
      summary.timeModes.add(hdr.mode);
      continue;
    }

    const cm = CMD_RE.exec(s);
    if (cm) {
      flush();
      if (pending) { summary.headersWithoutHex++; pending = null; }
      summary.command = s.slice(cm.index).slice(0, 200);
      summary.verbose = cm[3] ? parseInt(cm[3], 10) : summary.verbose;
      summary.timestampOption = cm[5] ? cm[5].toLowerCase() : (cm[3] ? 'relative' : summary.timestampOption);
      continue;
    }

    const rm = RECEIVED_RE.exec(s);
    if (rm) {
      flush();
      summary.reportedCount = (summary.reportedCount || 0) + parseInt(rm[1], 10);
      continue;
    }

    if (NOISE_RE.test(s)) { summary.noiseLines++; continue; }
    if (PROMPT_RE.test(s)) {
      flush();
      if (pending) { summary.headersWithoutHex++; pending = null; }
      summary.noiseLines++;
      continue;
    }

    if (cur || pending) {
      // 패킷 블록 안의 알 수 없는 줄: 패킷은 유지하고 실패 줄로만 기록
      fail(lineNo, 'unrecognized line inside a packet block', s);
    } else {
      summary.noiseLines++;
    }
  }
  flush();
  if (pending) summary.headersWithoutHex++;

  summary.packets = packets.length;
  summary.failedLines = failureCount;
  summary.failureExamples = failures;
  summary.timeMode = summary.timeModes.size === 0 ? null : summary.timeModes.size > 1 ? 'mixed' : [...summary.timeModes][0];
  delete summary.timeModes;

  const kinds = { eth: 0, ip: 0, unknown: 0 };
  const ifaces = new Map();
  let first = null, last = null;
  for (const p of packets) {
    kinds[p.kind]++;
    if (p.iface) ifaces.set(p.iface, (ifaces.get(p.iface) || 0) + 1);
    const t = p.sec + p.usec / 1e6;
    if (first === null || t < first) first = t;
    if (last === null || t > last) last = t;
  }
  summary.kinds = kinds;
  summary.interfaces = [...ifaces.entries()].map(([name, count]) => ({ name, packets: count }));
  summary.firstTime = first;
  summary.lastTime = last;
  summary.message = buildMessage(summary);
  summary.notes = buildNotes(summary);
  return { packets, summary };
}

function buildMessage(s) {
  if (s.packets > 0) return null;
  if (s.verbose !== null && [1, 4].includes(s.verbose)) {
    return `This capture was taken with verbose level ${s.verbose}, which prints packet headers only (no hex dump), so there are no packet bytes to convert. Re-run the sniffer with verbose 6 (or 3) — see "How to capture" below.`;
  }
  if (s.headerLines > 0) {
    return 'Found packet header lines but no hex dump. Verbose levels 1 and 4 print headers only. Re-run the sniffer with verbose 6 (or 3) to get convertible output.';
  }
  return 'No FortiGate sniffer output was found. Expected lines such as "2026-01-01 10:00:00.123456 port1 in 10.0.0.1.443 -> ..." followed by "0x0000 ..." hex lines.';
}

function buildNotes(s) {
  const notes = [];
  if (s.reportedCount !== null && s.reportedCount !== s.packets) {
    notes.push(`FortiGate reported ${s.reportedCount} packets received by filter, but ${s.packets} were converted. The log may be incomplete or contain damaged lines.`);
  }
  if (s.timeMode === 'relative') notes.push('Timestamps are relative to the start of the capture (no "a" option). Set a start time if you want wall-clock times in Wireshark.');
  if (s.timestampOption === 'l') notes.push('Timestamps were printed in the FortiGate\'s local time ("l" option). The pcap stores them as-is, interpreted as UTC.');
  if (s.timeMode === 'mixed') notes.push('The log mixes absolute and relative timestamps (several captures pasted together?). Packet order in the pcap follows the log.');
  if (s.kinds.eth && s.kinds.ip) notes.push('Some packets have an Ethernet header and some do not (e.g. tunnel or VPN interfaces). The combined file uses Raw IP; per-interface files keep Ethernet where every packet has it.');
  if (s.truncatedPackets) notes.push(`${s.truncatedPackets} packet(s) are shorter than their IP length (cut off in the log). Wireshark will mark them as truncated.`);
  if (s.headersWithoutHex && s.packets) notes.push(`${s.headersWithoutHex} header line(s) had no hex dump and were skipped.`);
  return notes;
}

/** 링크타입 결정 + RAW 출력 시 포함 가능한 패킷만 고른다. */
export function selectForOutput(pkts) {
  let eth = 0, ip = 0;
  for (const p of pkts) { if (p.kind === 'eth') eth++; else if (p.kind === 'ip') ip++; }
  if (ip === 0) return { linktype: LINKTYPE_ETHERNET, packets: pkts, dropped: 0 };
  const keep = pkts.filter(p => p.kind === 'ip' || (p.kind === 'eth' && p.ipOffset >= 0));
  return { linktype: LINKTYPE_RAW, packets: keep, dropped: pkts.length - keep.length };
}

function safeName(s) {
  return s.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60) || 'iface';
}

/** 다운로드할 파일 목록: 통합 1개 + (인터페이스가 2개 이상이면) 인터페이스별. */
export function planOutputs(result, baseName = 'sniffer') {
  const outs = [];
  const all = selectForOutput(result.packets);
  outs.push({ name: `${baseName}.pcap`, iface: null, ...all });
  if (result.summary.interfaces.length > 1) {
    for (const { name } of result.summary.interfaces) {
      const sel = selectForOutput(result.packets.filter(p => p.iface === name));
      outs.push({ name: `${baseName}_${safeName(name)}.pcap`, iface: name, ...sel });
    }
  }
  return outs;
}

/** libpcap 바이트 조각 배열 (Blob 생성자 또는 concat 에 그대로 사용). */
export function buildPcap(pkts, linktype) {
  const parts = [];
  const gh = new DataView(new ArrayBuffer(24));
  gh.setUint32(0, 0xa1b2c3d4, true);
  gh.setUint16(4, 2, true);
  gh.setUint16(6, 4, true);
  gh.setInt32(8, 0, true);
  gh.setUint32(12, 0, true);
  gh.setUint32(16, SNAPLEN, true);
  gh.setUint32(20, linktype, true);
  parts.push(new Uint8Array(gh.buffer));
  for (const p of pkts) {
    const strip = linktype === LINKTYPE_RAW && p.kind === 'eth' ? p.ipOffset : 0;
    const data = strip ? p.data.subarray(strip) : p.data;
    const rh = new DataView(new ArrayBuffer(16));
    rh.setUint32(0, p.sec >>> 0, true);
    rh.setUint32(4, p.usec, true);
    rh.setUint32(8, data.length, true);
    rh.setUint32(12, p.wireLen - strip, true);
    parts.push(new Uint8Array(rh.buffer), data);
  }
  return parts;
}

export function concatParts(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
