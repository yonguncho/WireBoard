// 변환은 전부 이 Worker 안에서 돈다 — 수십 MB 로그에서도 페이지가 멈추지 않게.
// 네트워크 호출 없음 (페이지 CSP 의 connect-src 'none' 이 이를 강제한다).
import { decodeInput, convertSnifferText, planOutputs, buildPcap } from './converter.js';

self.onmessage = async (e) => {
  const { file, text, baseName, options } = e.data;
  try {
    const started = performance.now();
    const input = file ? decodeInput(new Uint8Array(await file.arrayBuffer())) : text;
    const result = convertSnifferText(input, options);
    const outputs = result.summary.packets === 0 ? [] : planOutputs(result, baseName).map(o => ({
      name: o.name,
      iface: o.iface,
      linktype: o.linktype,
      packets: o.packets.length,
      dropped: o.dropped,
      blob: new Blob(buildPcap(o.packets, o.linktype), { type: 'application/vnd.tcpdump.pcap' }),
    }));
    self.postMessage({ ok: true, summary: result.summary, outputs, inputChars: input.length, ms: Math.round(performance.now() - started) });
  } catch (err) {
    self.postMessage({ ok: false, error: String((err && err.message) || err) });
  }
};
