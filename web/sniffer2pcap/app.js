// 페이지 UI: 입력 수집 → Worker 에 변환 위임 → 요약·다운로드 표시.
import { SAMPLE } from './sample.js';

const $ = (id) => document.getElementById(id);
const worker = new Worker('worker.js', { type: 'module' });
let objectUrls = [];
let busy = false;

const LINKTYPE_LABEL = { 1: 'Ethernet', 101: 'Raw IP (no Ethernet header)' };

function fmtTime(t, mode) {
  if (t === null || t === undefined) return '—';
  if (mode === 'relative' && t < 1e9) return `${t.toFixed(6)} s`;
  const ms = Math.floor(t * 1000);
  const us = String(Math.min(999999, Math.round((t - Math.floor(t)) * 1e6))).padStart(6, '0');
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, `.${us} UTC`).replace('T', ' ');
}

function fmtBytes(n) {
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c !== null && c !== undefined) node.append(c);
  return node;
}

function baseTimeOption() {
  const v = $('base-time').value;
  if (!v) return {};
  const t = Date.parse(v + 'Z');
  return Number.isFinite(t) ? { baseTime: Math.floor(t / 1000) } : {};
}

function setStatus(text, kind = '') {
  const s = $('status');
  s.textContent = text;
  s.className = `status ${kind}`;
}

function start(payload) {
  if (busy) return;
  busy = true;
  $('convert').disabled = true;
  $('results').hidden = true;
  setStatus('Converting…', 'working');
  worker.postMessage({ ...payload, options: baseTimeOption() });
}

worker.onmessage = (e) => {
  busy = false;
  $('convert').disabled = false;
  const r = e.data;
  if (!r.ok) { setStatus(`Conversion failed: ${r.error}`, 'error'); return; }
  render(r);
};

worker.onerror = (e) => {
  busy = false;
  $('convert').disabled = false;
  setStatus(`Your browser could not run the converter (${e.message || 'worker error'}). Please use a current version of Chrome, Edge, Firefox or Safari.`, 'error');
};

function render(r) {
  const s = r.summary;
  for (const u of objectUrls) URL.revokeObjectURL(u);
  objectUrls = [];

  if (s.packets === 0) {
    setStatus(s.message, 'error');
    return;
  }
  setStatus(`Converted ${s.packets.toLocaleString()} packets in ${(r.ms / 1000).toFixed(1)} s. Nothing was uploaded.`, 'ok');

  const rows = [
    ['Packets converted', s.packets.toLocaleString() + (s.reportedCount !== null ? ` (FortiGate reported ${s.reportedCount.toLocaleString()})` : '')],
    ['Time range', s.timeMode === 'relative' && s.firstTime < 1e9
      ? `${fmtTime(s.firstTime, 'relative')} → ${fmtTime(s.lastTime, 'relative')} (relative)`
      : `${fmtTime(s.firstTime)} → ${fmtTime(s.lastTime)}`],
    ['Interfaces', s.interfaces.length ? s.interfaces.map(i => `${i.name} (${i.packets})`).join(', ') : 'not in log (verbose 1–3)'],
    ['Sniffer command', s.command || 'not found in log'],
    ['Lines that could not be parsed', String(s.failedLines)],
  ];
  const tbody = $('summary-body');
  tbody.replaceChildren(...rows.map(([k, v]) => el('tr', {}, el('th', { scope: 'row' }, k), el('td', {}, v))));

  const fails = $('failures');
  fails.replaceChildren();
  if (s.failureExamples.length) {
    const list = el('ul');
    for (const f of s.failureExamples) {
      list.append(el('li', {}, el('span', { class: 'muted' }, `line ${f.line}: ${f.reason}`), el('code', {}, f.text)));
    }
    fails.append(el('details', {}, el('summary', {}, `Show examples (${s.failureExamples.length} of ${s.failedLines})`), list));
  }

  $('notes').replaceChildren(...s.notes.map(n => el('li', {}, n)));
  $('notes').hidden = s.notes.length === 0;

  const dl = $('downloads');
  dl.replaceChildren();
  for (const o of r.outputs) {
    const url = URL.createObjectURL(o.blob);
    objectUrls.push(url);
    const label = o.iface ? `Interface ${o.iface}` : (r.outputs.length > 1 ? 'All interfaces' : 'PCAP file');
    const meta = `${o.packets.toLocaleString()} packets · ${LINKTYPE_LABEL[o.linktype]} · ${fmtBytes(o.blob.size)}`
      + (o.dropped ? ` · ${o.dropped} non-IP packet(s) left out` : '');
    dl.append(el('a', { class: o.iface ? 'dl secondary' : 'dl', href: url, download: o.name },
      el('strong', {}, `Download ${label}`), el('span', {}, `${o.name} — ${meta}`)));
  }
  $('results').hidden = false;
  $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function baseNameOf(name) {
  return (name.replace(/\.[^.]+$/, '') || 'sniffer').replace(/[^A-Za-z0-9._-]+/g, '_');
}

function handleFile(file) {
  if (!file) return;
  $('file-name').textContent = `${file.name} (${fmtBytes(file.size)})`;
  start({ file, baseName: baseNameOf(file.name) });
}

$('file').addEventListener('change', (e) => handleFile(e.target.files[0]));
$('convert').addEventListener('click', () => {
  const text = $('paste').value;
  if (!text.trim()) { setStatus('Paste sniffer output or drop a log file first.', 'error'); return; }
  start({ text, baseName: 'sniffer' });
});

const drop = $('drop');
['dragenter', 'dragover'].forEach(t => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(t => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', (e) => handleFile(e.dataTransfer.files[0]));
// 드롭 영역 밖에 떨어뜨려도 브라우저가 파일을 열어버리지 않게
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => { e.preventDefault(); handleFile(e.dataTransfer.files[0]); });

$('sample').addEventListener('click', () => {
  $('paste').value = SAMPLE;
  start({ text: SAMPLE, baseName: 'sample' });
});
