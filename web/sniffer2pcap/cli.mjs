// 테스트·로컬 사용용 CLI: node cli.mjs <input.txt> <out_dir> [--base-time <epoch>]
// 브라우저와 같은 converter.js 를 쓰므로 여기서 검증한 결과가 웹 도구 결과와 동일하다.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { basename, extname, join } from 'node:path';
import { decodeInput, convertSnifferText, planOutputs, buildPcap, concatParts } from './converter.js';

const [input, outDir, ...rest] = process.argv.slice(2);
if (!input || !outDir) {
  console.error('usage: node cli.mjs <input.txt> <out_dir> [--base-time <epoch>]');
  process.exit(2);
}
const bt = rest.indexOf('--base-time');
const options = bt >= 0 ? { baseTime: Number(rest[bt + 1]) } : {};

const result = convertSnifferText(decodeInput(readFileSync(input)), options);
mkdirSync(outDir, { recursive: true });
const files = [];
if (result.summary.packets > 0) {
  for (const o of planOutputs(result, basename(input, extname(input)))) {
    writeFileSync(join(outDir, o.name), concatParts(buildPcap(o.packets, o.linktype)));
    files.push({ name: o.name, iface: o.iface, linktype: o.linktype, packets: o.packets.length, dropped: o.dropped });
  }
}
const out = { summary: result.summary, files };
writeFileSync(join(outDir, 'summary.json'), JSON.stringify(out, null, 2));
console.log(JSON.stringify(out));
