import { chromium } from "playwright";
import { writeFileSync } from "node:fs";
const SHOTS = [
  { id: "2609.35886", file: "real/p1_agents.png", phrases: ["AI agents now hold spend authority and settle payments without per-action human confirmation."] },
  { id: "2501.16681", file: "real/p2_poisoning.png", phrases: ["270M on-chain attacks targeting 17M victims", "at least 83.8M USD in losses"] },
  { id: "2508.12107", file: "real/p3_wallets.png", phrases: ["only three wallets throw an explicit warning message when users attempt to transfer to the phishing address"] },
];
const b = await chromium.launch({ executablePath: process.env.CHROME });
const p = await b.newPage({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1.5 });
const out = {};
for (const s of SHOTS) {
  await p.goto(`https://arxiv.org/abs/${s.id}`, { waitUntil: "networkidle", timeout: 45000 });
  await p.evaluate(() => { const h = document.querySelector("h1.title"); window.scrollTo(0, h.getBoundingClientRect().top + window.scrollY - 120); });
  const rects = await p.evaluate((phrases) => {
    const root = document.querySelector("#abs") || document.body;
    const nodes = []; const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT); let n, all = "";
    while ((n = w.nextNode())) { nodes.push([n, all.length]); all += n.textContent; }
    const norm = []; let flat = "";
    for (let i = 0; i < all.length; i++) { const c = /\s/.test(all[i]) ? " " : all[i]; if (c === " " && flat.endsWith(" ")) continue; norm.push(i); flat += c; }
    const pos = i => { for (let k = nodes.length - 1; k >= 0; k--) if (nodes[k][1] <= i) return [nodes[k][0], i - nodes[k][1]]; };
    return phrases.map(ph => {
      const at = flat.indexOf(ph); if (at < 0) return null;
      const s0 = pos(norm[at]), s1 = pos(norm[at + ph.length - 1] + 1);
      const r = document.createRange(); r.setStart(s0[0], s0[1]); r.setEnd(s1[0], s1[1]);
      const lines = [];
      for (const q of r.getClientRects()) { if (q.width < 2) continue; const l = lines.find(L => Math.abs(L.y - q.top) < 6);
        if (l) { l.x0 = Math.min(l.x0, q.left); l.x1 = Math.max(l.x1, q.right); l.h = Math.max(l.h, q.height); } else lines.push({ y: q.top, x0: q.left, x1: q.right, h: q.height }); }
      return lines;
    });
  }, s.phrases);
  await p.screenshot({ path: s.file });
  out[s.file] = { rects, missing: rects.filter(r => !r).length };
}
writeFileSync("real/highlights.json", JSON.stringify(out, null, 1));
console.log(JSON.stringify(out));
await b.close();
