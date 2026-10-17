import { chromium } from "playwright";
const b = await chromium.launch({ executablePath: process.env.CHROME }); const p = await b.newPage();
for (const id of ["2609.35886", "2501.16681", "2508.12107"]) {
  await p.goto(`https://arxiv.org/abs/${id}`, { waitUntil: "domcontentloaded", timeout: 30000 });
  const t = await p.evaluate(() => (document.querySelector("blockquote.abstract")?.innerText || "NONE").replace(/\s+/g, " "));
  const title = await p.evaluate(() => document.querySelector("h1.title")?.innerText);
  console.log(id, "|", title, "\n", t.slice(0, 1200), "\n");
}
await b.close();
