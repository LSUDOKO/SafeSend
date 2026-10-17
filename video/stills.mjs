import { chromium } from "playwright";
const times = process.argv.slice(2).map(Number);
const browser = await chromium.launch({ executablePath: process.env.CHROME });
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
const errs = []; page.on("pageerror", e => errs.push(e.message)); page.on("console", m => { if (m.type() === "error") errs.push(m.text()); });
await page.goto("file://" + process.cwd() + "/" + (process.env.FILM || "film.html")); await page.evaluate(() => window.ready);
for (const t of times) { await page.evaluate(t => window.seek(t), t); await page.screenshot({ path: `still_${t.toFixed(1)}.png` }); }
console.log("errors:", errs.length ? errs : "none"); await browser.close();
