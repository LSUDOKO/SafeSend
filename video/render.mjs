import { chromium } from "playwright";
import { spawn } from "node:child_process";
const FPS = Number(process.env.FPS || 30), SUB = Number(process.env.SUB || 4), WORKERS = Number(process.env.WORKERS || 5);
const exe = { executablePath: process.env.CHROME };
const b0 = await chromium.launch(exe); const p0 = await b0.newPage(); await p0.goto("file://" + process.cwd() + "/film.html");
const DURATION = await p0.evaluate(() => window.DURATION); await b0.close();
const FRAMES = Math.round(DURATION * FPS), per = Math.ceil(FRAMES / WORKERS), t0 = Date.now();
async function worker(w) {
  const from = w * per, to = Math.min(FRAMES, from + per); if (from >= to) return;
  const browser = await chromium.launch(exe);
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  await page.goto("file://" + process.cwd() + "/film.html"); await page.evaluate(() => window.ready);
  const ff = spawn("ffmpeg", ["-v", "error", "-y", "-f", "image2pipe", "-framerate", String(FPS * SUB), "-c:v", "mjpeg", "-i", "-",
    "-vf", `tmix=frames=${SUB},select='eq(mod(n\\,${SUB})\\,${SUB - 1})',setpts=N/(${FPS}*TB)`, "-r", String(FPS),
    "-c:v", "libx264", "-preset", "medium", "-crf", "16", "-pix_fmt", "yuv420p", `seg_${String(w).padStart(2, "0")}.mp4`], { stdio: ["pipe", "inherit", "inherit"] });
  for (let f = from; f < to; f++) {
    for (let s = 0; s < SUB; s++) {
      await page.evaluate(t => window.seek(t), (f + s / SUB * 0.6) / FPS);
      const buf = await page.screenshot({ type: "jpeg", quality: 92 });
      if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once("drain", r));
    }
    if (w === 0 && (f - from) % 60 === 0) console.log(`w0 ${f - from}/${to - from} ${((Date.now() - t0) / 1000).toFixed(0)}s`);
  }
  ff.stdin.end(); await new Promise(r => ff.on("close", r)); await browser.close();
}
await Promise.all([...Array(WORKERS).keys()].map(worker));
console.log("frames", FRAMES, "done in", ((Date.now() - t0) / 1000).toFixed(0), "s");
