import { chromium } from "playwright";
const b = await chromium.launch({ executablePath: process.env.CHROME }); const p = await b.newPage();
await p.goto("file://" + process.cwd() + "/film.html"); await p.evaluate(() => window.ready);
console.log(JSON.stringify(await p.evaluate(() => window.EVENTS))); await b.close();
