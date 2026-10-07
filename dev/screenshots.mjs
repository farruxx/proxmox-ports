// Capture README screenshots of pve-gateway (mock mode) with headless Chrome over CDP. Run via dev/screenshots.sh.
// Zero dependencies: Node 22+ (global fetch + WebSocket).
import { spawn } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";

const BASE = process.env.BASE || "http://127.0.0.1:8101";
const OUT = process.argv[2] || "docs/screenshots";
const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = 9333;
const sleep = ms => new Promise(r => setTimeout(r, ms));
mkdirSync(OUT, { recursive: true });

// 1. log in through the API to get a session cookie
const login = await fetch(BASE + "/api/login", {
  method: "POST", headers: { "Content-Type": "application/json", "X-PVEGW": "1" },
  body: JSON.stringify({ username: "admin", password: "admin" }),
});
const sid = /pvegw_sid=([^;]+)/.exec(login.headers.get("set-cookie"))[1];

// 2. headless chrome
const chrome = spawn(CHROME, ["--headless=new", `--remote-debugging-port=${PORT}`, "--hide-scrollbars",
  `--user-data-dir=${process.env.PROFILE_DIR}`, "--no-first-run", "--no-default-browser-check", "about:blank"],
  { stdio: "ignore" });
let target;
for (let i = 0; i < 50 && !target; i++) {
  await sleep(200);
  try { target = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find(t => t.type === "page"); } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener("open", r));
let seq = 0; const pending = new Map();
ws.addEventListener("message", e => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
});
const cdp = (method, params = {}) => new Promise((res, rej) => {
  const id = ++seq; pending.set(id, m => m.error ? rej(new Error(method + ": " + m.error.message)) : res(m.result));
  ws.send(JSON.stringify({ id, method, params }));
});
const js = async expr => {
  const r = await cdp("Runtime.evaluate", { expression: `(async () => { ${expr} })()`, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
  return r.result.value;
};

await cdp("Page.enable");
await cdp("Network.enable");
await cdp("Network.setCookie", { name: "pvegw_sid", value: sid, url: BASE, httpOnly: true });

// hide mock-only UI so screenshots look like a real host
const CLEAN = `{
  clearInterval(timer); timer = 1;   // stop auto-refresh re-rendering mid-shot
  for (const c of document.querySelectorAll('#status .chip')) if (c.textContent === 'MOCK') c.remove();
  const mb = document.querySelector('#mockBar'); if (mb) mb.remove();
  for (const li of document.querySelectorAll('#checks li')) if (/mock mode/.test(li.innerText)) li.remove();
  document.querySelector('#who').textContent = 'root@pam';
  for (const d of document.querySelectorAll('#checks .d')) {
    if (d.textContent === 'mock') d.textContent = 'uid 0';
    d.textContent = d.textContent.split(' [mock]').join('').trim();
  }
}`;

async function shot(name, { hash, width = 1200, height = 760, dark = false, mobile = false, setup = "", fit = false, wait = 900 }) {
  await cdp("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 2, mobile });
  await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: dark ? "dark" : "light" }] });
  await cdp("Page.navigate", { url: BASE + "/?" + Date.now() + hash });
  await sleep(wait);
  await js(`while (document.querySelector('#app').hidden) await new Promise(r => setTimeout(r, 100)); ${CLEAN} ${setup}`);
  await sleep(400);
  let h = height;
  if (fit) {
    h = await js(`const m = document.querySelector('main:not([hidden])'); return Math.ceil(m.getBoundingClientRect().bottom + 8)`);
    await cdp("Emulation.setDeviceMetricsOverride", { width, height: h, deviceScaleFactor: 2, mobile });
    await sleep(200);
  }
  const { data } = await cdp("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width, height: h, scale: 1 } });
  writeFileSync(`${OUT}/${name}.png`, Buffer.from(data, "base64"));
  console.log("saved", name, width + "x" + h);
}

const waitFor = cond => `for (let i = 0; i < 100 && !(${cond}); i++) await new Promise(r => setTimeout(r, 100));`;

await shot("ports", { hash: "#rules", fit: true });
await shot("domains", { hash: "#domains", fit: true });
await shot("add-domain", { hash: "#domains", height: 820, setup: `
  openDomDlg(null); const f = document.querySelector('#domForm');
  f.domain.value = 'grafana.example.com'; f.tls.value = 'wildcard';
  ${waitFor("f.guest.options.length > 1")}
  f.guest.value = '10.10.10.10'; f.guest.dispatchEvent(new Event('change')); f.port.value = '3000';
  f.tls.dispatchEvent(new Event('change')); document.activeElement.blur();` });
await shot("domain-test", { hash: "#domains", height: 820, setup: `
  const d = S.domains.find(x => x.domain === 'broken.invalid');
  runTestUrl('Test: ' + d.domain + ' → ' + d.ip + ':' + d.port, '/api/domains/' + d.id + '/test');
  ${waitFor("!document.querySelector('#testSteps .spin')")}` , wait: 900 });
await shot("wildcard", { hash: "#domains", height: 820, setup: `
  openWcDlg(null); const f = document.querySelector('#wcForm');
  f.zone.value = 'example.com'; f.zone.dispatchEvent(new Event('input'));
  document.querySelector('#wcFields input').value = 'x'.repeat(40); document.activeElement.blur();` });
await shot("debug", { hash: "#debug", height: 900, setup: `
  ${waitFor("document.querySelectorAll('#checks li').length > 3")}
  ${CLEAN}
  for (const d of document.querySelectorAll('details.sec')) d.open = false;` });

ws.close(); chrome.kill();
