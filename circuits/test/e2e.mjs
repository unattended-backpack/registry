#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// The end-to-end test: the real frontend, in headless Chromium, against a
// real deployment on a local anvil, driven through every flow a person uses.
//
//   node test/e2e.mjs            (or `make e2e` from the repository root)
//
// It starts anvil at the fixture emails' time (so the test never ages out),
// deploys the demo stack, honors both the throwaway test key and
// ethereum.org's key, serves `frontend/`, and for each set of fixture emails
// (synthetic, and real when present) walks every write through its two steps:
// sign or prepare, then either copy the transaction to a relayer (here, an
// unrelated anvil account broadcasting the copied JSON) or broadcast it from
// the page's wallet. It connects through the RPC field (refusing a dead one
// first), registers a profile, sees it in the directory, finds it by email
// and secret, sets records both ways and searches for them, renews it,
// rotates its controller, and checks that
// failures read as sentences: a second registration, a reused email, a
// signature from the wrong account, and a wrong secret. Every host but the
// local site and the local chain is blocked, so the run also proves the page
// reaches nothing else. Needs anvil, forge, and Chromium
// (`CHROME=/path/to/chrome` to choose one).

import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dkimKeyHash } from "../scripts/key-hash.mjs";
import { fixtureTime } from "../scripts/fixture-time.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(here, "..", "..");
const FRONTEND = path.join(ROOT, "frontend");
const FIXTURES = path.join(here, "fixtures");

const ANVIL_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ANVIL_1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const ANVIL_1_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
// The relayer: an account with no part in the profile, broadcasting whatever
// the page's copy button produced.
const RELAYER = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
// An RPC endpoint nothing listens on, which the page must refuse.
const DEAD_RPC = "http://127.0.0.1:1";
const REGISTRY = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";
const SECRET = "0x0000000000000000000000000000000000000000000000000000000000007e57";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const cleanup = [];

function freePort () {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function findChrome () {
  const candidates = [process.env.CHROME, "chromium", "chromium-browser", "google-chrome", "google-chrome-stable"];
  for (const c of candidates.filter(Boolean)) {
    try {
      execFileSync("which", [c], { stdio: "ignore" });
      return c;
    } catch (_) {
      // Try the next one.
    }
  }
  throw new Error("No Chromium found; set CHROME to a Chromium or Chrome binary.");
}

const TYPES = {
  ".html": "text/html", ".js": "text/javascript", ".css": "text/css",
  ".json": "application/json", ".dat": "application/octet-stream", ".txt": "text/plain"
};

// Serve `root`, with `overrides` (path to content) standing in for files.
function serve (root, port, overrides = {}) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (overrides[url.pathname] !== undefined) {
      res.writeHead(200, { "content-type": TYPES[path.extname(url.pathname)] || "text/plain" });
      res.end(overrides[url.pathname]);
      return;
    }
    const file = path.join(root, decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname));
    if (!file.startsWith(root) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}

async function rpc (url, method, params = []) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  const j = await r.json();
  if (j.error) {
    throw new Error(`${method}: ${j.error.message}`);
  }
  return j.result;
}

// Relay a prepared transaction exactly as the page's copy button hands it
// over, whole, from an account unrelated to the profile, as any relayer would.
async function relay (url, json, name) {
  const tx = JSON.parse(json);
  if (tx.chainId !== "0x7a69" || tx.to !== REGISTRY || tx.value !== "0x0" || !/^0x[0-9a-f]+$/.test(tx.data)) {
    throw new Error(`${name}: the copied transaction is malformed: ${json.slice(0, 200)}`);
  }
  const hash = await rpc(url, "eth_sendTransaction", [{ from: RELAYER, ...tx }]);
  let receipt = null;
  for (let i = 0; i < 50 && !receipt; i++) {
    receipt = await rpc(url, "eth_getTransactionReceipt", [hash]);
    if (!receipt) {
      await sleep(100);
    }
  }
  if (!receipt || receipt.status !== "0x1") {
    throw new Error(`${name}: the relayed ${tx.about.action} failed on chain (status ${receipt?.status})`);
  }
  return receipt;
}

async function startChain () {
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const anvil = spawn("anvil", ["--port", String(port), "--timestamp", String(fixtureTime()), "--silent"], { stdio: "ignore" });
  cleanup.push(() => anvil.kill());
  for (let i = 0; i < 50 && !(await rpc(url, "eth_chainId").catch(() => null)); i++) {
    await sleep(200);
  }
  const testKey = fs.readFileSync(path.join(FIXTURES, "test-dkim.txt"), "utf8");
  const gmailKey = fs.readFileSync(path.join(FIXTURES, "gmail._domainkey.ethereum.org.txt"), "utf8");
  const hashes = [await dkimKeyHash(testKey), await dkimKeyHash(gmailKey)].join(",");
  execFileSync("forge", [
    "script", "script/DeployLocal.s.sol", "--rpc-url", url, "--broadcast",
    "--sender", ANVIL_1, "--private-key", ANVIL_1_KEY
  ], {
    cwd: path.join(ROOT, "contracts"),
    env: { ...process.env, DEMO_KEY_HASHES: hashes, DOMAIN: "ethereum.org" },
    stdio: "ignore"
  });
  return { url, testKey };
}

// A minimal DevTools Protocol client for one page.
async function openBrowser (chrome) {
  const port = await freePort();
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "registry-e2e-"));
  const proc = spawn(chrome, [
    "--headless=new", "--no-sandbox", "--disable-gpu",
    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
    `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "about:blank"
  ], { stdio: "ignore" });
  cleanup.push(async () => {
    const exited = new Promise((r) => proc.once("exit", r));
    proc.kill();
    await Promise.race([exited, sleep(5000)]);
    fs.rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  });
  let ws = null;
  for (let i = 0; i < 100 && !ws; i++) {
    try {
      const page = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((t) => t.type === "page");
      if (page) {
        ws = new WebSocket(page.webSocketDebuggerUrl);
      }
    } catch (_) {
      await sleep(200);
    }
  }
  await new Promise((r) => ws.addEventListener("open", r));
  let id = 0;
  const pending = new Map();
  const hosts = new Set();
  const errors = [];
  ws.addEventListener("message", (event) => {
    const m = JSON.parse(event.data);
    if (m.id && pending.has(m.id)) {
      pending.get(m.id)(m);
      pending.delete(m.id);
    }
    if (m.method === "Network.requestWillBeSent") {
      hosts.add(new URL(m.params.request.url).host);
    }
    if (m.method === "Runtime.exceptionThrown") {
      errors.push(JSON.stringify(m.params.exceptionDetails).slice(0, 300));
    }
  });
  const send = (method, params = {}) => new Promise((r) => {
    const i = ++id;
    pending.set(i, r);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  for (const domain of ["Network", "Runtime", "Page", "DOM"]) {
    await send(`${domain}.enable`);
  }
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.result.exceptionDetails) {
      throw new Error(JSON.stringify(r.result.exceptionDetails).slice(0, 400));
    }
    return r.result.result.value;
  };
  return { send, evaluate, hosts, errors };
}

async function flow (page, site, chain, { name, email }) {
  const { send, evaluate } = page;
  const text = async (sel) => {
    const t = await evaluate(`document.querySelector(${JSON.stringify(sel)})?.textContent ?? null`);
    if (t === null) {
      throw new Error(`${name}: nothing matches ${sel}; status "${await evaluate("document.getElementById('status').textContent")}"`);
    }
    return t;
  };
  const click = (sel) => evaluate(`document.querySelector(${JSON.stringify(sel)}).click()`);
  // Fill a field as a person would, so the page hears the input.
  const fill = (sel, v) => evaluate(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); `
    + `el.value = ${JSON.stringify(v)}; el.dispatchEvent(new Event("input", { bubbles: true })); })()`);
  const tab = (t) => click(`#tabs button[data-tab="${t}"]`);
  const waitFor = async (sel, re, seconds = 240) => {
    for (const started = Date.now(); Date.now() - started < seconds * 1000; await sleep(500)) {
      const t = await evaluate(`document.querySelector(${JSON.stringify(sel)})?.textContent ?? ""`);
      if (re.test(t)) {
        return t;
      }
    }
    throw new Error(`${name}: waited for ${sel} to match ${re}; status "${await text("#status")}"; `
      + `text "${await evaluate(`document.querySelector(${JSON.stringify(sel)})?.textContent ?? ""`)}"`);
  };
  const setFile = async (sel, file) => {
    const doc = await send("DOM.getDocument", { depth: -1 });
    const q = await send("DOM.querySelector", { nodeId: doc.result.root.nodeId, selector: sel });
    await send("DOM.setFileInputFiles", { nodeId: q.result.nodeId, files: [file] });
  };
  const eml = (step) => path.join(FIXTURES, `${name}-${step}.eml`);

  // A fresh page with a wallet backed by anvil's unlocked accounts, and no
  // RPC remembered from an earlier run.
  const script = await send("Page.addScriptToEvaluateOnNewDocument", { source: `
    localStorage.removeItem("registry.rpcUrl");
    window.ethereum = { request: async ({ method, params }) => {
      if (method === "eth_requestAccounts") { method = "eth_accounts"; }
      const r = await fetch(${JSON.stringify(chain.url)}, { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params || [] }) });
      const j = await r.json();
      if (j.error) {
        throw Object.assign(new Error(j.error.message), { code: j.error.code, data: j.error.data });
      }
      return j.result;
    }, on () {}, removeListener () {} };` });
  // A headless page holds no focus, and the clipboard serves only a focused
  // page that may use it.
  const granted = await send("Browser.grantPermissions", {
    origin: new URL(site).origin, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"]
  });
  if (granted.error) {
    throw new Error("Could not grant the clipboard: " + granted.error.message);
  }
  await send("Emulation.setFocusEmulationEnabled", { enabled: true });
  await send("Page.navigate", { url: site });
  await sleep(1500);
  const out = {};

  // The RPC comes first: nothing loads without it, a dead endpoint is
  // explained, and a live one loads the directory at once.
  await waitFor("#profiles", /Enter an RPC URL above/, 10);
  await fill("#rpcUrl", DEAD_RPC);
  await click("#rpcConnect");
  await waitFor("#netStatus", new RegExp(`Could not reach ${DEAD_RPC.replace(/\./g, "\\.")}`), 30);
  await fill("#rpcUrl", chain.url);
  await click("#rpcConnect");
  await waitFor("#netStatus", /Connected at block/, 30);
  await waitFor("#profiles", /No profiles are registered yet|Status\s*(active|lapsed|former EF)/, 30);
  const card = (id) => `#profiles .profile[data-id="${id}"]`;
  const search = (q) => evaluate(`(() => { const s = document.getElementById("search"); `
    + `s.value = ${JSON.stringify(q)}; s.dispatchEvent(new Event("input")); })()`);
  const visible = (id) => evaluate(`!document.querySelector(${JSON.stringify(card(id))}).hidden`);

  // Step two of every write: the prepared transaction, simulated, then either
  // copied to the relayer or broadcast from the page's wallet.
  const prepared = async (mount) => {
    await waitFor(`${mount} .sbStatus`, /succeeds if broadcast now/);
    await click(`${mount} .sbCopy`);
    await waitFor(`${mount} .sbStatus`, /Copied|Could not copy/, 10);
    return await text(`${mount} .sbOut`);
  };
  const broadcast = async (mount) => {
    await prepared(mount);
    await click(`${mount} .sbBroadcast`);
    return await waitFor(`${mount} .sbStatus`, /Broadcast from 0x.*included in block|Broadcast failed/);
  };
  const broadcastOk = async (mount, what) => {
    const t = await broadcast(mount);
    if (!/included in block/.test(t)) {
      throw new Error(`${name}: ${what}: ${t}`);
    }
    return t;
  };

  // Register, relayed: no signature, no wallet; the copied transaction is all
  // a relayer needs.
  await tab("register");
  await fill("#regSecret", SECRET);
  await evaluate("document.getElementById('regSaved').checked = true");
  await fill("#regController", ANVIL_0);
  await fill("#regEmail", email);
  await click("#regBuildCommand");

  // The subject block holds the exact subject and nothing else; the profile
  // id it will create shows apart from it.
  const subject = await text("#regCommand");
  if (!/^Set controller to 0x[0-9a-f]{64}$/.test(subject)) {
    throw new Error(`${name}: the subject block holds more than the subject: "${subject}"`);
  }
  const expectedId = await waitFor("#regProfile", /Your profile id\s*0x[0-9a-f]{64}/, 10);
  await setFile("#registerProofMount .pbFile", eml("register"));
  await click("#registerProofMount .pbProve");
  out.proof = (await waitFor("#registerProofMount .pbStatus", /DKIM key: honored/)).split("\n")[0];
  await click("#regPrepare");
  const id = JSON.parse(await prepared("#regSigned")).about.profileId;
  if (!expectedId.includes(id)) {
    throw new Error(`${name}: the page previewed a profile id other than the one registered`);
  }
  await relay(chain.url, await text("#regSigned .sbOut"), name);

  // Preparing it again now explains why it would fail.
  await click("#regPrepare");
  await waitFor("#regSigned .sbStatus", /would fail if broadcast now: Profile 0x[0-9a-f]{64} is already registered/, 30);

  // The directory picks it up when Browse opens; then find it by email and
  // secret.
  await tab("browse");
  await waitFor(card(id), /active/);
  await tab("manage");
  await fill("#mEmail", email.toUpperCase());
  await fill("#mSecret", SECRET);
  await click("#mFind");
  await waitFor("#mProfile", /Status\s*active/);

  // Records, in the table: three new ones signed once and broadcast from the
  // page; then an edit, a clear, and an addition signed once and relayed.
  const row = (key) => `#recBody tr[data-key="${key}"]`;
  const addRecord = async (key, value) => {
    await click("#recAdd");
    await fill("#recBody tr.new:last-child .key", key);
    await fill("#recBody tr.new:last-child .val", value);
  };
  await addRecord("url", "https://ethereum.org");
  await addRecord("team", `Protocol ${name}`);
  await addRecord("desk", "Berlin");
  await waitFor("#recSummary", /^3 added\. One signature covers every change\.$/, 10);
  await click("#recSign");
  await broadcastOk("#recSigned", "setting records");
  await waitFor(row("desk"), /desk/);
  await fill(`${row("url")} .val`, "https://ethereum.foundation");
  await click(`${row("desk")} .rm`);
  await addRecord("com.github", "ethereum");
  await waitFor("#recSummary", /^1 edited, 1 added, 1 cleared\./, 10);

  // A new key repeating one already in the table is refused before signing.
  await addRecord("team", "again");
  await waitFor("#recSummary", /The "team" record is already in the table/, 10);
  if (!(await evaluate("document.getElementById('recSign').disabled"))) {
    throw new Error(`${name}: a duplicate key left signing enabled`);
  }
  await click("#recBody tr.new:last-child .rm");
  await waitFor("#recSummary", /^1 edited, 1 added, 1 cleared\./, 10);
  await click("#recSign");
  const batchJson = await prepared("#recSigned");
  if (JSON.parse(batchJson).about.records.length !== 3) {
    throw new Error(`${name}: the batch should carry exactly three records: ${batchJson.slice(0, 300)}`);
  }
  await relay(chain.url, batchJson, name);

  // Browse shows every record in full, the custom key included and the
  // cleared one gone, and the search narrows the grid live.
  await tab("browse");
  const shown = await waitFor(card(id),
    new RegExp(`url.*https://ethereum\\.foundation.*com\\.github.*ethereum.*team.*Protocol ${name}`, "s"));
  if (/desk|Berlin/.test(shown)) {
    throw new Error(`${name}: a cleared record still shows`);
  }
  if (!shown.includes(id) || !shown.includes(ANVIL_0)) {
    throw new Error(`${name}: the card truncates the id or the controller`);
  }

  // The copy button beside the id copies the id itself.
  const copyId = JSON.stringify(`${card(id)} button.copy[aria-label="Copy ID"]`);
  await click(`${card(id)} button.copy[aria-label="Copy ID"]`);
  let copied = "";
  for (let i = 0; i < 50 && !copied; i++, await sleep(100)) {
    copied = await evaluate(`(() => { const b = document.querySelector(${copyId}); `
      + `return b.classList.contains("copied") ? "copied" : (b.classList.contains("failed") ? "failed" : ""); })()`);
  }
  if (copied !== "copied") {
    throw new Error(`${name}: copying the id ${copied ? "reported failure" : "never finished"}`);
  }
  const clipboard = await evaluate("navigator.clipboard.readText()");
  if (clipboard !== id) {
    throw new Error(`${name}: the clipboard holds "${clipboard}", not the id`);
  }
  await search(`protocol ${name.toUpperCase()}`);
  await waitFor("#profileCount", /^1 of \d+ profiles?$/, 10);
  if (!(await visible(id))) {
    throw new Error(`${name}: the search hid the profile it should match`);
  }
  await search("no such record anywhere");
  await waitFor("#profiles", /No profile matches that search/, 10);
  await search("");
  await waitFor("#profileCount", /^\d+ profiles?$/, 10);
  await tab("manage");

  // Renew with the current controller, broadcast from the page.
  if (await evaluate("document.getElementById('rController').value") !== ANVIL_0) {
    throw new Error(`${name}: renewal did not default to the current controller`);
  }
  await setFile("#rotateProofMount .pbFile", eml("renew"));
  await click("#rotateProofMount .pbProve");
  await waitFor("#rotateProofMount .pbStatus", /DKIM key: honored/);
  await click("#rSign");
  await broadcastOk("#rotSigned", "renewing");

  // The same email again: the simulation explains the refusal, and a
  // broadcast anyway comes back through the wallet explained the same way.
  await click("#rSign");
  await waitFor("#rotSigned .sbStatus", /would fail if broadcast now: This email has already been used/, 30);
  await click("#rotSigned .sbBroadcast");
  await waitFor("#rotSigned .sbStatus", /Broadcast failed: This email has already been used/, 30);

  // Rotate to anvil's second account, relayed.
  await fill("#rController", ANVIL_1);
  await setFile("#rotateProofMount .pbFile", eml("rotate"));
  await click("#rotateProofMount .pbProve");
  await waitFor("#rotateProofMount .pbStatus", /Authorizes: 0x7099/);
  await click("#rSign");
  await relay(chain.url, await prepared("#rotSigned"), name);
  await click("#mFind");
  await waitFor("#mProfile", /Controller\s*0x7099/);
  out.after = await evaluate(`[...document.querySelectorAll("#mProfile dt")]`
    + `.map((dt) => dt.textContent + ": " + dt.nextElementSibling.textContent.trim()).join("; ")`);

  // The wallet's account is no longer the controller, so it cannot sign.
  await fill(`${row("url")} .val`, "https://example.org");
  await click("#recSign");
  await waitFor("#status", /is not this profile's controller/, 30);

  // A wrong secret is refused before any proving starts.
  await fill("#mSecret", "0x1234");
  await click("#rotateProofMount .pbProve");
  await waitFor("#rotateProofMount .pbStatus", /Proving failed: The email's subject reads/, 30);

  await send("Page.removeScriptToEvaluateOnNewDocument", { identifier: script.result.identifier });
  return { id, ...out };
}

async function main () {
  const chrome = findChrome();
  const chain = await startChain();
  const sitePort = await freePort();
  // The shipped config.js names its own deployment; the test serves one
  // naming this chain's, with the throwaway key the synthetic emails need.
  const shipped = fs.readFileSync(path.join(FRONTEND, "config.js"), "utf8");
  const testConfig = shipped + `
window.REGISTRY_CONFIG = { ...window.REGISTRY_CONFIG, chainId: 31337,
  registryAddress: ${JSON.stringify(REGISTRY)}, deployBlock: 0,
  dkimKeys: { ...window.REGISTRY_CONFIG.dkimKeys, test: ${JSON.stringify(chain.testKey.trim())} } };
`;
  const server = await serve(FRONTEND, sitePort, { "/config.js": testConfig });
  cleanup.push(() => server.close());
  const page = await openBrowser(chrome);
  const site = `http://127.0.0.1:${sitePort}/index.html`;

  const runs = [{ name: "synthetic", email: "alice@ethereum.org" }];
  if (fs.existsSync(path.join(FIXTURES, "ethereum-org-private-register.eml"))) {
    runs.push({ name: "ethereum-org-private", email: "tim.clancy@ethereum.org" });
  }
  for (const run of runs) {
    const started = Date.now();
    const result = await flow(page, site, chain, run);
    console.log(`ok ${run.name}: ${((Date.now() - started) / 1000).toFixed(0)}s, ${result.proof} `
      + `profile ${result.id.slice(0, 10)}…; ${result.after}`);
  }
  const allowed = new Set([`127.0.0.1:${sitePort}`, new URL(chain.url).host, new URL(DEAD_RPC).host]);
  const strays = [...page.hosts].filter((h) => !allowed.has(h));
  if (strays.length) {
    throw new Error("The page contacted other hosts: " + strays.join(", "));
  }
  if (page.errors.length) {
    throw new Error("The page threw: " + page.errors.join(" | "));
  }
  console.log(`ok the page contacted only the site and the chain (${[...page.hosts].join(", ")})`);
}

// Tear everything down; a failure to clean up is reported, never mistaken for
// a test failure.
async function teardown () {
  for (const f of cleanup.reverse()) {
    try {
      await f();
    } catch (e) {
      console.error("warning: cleanup: " + (e.message || e));
    }
  }
}

main()
  .then(async () => {
    await teardown();
    process.exit(0);
  })
  .catch(async (e) => {
    console.error("not ok " + (e.message || e));
    await teardown();
    process.exit(1);
  });
