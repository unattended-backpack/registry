// UI wiring, as a module. Small and dependency-free: it reads the directory
// over the visitor's own RPC, signs through the wallet, prepares every write as a complete
// transaction for any relayer or the wallet to broadcast, and drives the local
// prover. It computes subject lines and profile ids with the same module the
// prover uses. The profile secret lives only in this page and the proving
// worker; nothing here sends it anywhere. There is no framework and no build
// step.

import {
  generateSalt, parseSalt, privateProfileId, privateSubject
} from "./email-input.js";

const $ = (id) => document.getElementById(id);
const R = window.Registry;
const E = window.ethers;

const state = {
  connected: false,
  profile: null,
  registerProof: null,
  rotateProof: null
};

// JSON.stringify that survives BigInt, for showing proofs and signatures.
const jstr = (o) => JSON.stringify(
  o, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2
);

function setStatus (msg, kind) {
  const s = $("status");
  s.textContent = msg || "";
  s.className = "status" + (kind ? " " + kind : "");
}

function escapeHtml (s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

const day = (t) => new Date(Number(t) * 1000).toISOString().slice(0, 10);

// The authorization a subject line commits to, from the configured Registry.
function authorization (controller, salt) {
  const cfg = R.loadConfig();
  if (!cfg.registryAddress) {
    throw new Error("This site's config.js names no Registry address.");
  }
  parseSalt(salt);
  return {
    controller: E.getAddress(controller),
    chainId: String(cfg.chainId),
    registry: E.getAddress(cfg.registryAddress),
    salt
  };
}

// Refuse a proof that binds a different authorization than this action
// needs, before any wallet is asked to sign or pay.
function requireBinding (binding, controller) {
  const cfg = R.loadConfig();
  if (binding.controller && binding.controller !== E.getAddress(controller)) {
    throw new Error(`This proof authorizes ${binding.controller}, not ${controller}.`);
  }
  if (binding.registry && binding.registry !== E.getAddress(cfg.registryAddress)) {
    throw new Error(`This proof is for the Registry at ${binding.registry}.`);
  }
  if (binding.chainId && binding.chainId !== String(cfg.chainId)) {
    throw new Error(`This proof is for chain ${binding.chainId}.`);
  }
}

// --- Copying --------------------------------------------------------------
const COPY_ICON = "<svg viewBox='0 0 16 16' width='14' height='14' aria-hidden='true'>"
  + "<rect x='5.5' y='5.5' width='8.5' height='8.5' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.4'/>"
  + "<path d='M10.5 5.5V3.5A1.5 1.5 0 0 0 9 2H3.5A1.5 1.5 0 0 0 2 3.5V9a1.5 1.5 0 0 0 1.5 1.5h2' "
  + "fill='none' stroke='currentColor' stroke-width='1.4'/></svg>";
const CHECK_ICON = "<svg viewBox='0 0 16 16' width='14' height='14' aria-hidden='true'>"
  + "<path d='M3 8.5l3 3 7-7' fill='none' stroke='currentColor' stroke-width='1.8' "
  + "stroke-linecap='round' stroke-linejoin='round'/></svg>";

// Copy text to the clipboard, falling back to a hidden selection where the
// clipboard API is unavailable (an insecure origin, a denied permission).
// Resolves to whether it worked.
async function copyText (text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.cssText = "position:fixed;top:0;left:0;opacity:0";
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (_) {
      ok = false;
    }
    area.remove();
    return ok;
  }
}

function copyButton (value, what) {
  const label = escapeHtml("Copy " + what);
  return `<button type="button" class="copy" data-copy="${escapeHtml(value)}" `
    + `aria-label="${label}" title="${label}">${COPY_ICON}</button>`;
}

// Every copy button on the page, present or future: copy, then confirm.
document.addEventListener("click", async (event) => {
  const button = event.target.closest("button.copy");
  if (!button) {
    return;
  }
  const ok = await copyText(button.dataset.copy);
  button.classList.toggle("copied", ok);
  button.classList.toggle("failed", !ok);
  button.innerHTML = ok ? CHECK_ICON : COPY_ICON;
  button.title = ok ? "Copied" : "Could not copy; select the text instead";
  clearTimeout(button.resetTimer);
  button.resetTimer = setTimeout(() => {
    button.classList.remove("copied", "failed");
    button.innerHTML = COPY_ICON;
    button.title = button.getAttribute("aria-label");
  }, 1600);
});

// --- Key-value rows -------------------------------------------------------
// Every field on the page is one of these rows, the same way everywhere.
// Addresses and hashes show in full, in monospace, with a copy button; web
// links become links; everything else is text. Nothing is ever fetched to
// render a row, avatars included.
const HEX_VALUE = /^0x[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$/;

function linkOrText (v) {
  return /^https?:\/\/[^\s"'<>]+$/i.test(v)
    ? `<a href="${escapeHtml(v)}" target="_blank" rel="noopener noreferrer">${escapeHtml(v)}</a>`
    : escapeHtml(v);
}

function kvRow (key, value, html) {
  const hex = HEX_VALUE.test(value);
  const shown = html ?? (hex ? escapeHtml(value) : linkOrText(value));
  return `<dt>${escapeHtml(key)}</dt><dd><span class="v${hex ? " mono" : ""}">${shown}</span>`
    + `${hex ? copyButton(value, key) : ""}</dd>`;
}

function statusFlag (p) {
  if (p.flaggedInactive) {
    return "<span class='flag former'>former EF</span>";
  }
  return p.active
    ? "<span class='flag active'>active</span>"
    : "<span class='flag lapsed'>lapsed</span>";
}

const standing = (p) => (p.flaggedInactive ? "former EF" : (p.active ? "active" : "lapsed"));

// A profile's own fields, as rows: the same in Browse and in Manage.
function profileRows (p) {
  return kvRow("Status", standing(p), statusFlag(p))
    + kvRow(p.active ? "Renew by" : "Lapsed", day(p.expiresAt))
    + kvRow("ID", p.id)
    + kvRow("Controller", p.controller);
}

// --- Tabs -----------------------------------------------------------------
// The open tab follows the address bar's hash, so a reload keeps it.
document.querySelectorAll("#tabs button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $(b.dataset.tab).classList.add("active");
    history.replaceState(null, "", b.dataset.tab === "browse" ? location.pathname : "#/" + b.dataset.tab);
    setStatus("");
    if (b.dataset.tab === "browse" && state.connected) {
      loadDirectory();
    }
  });
});

// --- Network --------------------------------------------------------------
function netStatus (text, kind) {
  $("netStatus").innerHTML = `<span class="dot${kind ? " " + kind : ""}"></span>`;
  $("netStatus").append(text);
}

async function connect (url) {
  state.connected = false;
  netStatus("Connecting ...");
  try {
    const block = await R.checkRpc(url);
    state.connected = true;
    netStatus(`Connected at block ${block.toLocaleString("en-US")}`, "ok");
    await loadDirectory();
  } catch (e) {
    netStatus(R.explain(e), "err");
    showEmpty("Enter a working RPC URL above to load the directory.");
  }
}

$("rpcForm").addEventListener("submit", (event) => {
  event.preventDefault();
  connect($("rpcUrl").value.trim());
});

// --- Browse ---------------------------------------------------------------
function profileCard (p) {
  const card = document.createElement("article");
  card.className = "profile";
  card.dataset.id = p.id;
  const records = Object.entries(p.records);
  card.innerHTML = `<dl class="kv">${profileRows(p)}</dl>`
    + (records.length
      ? `<dl class="kv records">${records.map(([k, v]) => kvRow(k, v)).join("")}</dl>`
      : "<p class='hint norecords'>No records yet.</p>");
  // Everything a search can match, in one lowercase string.
  card.dataset.search = [...records.flat(), p.controller, p.id, standing(p)]
    .join("\n").toLowerCase();
  return card;
}

// Active profiles first, then lapsed, then former; oldest first within each.
function byStanding (a, b) {
  const rank = (p) => (p.active ? 0 : (p.flaggedInactive ? 2 : 1));
  return rank(a) - rank(b) || a.registeredAt - b.registeredAt;
}

function showEmpty (message) {
  $("profiles").innerHTML = "";
  const p = document.createElement("p");
  p.className = "empty";
  p.textContent = message;
  $("profiles").appendChild(p);
  $("profileCount").textContent = "";
}

// Show only the cards whose records, controller, id, or standing contain
// every word of the search.
function applySearch () {
  const words = $("search").value.toLowerCase().split(/\s+/).filter(Boolean);
  const cards = [...$("profiles").querySelectorAll(".profile")];
  let shown = 0;
  for (const card of cards) {
    const match = words.every((w) => card.dataset.search.includes(w));
    card.hidden = !match;
    shown += match ? 1 : 0;
  }
  const none = $("profiles").querySelector(".nomatch");
  if (none) {
    none.remove();
  }
  if (cards.length && !shown) {
    const p = document.createElement("p");
    p.className = "empty nomatch";
    p.textContent = "No profile matches that search.";
    $("profiles").appendChild(p);
  }
  $("profileCount").textContent = !cards.length
    ? ""
    : (words.length ? `${shown} of ${cards.length} profiles` : `${cards.length} profile${cards.length === 1 ? "" : "s"}`);
}

// Load the whole directory. A newer load supersedes an older one still in
// flight, so a slow read never paints over a fresh one.
let loads = 0;
async function loadDirectory () {
  const mine = ++loads;
  if (!$("profiles").querySelector(".profile")) {
    showEmpty("Loading the directory ...");
  }
  try {
    const list = (await R.listProfiles()).sort(byStanding);
    if (mine !== loads) {
      return;
    }
    if (!list.length) {
      showEmpty("No profiles are registered yet.");
      return;
    }
    $("profiles").innerHTML = "";
    for (const p of list) {
      $("profiles").appendChild(profileCard(p));
    }
    applySearch();
  } catch (e) {
    if (mine === loads) {
      showEmpty("Could not load the directory: " + R.explain(e));
    }
  }
}

$("search").addEventListener("input", applySearch);

// --- A reusable proof block -------------------------------------------------
// Clones the template into `container`. `authorizationFn` returns the
// authorization the email must carry (the secret and the controller);
// `onProof({ proof, binding })` runs whenever the browser proves an email.
function mountProofBlock (container, authorizationFn, onProof) {
  const frag = $("proofBlock").content.cloneNode(true);
  const root = frag.querySelector(".proofblock");
  const fileInput = root.querySelector(".pbFile");
  const proveBtn = root.querySelector(".pbProve");
  const status = root.querySelector(".pbStatus");

  proveBtn.addEventListener("click", async () => {
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      status.textContent = "Choose the .eml file first.";
      return;
    }
    let auth;
    try {
      auth = authorizationFn();
    } catch (e) {
      status.textContent = e.message;
      return;
    }
    let result;
    try {
      const eml = await file.arrayBuffer();
      status.textContent = "Starting the prover ...";
      result = await window.Prove.generateProof(eml, auth, (m) => { status.textContent = m; });
    } catch (e) {
      status.textContent = "Proving failed: " + e.message;
      return;
    }
    const { proof, binding } = result;
    let lines = `Proof ready in ${result.seconds.toFixed(1)}s.`
      + "\nProfile id: " + proof.profileId
      + "\nDomain: " + proof.domainName
      + "\nEmail week: " + day(proof.timestamp)
      + (binding.controller ? "\nAuthorizes: " + binding.controller : "");
    status.textContent = lines;
    onProof({ proof, binding });
    try {
      const honored = await R.isKeyHonored(proof.publicKeyHash);
      lines += honored
        ? "\nDKIM key: honored by the Registry."
        : "\nDKIM key: NOT honored by the Registry (" + proof.publicKeyHash
          + "). Management must honor it before this email can act.";
    } catch (e) {
      lines += "\nDKIM key: not checked (" + R.explain(e) + ")";
    }
    status.textContent = lines;
  });

  container.innerHTML = "";
  container.appendChild(frag);
}

// --- Prepared transactions ------------------------------------------------
// Show a prepared transaction in `container`. It can be copied for any relayer
// at once, or broadcast from whichever account the wallet has selected. It is
// also simulated against the chain, so a transaction that would fail says why
// before anyone pays for it; the verdict is advice, and never blocks a
// broadcast, since the chain may change before it lands. `afterBroadcast` runs
// once it is included.
function showPrepared (container, tx, afterBroadcast) {
  container.innerHTML = "";
  const frag = $("signedBlock").content.cloneNode(true);
  const root = frag.querySelector(".signedblock");
  const out = root.querySelector(".sbOut");
  const status = root.querySelector(".sbStatus");
  const copyTx = root.querySelector(".sbCopy");
  const broadcastButton = root.querySelector(".sbBroadcast");
  container.appendChild(frag);
  out.textContent = jstr(tx);

  copyTx.addEventListener("click", async () => {
    status.textContent = (await copyText(jstr(tx)))
      ? "Copied. Paste it into the relayer of your choice."
      : "Could not copy. Select the transaction above and copy it with your keyboard.";
  });
  broadcastButton.addEventListener("click", async () => {
    let r;
    try {
      broadcastButton.disabled = true;
      status.textContent = "Confirm in your wallet ...";
      r = await R.broadcast(tx);
    } catch (e) {
      broadcastButton.disabled = false;
      status.textContent = "Broadcast failed: " + R.explain(e);
      return;
    }
    status.textContent = `Broadcast from ${r.from}; included in block ${r.blockNumber} (${r.hash}).`;
    if (afterBroadcast) {
      try {
        await afterBroadcast(r);
      } catch (e) {
        setStatus("Included, but refreshing the view failed: " + R.explain(e), "err");
      }
    }
  });

  status.textContent = "Checking it against the chain ...";
  return R.simulate(tx).then(
    (gas) => {
      status.textContent = "It succeeds if broadcast now, for about "
        + `${Number(gas).toLocaleString("en-US")} gas.`;
    },
    (e) => {
      status.textContent = "It would fail if broadcast now: " + e.message;
    }
  );
}

// --- Register -------------------------------------------------------------
$("regNewSecret").addEventListener("click", () => {
  $("regSecret").value = generateSalt();
  $("regSaved").checked = false;
  setStatus("New secret created. Save it before you continue.", "ok");
});

function registerAuthorization () {
  if (!$("regSaved").checked) {
    throw new Error("Save your profile secret first, and tick the box.");
  }
  const c = $("regController").value.trim();
  if (!c) {
    throw new Error("Enter your controller address first.");
  }
  return authorization(c, $("regSecret").value.trim());
}

$("regBuildCommand").addEventListener("click", () => {
  try {
    const auth = registerAuthorization();
    const email = $("regEmail").value.trim();
    // The block holds the subject line alone, exactly as it must be pasted;
    // the profile id it will create sits apart from it.
    $("regCommand").textContent = privateSubject(auth);
    $("regProfile").innerHTML = email
      ? `<dl class="kv">${kvRow("Your profile id", privateProfileId(email, auth.salt))}</dl>`
      : "";
    setStatus("Subject line built. Send the email, then prove it below.", "ok");
  } catch (e) {
    setStatus(R.explain(e), "err");
  }
});

mountProofBlock(
  $("registerProofMount"),
  registerAuthorization,
  (result) => {
    state.registerProof = result;
    $("regPrepare").disabled = false;
    setStatus("Registration proof ready. Prepare the registration.", "ok");
  }
);

$("regPrepare").addEventListener("click", async () => {
  try {
    if (!state.registerProof) {
      throw new Error("Acquire a proof first.");
    }
    const { proof, binding } = state.registerProof;
    const controller = binding.controller || $("regController").value.trim();
    requireBinding(binding, controller);
    const tx = R.prepareRegister(proof, controller);
    setStatus("Registration prepared. Copy it for a relayer, or broadcast it yourself.", "ok");
    await showPrepared($("regSigned"), tx, async () => {
      setStatus("Registered profile " + proof.profileId + ".", "ok");
    });
  } catch (e) {
    setStatus(R.explain(e), "err");
  }
});

// --- Manage: find the profile ---------------------------------------------
async function showProfile (id) {
  const p = await R.resolveProfile(id);
  $("mProfileId").value = id;
  $("mProfile").innerHTML = `<dl class="kv">${profileRows(p)}</dl>`;
  renderRecords(p);
  if (!$("rController").value.trim()) {
    $("rController").value = p.controller;
  }
  return p;
}

$("mFind").addEventListener("click", async () => {
  try {
    const email = $("mEmail").value.trim();
    const secret = $("mSecret").value.trim();
    if (!email || !secret) {
      throw new Error("Enter your email address and your secret.");
    }
    $("recSigned").innerHTML = "";
    await showProfile(privateProfileId(email, secret));
    setStatus("Found your profile.", "ok");
  } catch (e) {
    setStatus(R.explain(e), "err");
  }
});

const profileId = () => {
  const id = $("mProfileId").value.trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(id)) {
    throw new Error("Find your profile first.");
  }
  return id;
};

// --- Manage: records ------------------------------------------------------
// The table holds every record the profile has, each value editable in
// place, plus any new rows. Only what differs from the chain is signed, all
// of it under one signature, as one transaction.
function recordRow (key, value) {
  const tr = document.createElement("tr");
  const fresh = key === null;
  if (fresh) {
    tr.className = "new";
  } else {
    tr.dataset.key = key;
    tr.dataset.original = value;
  }
  tr.innerHTML = "<td>" + (fresh
    ? "<input class='key' list='knownKeys' placeholder='new key' autocomplete='off' spellcheck='false' aria-label='Record key' />"
    : `<span class="key">${escapeHtml(key)}</span>`) + "</td>"
    + `<td><input class="val" autocomplete="off" spellcheck="false" aria-label="Record value" `
    + `placeholder="${fresh ? "value" : "empty clears this record"}" /></td>`
    + `<td><button type="button" class="ghost icon rm" `
    + `aria-label="${fresh ? "Remove this row" : "Clear this record"}" `
    + `title="${fresh ? "Remove this row" : "Clear this record, or restore it"}">×</button></td>`;
  if (!fresh) {
    tr.querySelector(".val").value = value;
  }
  return tr;
}

function renderRecords (p) {
  state.profile = p;
  const body = $("recBody");
  body.innerHTML = "";
  for (const [key, value] of Object.entries(p.records)) {
    body.appendChild(recordRow(key, value));
  }
  if (!body.children.length) {
    body.innerHTML = "<tr class='placeholder'><td colspan='3'>No records yet. Add one below.</td></tr>";
  }
  $("recAdd").disabled = false;
  $("recDiscard").disabled = false;
  updateRecordSummary();
}

// What the table would change, in order: edits and clears of existing
// records, then additions. New keys must be usable and must not repeat a
// key already in the table.
function recordChanges () {
  const out = { keys: [], values: [], problems: [], edited: 0, added: 0, cleared: 0 };
  const seen = new Set();
  for (const tr of $("recBody").querySelectorAll("tr[data-key]")) {
    const key = tr.dataset.key;
    const value = tr.querySelector(".val").value;
    seen.add(key);
    tr.classList.toggle("clearing", value === "");
    tr.classList.toggle("changed", value !== "" && value !== tr.dataset.original);
    if (value !== tr.dataset.original) {
      out.keys.push(key);
      out.values.push(value);
      out[value === "" ? "cleared" : "edited"] += 1;
    }
  }
  for (const tr of $("recBody").querySelectorAll("tr.new")) {
    const key = tr.querySelector(".key").value.trim();
    const value = tr.querySelector(".val").value;
    let problem = null;
    if (!key && value) {
      problem = "Give every new record a key.";
    } else if (key && /\s/.test(key)) {
      problem = `Record keys cannot contain spaces ("${key}").`;
    } else if (key && seen.has(key)) {
      problem = `The "${key}" record is already in the table; edit it there.`;
    } else if (key && !value) {
      problem = `Give the new "${key}" record a value.`;
    }
    tr.classList.toggle("invalid", problem !== null);
    if (problem) {
      out.problems.push(problem);
    } else if (key) {
      seen.add(key);
      out.keys.push(key);
      out.values.push(value);
      out.added += 1;
    }
  }
  return out;
}

function updateRecordSummary () {
  const c = recordChanges();
  const parts = [["edited", c.edited], ["added", c.added], ["cleared", c.cleared]]
    .filter(([, n]) => n).map(([what, n]) => `${n} ${what}`);
  const summary = $("recSummary");
  summary.classList.toggle("err", c.problems.length > 0);
  summary.textContent = c.problems.length
    ? c.problems[0]
    : (c.keys.length ? parts.join(", ") + ". One signature covers every change." : (state.profile ? "No changes yet." : ""));
  $("recSign").disabled = !state.profile || !c.keys.length || c.problems.length > 0;
}

$("recBody").addEventListener("input", updateRecordSummary);
$("recBody").addEventListener("click", (event) => {
  const button = event.target.closest("button.rm");
  if (!button) {
    return;
  }
  const tr = button.closest("tr");
  if (tr.classList.contains("new")) {
    tr.remove();
  } else {
    const input = tr.querySelector(".val");
    input.value = input.value === "" ? tr.dataset.original : "";
  }
  updateRecordSummary();
});

$("recAdd").addEventListener("click", () => {
  const placeholder = $("recBody").querySelector(".placeholder");
  if (placeholder) {
    placeholder.remove();
  }
  const tr = recordRow(null, "");
  $("recBody").appendChild(tr);
  tr.querySelector(".key").focus();
  updateRecordSummary();
});

$("recDiscard").addEventListener("click", () => {
  if (state.profile) {
    renderRecords(state.profile);
  }
});

$("recSign").addEventListener("click", async () => {
  try {
    const id = profileId();
    const { keys, values, problems } = recordChanges();
    if (problems.length) {
      throw new Error(problems[0]);
    }
    if (!keys.length) {
      throw new Error("Change a record first.");
    }
    setStatus("Sign the changes in your wallet, as the profile's controller ...");
    const signer = await R.connectWallet();
    const signed = await R.signSetTexts(signer, id, keys, values);
    const tx = R.prepareSetTextsSigned(id, keys, values, signed);
    setStatus("Changes signed. Copy them for a relayer, or broadcast them yourself.", "ok");
    await showPrepared($("recSigned"), tx, async () => {
      await showProfile(id);
      setStatus(`Records updated: ${keys.join(", ")}.`, "ok");
    });
  } catch (e) {
    setStatus(R.explain(e), "err");
  }
});

// --- Manage: renew or rotate ----------------------------------------------
function renewAuthorization () {
  const c = $("rController").value.trim();
  if (!c) {
    throw new Error("Enter the controller to authorize first.");
  }
  const secret = $("mSecret").value.trim();
  if (!secret) {
    throw new Error("Enter your profile secret above first.");
  }
  return authorization(c, secret);
}

$("rBuildCommand").addEventListener("click", () => {
  try {
    $("rCommand").textContent = privateSubject(renewAuthorization());
    setStatus("Subject line built. Email it as in Register, then prove below.", "ok");
  } catch (e) {
    setStatus(R.explain(e), "err");
  }
});

mountProofBlock(
  $("rotateProofMount"),
  renewAuthorization,
  (result) => {
    state.rotateProof = result;
    $("rSign").disabled = false;
    setStatus("Proof ready. Sign the authorization with the current controller.", "ok");
  }
);

$("rSign").addEventListener("click", async () => {
  try {
    if (!state.rotateProof) {
      throw new Error("Acquire a proof first.");
    }
    const { proof, binding } = state.rotateProof;
    const controller = binding.controller || $("rController").value.trim();
    requireBinding(binding, controller);
    $("mProfileId").value = proof.profileId;
    setStatus("Sign the authorization in your wallet, as the current controller ...");
    const signer = await R.connectWallet();
    const signed = await R.signEmailAuthorization(signer, proof.profileId, proof.emailNullifier);
    const tx = R.prepareSetController(proof, controller, signed);
    setStatus("Authorization signed. Copy it for a relayer, or broadcast it yourself.", "ok");
    await showPrepared($("rotSigned"), tx, async () => {
      await showProfile(proof.profileId);
      setStatus("Done. The profile now authorizes " + controller + ".", "ok");
    });
  } catch (e) {
    setStatus(R.explain(e), "err");
  }
});

// --- Boot -----------------------------------------------------------------
{
  const cfg = R.loadConfig();
  $("netChain").textContent = String(cfg.chainId);
  $("netRegistry").innerHTML = cfg.registryAddress
    ? `<span class="v mono">${escapeHtml(cfg.registryAddress)}</span>${copyButton(cfg.registryAddress, "Registry address")}`
    : "none configured";
  $("knownKeys").innerHTML = window.REGISTRY_DEFAULT_KEYS
    .map((k) => `<option value="${escapeHtml(k)}"></option>`).join("");
  $("domainLabel").textContent = cfg.domain || "ethereum.org";
  const opened = document.querySelector(`#tabs button[data-tab="${location.hash.replace(/^#\/?/, "")}"]`);
  if (opened) {
    opened.click();
  }
  if (cfg.rpcUrl) {
    $("rpcUrl").value = cfg.rpcUrl;
    connect(cfg.rpcUrl);
  }
}
