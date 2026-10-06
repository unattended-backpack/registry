// The contract layer: read-only browsing over the configured RPC, signatures
// through the connected wallet, and every write as a prepared transaction a
// person can copy to any relayer or broadcast themselves. Everything here is
// client-side; no server ever sees an email, a key, or a signature.

const E = () => window.ethers;

// The deployment comes from `config.js` alone. The one thing a visitor
// supplies is the RPC endpoint, which stays in this browser.
const RPC_KEY = "registry.rpcUrl";

function storedRpcUrl () {
  try {
    return localStorage.getItem(RPC_KEY) || "";
  } catch (_) {
    return "";
  }
}

function loadConfig () {
  return { ...(window.REGISTRY_CONFIG || {}), rpcUrl: storedRpcUrl() };
}

function saveRpcUrl (url) {
  try {
    localStorage.setItem(RPC_KEY, url);
    // Earlier versions let the page override the whole deployment; never
    // let a stale override outlive them.
    localStorage.removeItem("registry.config");
  } catch (_) {
    // Storage is unavailable; the endpoint lasts for this visit only.
  }
}

function registryAddress () {
  const cfg = loadConfig();
  if (!cfg.registryAddress) {
    throw new Error("This site's config.js names no Registry address.");
  }
  return E().getAddress(cfg.registryAddress);
}

// One read-only provider per endpoint. Its network is fixed to the
// configured chain; `checkRpc` confirms the endpoint really serves it.
let cachedProvider = null;
function readProvider (url) {
  const cfg = loadConfig();
  const rpcUrl = url || cfg.rpcUrl;
  if (!rpcUrl) {
    throw new Error("Enter your RPC URL at the top of the page first.");
  }
  if (!cachedProvider || cachedProvider.url !== rpcUrl) {
    const network = E().Network.from(Number(cfg.chainId));
    cachedProvider = {
      url: rpcUrl,
      provider: new (E().JsonRpcProvider)(rpcUrl, network, { staticNetwork: network })
    };
  }
  return cachedProvider.provider;
}

function readContract () {
  return new (E().Contract)(registryAddress(), window.REGISTRY_ABI, readProvider());
}

/**
  Check an RPC endpoint before using it: that it answers, that it serves the
  configured chain, and that the Registry exists there. Resolves to the
  latest block number; saves the endpoint once it passes.
*/
async function checkRpc (url) {
  const cfg = loadConfig();
  let parsed;
  try {
    parsed = new URL(url);
  } catch (_) {
    throw new Error("That is not a URL. It should look like http://127.0.0.1:8545.");
  }
  if (!/^https?:$/.test(parsed.protocol)) {
    throw new Error("The RPC URL must start with http:// or https://.");
  }
  const provider = readProvider(url);
  let chainId;
  try {
    chainId = Number(await provider.send("eth_chainId", []));
  } catch (e) {
    throw new Error(`Could not reach ${url}. Check that the node is running and allows `
      + "requests from this page (CORS).");
  }
  if (chainId !== Number(cfg.chainId)) {
    throw new Error(`That RPC serves chain ${chainId}, but this Registry lives on chain `
      + `${cfg.chainId}.`);
  }
  const code = await provider.getCode(registryAddress());
  if (!code || code === "0x") {
    throw new Error(`There is no Registry at ${registryAddress()} on chain ${chainId}. `
      + "Is the node fully synced?");
  }
  const block = await provider.getBlockNumber();
  saveRpcUrl(url);
  return block;
}

const iface = () => new (E().Interface)(window.REGISTRY_ABI);

// Connect an injected wallet and return the signer for the account selected
// right now, checking the chain.
async function connectWallet () {
  if (!window.ethereum) {
    throw new Error("No injected wallet found. Install one, or copy the "
      + "prepared transaction to a relayer from another device.");
  }
  const cfg = loadConfig();
  const provider = new (E().BrowserProvider)(window.ethereum);
  await provider.send("eth_requestAccounts", []);
  const net = await provider.getNetwork();
  if (Number(net.chainId) !== Number(cfg.chainId)) {
    throw new Error(`Your wallet is on chain ${net.chainId}; the Registry is on `
      + `chain ${cfg.chainId}. Switch networks in your wallet and try again.`);
  }
  return await provider.getSigner();
}

// The EIP-712 domain, built to match the contract's signing domain exactly.
function eip712Domain () {
  const cfg = loadConfig();
  return {
    name: "Registry",
    version: "1",
    chainId: Number(cfg.chainId),
    verifyingContract: registryAddress()
  };
}

// --- Explaining failures ----------------------------------------------------

const week = (t) => new Date(Number(t) * 1000).toISOString().slice(0, 10);

// What each Registry error means, and what to do about it.
const ERRORS = {
  ZeroAddress: () => "The controller cannot be the zero address.",
  EmptyDomain: () => "The Registry was deployed without a domain.",
  NotManagement: () => "Only management can do this. Anyone may flag a profile inactive, "
    + "but only once it has lapsed.",
  NotPendingManagement: () => "Only the pending management can accept the handover.",
  NotController: () => "Only the profile's controller can do this.",
  UnknownProfile: ([id]) => `No profile is registered with id ${id}.`,
  AlreadyRegistered: ([id]) => `Profile ${id} is already registered. To extend it, `
    + "renew it from Manage.",
  InactiveProfile: ([id]) => `Profile ${id} has been flagged inactive (former EF). It is `
    + "read-only and cannot renew; register a fresh profile under a new secret.",
  LapsedProfile: ([id]) => `Profile ${id} has lapsed and is read-only. Renew it with a `
    + "fresh email to write records again.",
  WrongDomain: ([domain]) => `This email comes from ${domain}, which this Registry does not accept.`,
  InvalidDKIMPublicKeyHash: ([hash]) => "The DKIM key that signed this email is not honored by this "
    + `Registry (key hash ${hash}). Management must approve it first.`,
  EmailAlreadyUsed: () => "This email has already been used. Send a fresh email.",
  StaleEmail: ([t, last]) => `This email (week of ${week(t)}) predates the last email honored for `
    + `this profile (week of ${week(last)}). Use a newer email.`,
  ExpiredEmail: ([t]) => `This email (week of ${week(t)}) is more than five weeks old. Send a fresh one.`,
  InvalidEmailProof: () => "The proof does not verify for this controller, this Registry, and this "
    + "chain. Prove the email again for exactly this controller and Registry.",
  InvalidControllerSignature: () => "The signature is not the profile's current controller's, or it "
    + "signs a different email or record. Sign again with the current controller.",
  InvalidKey: ([key]) => `Record keys cannot be empty or contain spaces ("${key}").`,
  LengthMismatch: () => "The record keys and values do not pair up. Sign the records again."
};

// Find revert data anywhere in the layers of error objects wallets and
// providers wrap around it.
function revertData (e, depth = 0) {
  if (!e || depth > 6) {
    return null;
  }
  if (typeof e === "string") {
    return /^0x[0-9a-fA-F]{8}/.test(e) ? e : null;
  }
  if (typeof e !== "object") {
    return null;
  }
  for (const k of ["data", "error", "info", "cause", "originalError", "payload"]) {
    const found = revertData(e[k], depth + 1);
    if (found) {
      return found;
    }
  }
  return null;
}

/**
  Turn any error from the wallet, the provider, or the Registry into a
  sentence a person can act on.
*/
function explain (e) {
  if (!e) {
    return "Something failed without saying why.";
  }
  const code = e.code ?? e.info?.error?.code ?? e.error?.code;
  if (code === "ACTION_REJECTED" || code === 4001) {
    return "You declined in your wallet.";
  }
  if (code === "INSUFFICIENT_FUNDS" || /insufficient funds/i.test(e.message || "")) {
    return "The account broadcasting this has too little ETH to pay for gas. Switch to a funded "
      + "account, or copy the transaction to a relayer.";
  }
  if (e.revert && ERRORS[e.revert.name]) {
    return ERRORS[e.revert.name](e.revert.args);
  }
  const data = revertData(e);
  if (data) {
    try {
      const parsed = iface().parseError(data);
      if (parsed && ERRORS[parsed.name]) {
        return ERRORS[parsed.name](parsed.args);
      }
    } catch (_) {
      // Not a Registry error; fall through.
    }
  }
  return e.shortMessage || e.message || String(e);
}

// --- Reads ----------------------------------------------------------------------

// Every record key ever written, by profile, from the Registry's
// TextChanged logs (one profile's, given an id). Logs are read in spans, so
// a node that bounds the range of one query still answers. Resolves to null
// when the node will not serve logs at all.
const LOG_SPAN = 50000;
async function recordKeys (id) {
  const cfg = loadConfig();
  const provider = readProvider();
  const topic = iface().getEvent("TextChanged").topicHash;
  try {
    const latest = await provider.getBlockNumber();
    const spans = [];
    for (let from = Number(cfg.deployBlock || 0); from <= latest; from += LOG_SPAN) {
      spans.push(provider.getLogs({
        address: registryAddress(),
        topics: id ? [topic, id] : [topic],
        fromBlock: from,
        toBlock: Math.min(from + LOG_SPAN - 1, latest)
      }));
    }
    const keys = new Map();
    for (const log of (await Promise.all(spans)).flat()) {
      const { args } = iface().parseLog(log);
      if (!keys.has(args.profileId)) {
        keys.set(args.profileId, new Set());
      }
      keys.get(args.profileId).add(args.key);
    }
    return keys;
  } catch (_) {
    return null;
  }
}

// The default keys first, in their usual order, then the rest by name.
function orderKeys (keys) {
  const defaults = window.REGISTRY_DEFAULT_KEYS;
  const rest = [...keys].filter((k) => !defaults.includes(k)).sort();
  return [...defaults.filter((k) => keys.has(k)), ...rest];
}

// Enumerate the directory: every registered profile with its standing and
// all of its records. The reads go out together and the provider batches
// them, which suits a directory of the scale of one foundation's personnel.
async function listProfiles () {
  const c = readContract();
  const count = Number(await c.profileCount());
  const [ids, keys] = await Promise.all([
    Promise.all(Array.from({ length: count }, (_, i) => c.profileIds(i))),
    recordKeys()
  ]);
  return await Promise.all(ids.map((id) => resolveProfile(id, c, keys)));
}

// Resolve one profile by id: its controller, status, expiry, and records. An
// id reveals no owner; only its owner can compute it. Without the logs, only
// the default keys can be read.
async function resolveProfile (id, contract, knownKeys) {
  const c = contract || readContract();
  const keyMap = knownKeys === undefined ? await recordKeys(id) : knownKeys;
  const keys = keyMap
    ? orderKeys(keyMap.get(id) || new Set())
    : window.REGISTRY_DEFAULT_KEYS;
  const [p, live, expiresAt, values] = await Promise.all([
    c.profiles(id), c.isActive(id), c.expiresAt(id),
    Promise.all(keys.map((k) => c.text(id, k)))
  ]);
  if (Number(p.registeredAt) === 0) {
    throw new Error("No profile is registered with id " + id + ".");
  }
  const records = {};
  keys.forEach((k, i) => {
    if (values[i]) {
      records[k] = values[i];
    }
  });
  return {
    id,
    controller: p.controller,
    flaggedInactive: !p.active,
    active: live,
    expiresAt: Number(expiresAt),
    registeredAt: Number(p.registeredAt),
    lastTimestamp: Number(p.lastTimestamp),
    records
  };
}

// Read a profile's current controller.
async function readController (id) {
  const p = await readContract().profiles(id);
  if (Number(p.registeredAt) === 0) {
    throw new Error("No profile is registered with id " + id + ".");
  }
  return p.controller;
}

// Read a profile's current signed-write nonce.
async function readNonce (id) {
  return await readContract().nonces(id);
}

// Whether the Registry currently honors a DKIM key hash.
async function isKeyHonored (publicKeyHash) {
  return await readContract().dkimPublicKeyHashes(publicKeyHash);
}

// --- Signatures ---------------------------------------------------------------

// Refuse to sign as anyone but the profile's current controller.
async function requireController (signer, id) {
  const [who, controller] = await Promise.all([signer.getAddress(), readController(id)]);
  if (E().getAddress(who) !== E().getAddress(controller)) {
    throw new Error(`The connected account ${who} is not this profile's controller `
      + `(${controller}). Switch accounts in your wallet and sign again.`);
  }
  return who;
}

// The controller signs one batch of record writes, in order, at the profile's
// next nonce: one signature however many records change.
async function signSetTexts (signer, id, keys, values) {
  const signerAddress = await requireController(signer, id);
  const nonce = await readNonce(id);
  const signature = await signer.signTypedData(
    eip712Domain(), window.REGISTRY_EIP712.setTexts, { profileId: id, keys, values, nonce }
  );
  return { signature, nonce: nonce.toString(), signer: signerAddress };
}

// The current controller signs off on one email, by its nullifier.
async function signEmailAuthorization (signer, id, emailNullifier) {
  const signerAddress = await requireController(signer, id);
  const signature = await signer.signTypedData(
    eip712Domain(), window.REGISTRY_EIP712.emailAuthorization, { emailNullifier }
  );
  return { signature, signer: signerAddress };
}

// --- Prepared transactions ---------------------------------------------------------

// A prepared transaction: exactly what any relayer, or the person's own wallet,
// broadcasts, as a standard transaction request with JSON-RPC quantities, so
// any tool that sends one takes it whole. `about` describes it for people, and
// is kept apart so nothing in it can ever be mistaken for a transaction field.
function prepared (fn, args, action, details) {
  const cfg = loadConfig();
  return {
    chainId: E().toQuantity(Number(cfg.chainId)),
    to: registryAddress(),
    value: "0x0",
    data: iface().encodeFunctionData(fn, args),
    about: { action, ...details }
  };
}

const tuple = (proof) => ({
  domainName: proof.domainName,
  publicKeyHash: proof.publicKeyHash,
  timestamp: BigInt(proof.timestamp),
  emailNullifier: proof.emailNullifier,
  profileId: proof.profileId,
  proof: proof.proof
});

function prepareRegister (proof, controller) {
  return prepared("register", [tuple(proof), E().getAddress(controller)],
    "register(proof, controller)",
    { profileId: proof.profileId, controller: E().getAddress(controller) });
}

function prepareSetController (proof, controller, signed) {
  return prepared("setController", [tuple(proof), E().getAddress(controller), signed.signature],
    "setController(proof, controller, signature)",
    { profileId: proof.profileId, controller: E().getAddress(controller), signedBy: signed.signer });
}

function prepareSetTextsSigned (id, keys, values, signed) {
  const records = keys.map((key, i) => ({ key, value: values[i] }));
  return prepared("setTextsSigned", [id, keys, values, signed.signature],
    "setTextsSigned(profileId, keys, values, signature)",
    { profileId: id, records, nonce: signed.nonce, signedBy: signed.signer });
}

// Simulate a prepared transaction against the chain, as any relayer would
// send it. Resolves to a gas estimate; rejects with an explained error.
async function simulate (tx) {
  const provider = readProvider();
  try {
    await provider.call({ to: tx.to, data: tx.data });
    return (await provider.estimateGas({ to: tx.to, data: tx.data })).toString();
  } catch (e) {
    throw new Error(explain(e));
  }
}

// Broadcast a prepared transaction from whichever wallet account is selected
// now. Resolves to the transaction hash, the block, and the sender.
async function broadcast (tx) {
  const signer = await connectWallet();
  const from = await signer.getAddress();
  const response = await signer.sendTransaction({ to: tx.to, data: tx.data, value: 0 });
  const receipt = await response.wait();
  if (!receipt || receipt.status !== 1) {
    throw new Error(`The transaction ${response.hash} failed on chain.`);
  }
  return { hash: response.hash, blockNumber: receipt.blockNumber, from };
}

window.Registry = {
  loadConfig, checkRpc, connectWallet, explain,
  listProfiles, resolveProfile, readController, readNonce, isKeyHonored,
  signSetTexts, signEmailAuthorization,
  prepareRegister, prepareSetController, prepareSetTextsSigned,
  simulate, broadcast
};
