// The contract layer: read-only browsing over the configured RPC, and writes
// and signatures through the connected wallet. Everything here is client-side;
// no server ever sees an email, a key, or a signature.

const E = () => window.ethers;

// Merge the shipped defaults with any runtime overrides saved in localStorage.
function loadConfig () {
  const base = window.REGISTRY_CONFIG || {};
  let saved = {};
  try {
    saved = JSON.parse(localStorage.getItem("registry.config") || "{}");
  } catch (_) {
    saved = {};
  }
  return { ...base, ...saved };
}

function saveConfig (patch) {
  let saved = {};
  try {
    saved = JSON.parse(localStorage.getItem("registry.config") || "{}");
  } catch (_) {
    saved = {};
  }
  const next = { ...saved, ...patch };
  localStorage.setItem("registry.config", JSON.stringify(next));
  return next;
}

// A read-only contract bound to the configured RPC.
function readContract () {
  const cfg = loadConfig();
  if (!cfg.registryAddress) {
    throw new Error("Set the Registry address in Settings first.");
  }
  const provider = new (E().JsonRpcProvider)(cfg.rpcUrl, cfg.chainId);
  return new (E().Contract)(cfg.registryAddress, window.REGISTRY_ABI, provider);
}

// Connect an injected wallet and return the signer, checking the chain.
async function connectWallet () {
  if (!window.ethereum) {
    throw new Error("No injected wallet found. Install one, or use the "
      + "Import Proof and signed-message paths from another device.");
  }
  const cfg = loadConfig();
  const provider = new (E().BrowserProvider)(window.ethereum);
  await provider.send("eth_requestAccounts", []);
  const net = await provider.getNetwork();
  if (Number(net.chainId) !== Number(cfg.chainId)) {
    throw new Error(`Wallet is on chain ${net.chainId}; the Registry is on `
      + `chain ${cfg.chainId}. Switch networks and reconnect.`);
  }
  return await provider.getSigner();
}

// A write contract bound to a signer.
function writeContract (signer) {
  const cfg = loadConfig();
  return new (E().Contract)(cfg.registryAddress, window.REGISTRY_ABI, signer);
}

// The EIP-712 domain, built to match the contract's signing domain exactly.
function eip712Domain () {
  const cfg = loadConfig();
  return {
    name: "Registry",
    version: "1",
    chainId: Number(cfg.chainId),
    verifyingContract: E().getAddress(cfg.registryAddress)
  };
}

// Build the binding tag and the controller command locally, byte for byte as
// the contract renders them (checksummed addresses, "{chainId}:{registry}").
// Computing these here keeps the register flow sovereign: no RPC call needed
// to learn what to put in the email.
function commandBinding () {
  const cfg = loadConfig();
  return `${Number(cfg.chainId)}:${E().getAddress(cfg.registryAddress)}`;
}

function setControllerCommand (controller) {
  return `Set controller to ${E().getAddress(controller)} ${commandBinding()}`;
}

// Enumerate the directory: every registered profile with its metadata and its
// default text records. Simple and linear, which suits a directory of the
// scale of one foundation's personnel.
async function listProfiles () {
  const c = readContract();
  const count = Number(await c.profileCount());
  const out = [];
  for (let i = 0; i < count; i++) {
    const id = await c.profileIds(i);
    out.push(await resolveProfile(id, c));
  }
  return out;
}

// Resolve one profile: its controller, flags, and default records.
async function resolveProfile (id, contract) {
  const c = contract || readContract();
  const p = await c.profiles(id);
  const records = {};
  for (const key of window.REGISTRY_DEFAULT_KEYS) {
    const v = await c.text(id, key);
    if (v && v.length > 0) {
      records[key] = v;
    }
  }
  return {
    id,
    controller: p.controller,
    active: p.active,
    registeredAt: Number(p.registeredAt),
    lastTimestamp: Number(p.lastTimestamp),
    records
  };
}

// Read a single arbitrary text record.
async function readText (id, key) {
  return await readContract().text(id, key);
}

// Read a profile's current signed-write nonce.
async function readNonce (id) {
  return await readContract().nonces(id);
}

// Controller path: set a record with an ordinary transaction.
async function setText (signer, id, key, value) {
  const tx = await writeContract(signer).setText(id, key, value);
  return await tx.wait();
}

// Controller path for signers that cannot transact: sign the SetText digest
// so anyone may relay it. Returns the signature and the exact call to submit.
async function signSetText (signer, id, key, value) {
  const nonce = await readNonce(id);
  const signature = await signer.signTypedData(
    eip712Domain(),
    window.REGISTRY_EIP712.setText,
    { profileId: id, key, value, nonce }
  );
  return { id, key, value, nonce, signature };
}

// Submit a signed SetText (may be relayed by any account).
async function submitSetTextSigned (signer, signed) {
  const tx = await writeContract(signer).setTextSigned(
    signed.id, signed.key, signed.value, signed.signature
  );
  return await tx.wait();
}

// Sign the email authorization for a controller rotation: the current
// controller signs off on the exact email (by its nullifier).
async function signEmailAuthorization (signer, emailNullifier) {
  return await signer.signTypedData(
    eip712Domain(),
    window.REGISTRY_EIP712.emailAuthorization,
    { emailNullifier }
  );
}

// Register a new profile from a verified email proof.
async function submitRegister (signer, proof, controller) {
  const tx = await writeContract(signer).register(proof, controller);
  return await tx.wait();
}

// Rotate a controller: email proof plus the current controller's signature.
async function submitSetController (signer, proof, controller, signature) {
  const tx = await writeContract(signer).setController(
    proof, controller, signature
  );
  return await tx.wait();
}

window.Registry = {
  loadConfig, saveConfig, connectWallet,
  commandBinding, setControllerCommand,
  listProfiles, resolveProfile, readText, readNonce,
  setText, signSetText, submitSetTextSigned,
  signEmailAuthorization, submitRegister, submitSetController
};
