// The proving layer, main-thread side. Proof generation happens entirely in
// the browser, in a module worker (`worker.js`), so the raw email never leaves
// the machine. Everything the worker needs ships with this site: the input
// generator, the compiled circuit, the prover, and its reference points. The
// DKIM keys come from `config.js` alone. The profile secret goes to the
// worker and nowhere else.

// Reject anything that is not a well-formed EmailProof before it reaches the
// wallet, so failures surface here with a clear message rather than as an
// opaque revert.
function validateEmailProof (p) {
  const need = ["domainName", "publicKeyHash", "timestamp", "emailNullifier",
    "profileId", "proof"];
  for (const k of need) {
    if (p[k] === undefined || p[k] === null) {
      throw new Error(`Proof is missing the field "${k}".`);
    }
  }
  const b32 = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
  for (const k of ["publicKeyHash", "emailNullifier", "profileId"]) {
    if (!b32(p[k])) {
      throw new Error(`${k} is not bytes32.`);
    }
  }
  if (typeof p.proof !== "string" || !/^0x([0-9a-fA-F]{2})+$/.test(p.proof)) {
    throw new Error("proof bytes are not 0x-hex.");
  }
  const proof = {
    domainName: String(p.domainName),
    publicKeyHash: p.publicKeyHash,
    timestamp: BigInt(p.timestamp),
    emailNullifier: p.emailNullifier,
    profileId: p.profileId,
    proof: p.proof
  };
  // The authorization the proof binds, when the file records it; the chain
  // checks it regardless.
  const binding = {};
  if (p.controller) {
    binding.controller = window.ethers.getAddress(p.controller);
  }
  if (p.chainId !== undefined) {
    binding.chainId = String(p.chainId);
  }
  if (p.registry) {
    binding.registry = window.ethers.getAddress(p.registry);
  }
  return { proof, binding };
}

// Prove an email in the browser. `eml` is the raw message as an ArrayBuffer;
// `authorization` holds the profile's `salt` and the `controller` the email
// authorizes. Resolves to { proof, binding, meta, seconds }; `onProgress`
// receives status lines.
function generateProof (eml, authorization, onProgress) {
  const cfg = window.Registry.loadConfig();
  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = new Worker(new URL("./worker.js", location.href), { type: "module" });
    } catch (e) {
      reject(new Error("Could not start the proving worker: " + e.message));
      return;
    }
    worker.onmessage = (ev) => {
      const m = ev.data;
      if (m.type === "progress") {
        if (onProgress) {
          onProgress(m.message);
        }
      } else if (m.type === "done") {
        worker.terminate();
        try {
          const { proof, binding } = validateEmailProof(m.emailProof);
          resolve({ proof, binding, meta: m.meta, seconds: m.seconds });
        } catch (e) {
          reject(e);
        }
      } else if (m.type === "error") {
        worker.terminate();
        reject(new Error(m.message));
      }
    };
    worker.onerror = (e) => {
      worker.terminate();
      reject(new Error("Proving worker failed: " + (e.message || "it could not load")));
    };
    worker.postMessage({
      eml,
      domain: cfg.domain,
      keys: cfg.dkimKeys || {},
      salt: authorization.salt,
      controller: authorization.controller,
      chainId: String(cfg.chainId),
      registry: cfg.registryAddress
    }, [eml]);
  });
}

window.Prove = { generateProof, validateEmailProof };
