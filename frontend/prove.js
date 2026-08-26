// The proving layer. Proof generation happens entirely in the browser, in a
// Web Worker, so the raw email never leaves the machine. The heavy circuit
// artifacts (WASM witness generator, ceremony zkey, input generator) are not
// shipped with this site; they are hosted separately and pointed at by
// `proverArtifactBase` in Settings. When they are not configured, the Import
// Proof path accepts a proof produced by the local CLI (`snarkjs`), so a
// machine that cannot prove in the browser is never locked out.

const Ep = () => window.ethers;

// Pack a snarkjs Groth16 proof into the `bytes proof` our Verifier decodes:
// abi.encode(uint256[2] pA, uint256[2][2] pB, uint256[2] pC), with pB's
// coordinates swapped exactly as snarkjs's own Solidity calldata export does.
function packProofBytes (snarkProof) {
  const a = [snarkProof.pi_a[0], snarkProof.pi_a[1]];
  const b = [
    [snarkProof.pi_b[0][1], snarkProof.pi_b[0][0]],
    [snarkProof.pi_b[1][1], snarkProof.pi_b[1][0]]
  ];
  const c = [snarkProof.pi_c[0], snarkProof.pi_c[1]];
  return Ep().AbiCoder.defaultAbiCoder().encode(
    ["uint256[2]", "uint256[2][2]", "uint256[2]"], [a, b, c]
  );
}

// Assemble the EmailProof tuple the contract expects from the worker's result:
// the scalar fields the input generator surfaced, plus the packed proof bytes.
function assembleEmailProof (meta, proofBytes) {
  return {
    domainName: meta.domainName,
    publicKeyHash: meta.publicKeyHash,
    timestamp: BigInt(meta.timestamp || 0),
    maskedCommand: meta.maskedCommand,
    emailNullifier: meta.emailNullifier,
    accountSalt: meta.accountSalt,
    isCodeExist: Boolean(meta.isCodeExist),
    proof: proofBytes
  };
}

// Reject anything that is not a well-formed EmailProof before it reaches the
// wallet, so failures surface here with a clear message rather than as an
// opaque revert.
function validateEmailProof (p) {
  const need = ["domainName", "publicKeyHash", "timestamp", "maskedCommand",
    "emailNullifier", "accountSalt", "isCodeExist", "proof"];
  for (const k of need) {
    if (p[k] === undefined || p[k] === null) {
      throw new Error(`Proof is missing the field "${k}".`);
    }
  }
  const b32 = (v) => typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
  if (!b32(p.publicKeyHash)) throw new Error("publicKeyHash is not bytes32.");
  if (!b32(p.emailNullifier)) throw new Error("emailNullifier is not bytes32.");
  if (!b32(p.accountSalt)) throw new Error("accountSalt is not bytes32.");
  if (typeof p.proof !== "string" || !p.proof.startsWith("0x")) {
    throw new Error("proof bytes are not 0x-hex.");
  }
  return p;
}

// Generate a proof in the browser from a selected .eml file. Spawns the
// worker, streams progress, and returns { proof, publicSignals }.
function generateProof (emlText, command, onProgress) {
  const cfg = window.Registry.loadConfig();
  if (!cfg.proverArtifactBase) {
    return Promise.reject(new Error(
      "In-browser proving is not configured. Set the prover artifact base in "
      + "Settings, or use Import Proof with a proof from the CLI."
    ));
  }
  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = new Worker("./worker.js");
    } catch (e) {
      reject(new Error("Could not start the proving worker: " + e.message));
      return;
    }
    worker.onmessage = (ev) => {
      const m = ev.data;
      if (m.type === "progress") {
        if (onProgress) onProgress(m.message);
      } else if (m.type === "done") {
        worker.terminate();
        try {
          const proofBytes = packProofBytes(m.proof);
          const emailProof = validateEmailProof(
            assembleEmailProof(m.meta, proofBytes)
          );
          resolve({ proof: emailProof, publicSignals: m.publicSignals });
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
      reject(new Error("Proving worker failed: " + e.message));
    };
    worker.postMessage({
      emlText,
      command,
      artifactBase: cfg.proverArtifactBase.replace(/\/$/, ""),
      snarkjsUrl: new URL("./vendor/snarkjs.min.js", location.href).href
    });
  });
}

// Import a proof produced elsewhere (the CLI). Accepts either a finished
// EmailProof (proof as 0x bytes) or a snarkjs bundle
// { proof: {pi_a,pi_b,pi_c}, publicSignals, meta } and packs it.
function importProof (jsonText) {
  let obj;
  try {
    obj = JSON.parse(jsonText);
  } catch (e) {
    throw new Error("Not valid JSON: " + e.message);
  }
  if (obj && obj.proof && typeof obj.proof === "object" && obj.proof.pi_a) {
    if (!obj.meta) {
      throw new Error("A snarkjs bundle must include a `meta` object with the "
        + "domainName, publicKeyHash, timestamp, maskedCommand, "
        + "emailNullifier, accountSalt, and isCodeExist fields.");
    }
    return validateEmailProof(
      assembleEmailProof(obj.meta, packProofBytes(obj.proof))
    );
  }
  return validateEmailProof({
    domainName: obj.domainName,
    publicKeyHash: obj.publicKeyHash,
    timestamp: BigInt(obj.timestamp || 0),
    maskedCommand: obj.maskedCommand,
    emailNullifier: obj.emailNullifier,
    accountSalt: obj.accountSalt,
    isCodeExist: Boolean(obj.isCodeExist),
    proof: obj.proof
  });
}

window.Prove = { generateProof, importProof, packProofBytes, validateEmailProof };
