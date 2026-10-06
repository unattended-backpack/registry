// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// The proving worker, a module worker. It turns a raw email into an EmailProof
// entirely on this machine: the input generator, the compiled circuit, the
// prover, and the proving reference string all ship with this site, so the
// email never leaves the browser and no third party is contacted.
//
// Proving is single-threaded. Multithreaded WebAssembly needs cross-origin
// isolation headers that static hosts and IPFS gateways do not send, and the
// circuit is small enough that one thread proves it in well under a minute.

import {
  BackendType, Barretenberg, initNoir, Noir, UltraHonkBackend
} from "./vendor/prover/prover.js";
import {
  buildInputs, decodePublicInputs, decodePublicOutputs, signedHeader
} from "./email-input.js";

// The reference points the prover loads: the circuit's dyadic size, 2^18.
const SRS_POINTS = 2 ** 18;

const report = (message) => self.postMessage({ type: "progress", message });

let circuit = null;

async function loadCircuit () {
  if (!circuit) {
    const response = await fetch(new URL("./circuit/email_proof.json", import.meta.url));
    if (!response.ok) {
      throw new Error("Could not load the compiled circuit (circuit/email_proof.json).");
    }
    circuit = await response.json();
  }
  return circuit;
}

// Pick the DKIM key for the email's own selector from the configured keys.
function chooseKey (raw, { domain, keys, key }) {
  if (key) {
    return key;
  }
  const { tags } = signedHeader(raw, { domain });
  const known = keys && keys[tags.s];
  if (!known) {
    throw new Error(`This site has no DKIM key for the selector "${tags.s}" that signed `
      + `this email. Its maintainers must add the TXT record at `
      + `${tags.s}._domainkey.${tags.d} to config.js.`);
  }
  return known;
}

async function prove (request) {
  report("Reading the email ...");
  const raw = new Uint8Array(request.eml);
  const { domain, salt, controller, chainId, registry } = request;
  if (!registry) {
    throw new Error("This site's config.js names no Registry address.");
  }
  const { inputs, meta } = buildInputs(raw, {
    key: chooseKey(raw, request), domain, salt, controller, chainId, registry
  });
  report(`Solving the circuit for profile ${meta.profileId} ...`);
  await initNoir();
  const compiled = await loadCircuit();
  const { witness, returnValue } = await new Noir(compiled).execute(inputs);

  report("Generating the proof (single-threaded; allow a minute) ...");
  const started = Date.now();
  const api = await Barretenberg.new({
    backend: BackendType.Wasm, threads: 1, srsSize: SRS_POINTS
  });
  try {
    const backend = new UltraHonkBackend(compiled.bytecode, api);
    const proofData = await backend.generateProof(witness, { verifierTarget: "evm" });
    report("Checking the proof ...");
    if (!(await backend.verifyProof(proofData, { verifierTarget: "evm" }))) {
      throw new Error("The proof did not verify locally.");
    }
    const decoded = decodePublicInputs(proofData.publicInputs);
    const expected = decodePublicOutputs(returnValue);
    for (const k of Object.keys(expected)) {
      if (decoded[k] !== expected[k]) {
        throw new Error(`Public output ${k} differs from the circuit's result.`);
      }
    }
    const proof = "0x" + Array.from(proofData.proof,
      (b) => b.toString(16).padStart(2, "0")).join("");
    // The sender and the exact time stay here; the page sees only what the
    // chain will see, plus the profile id the person computed anyway.
    return {
      emailProof: { ...decoded, proof },
      meta: { profileId: meta.profileId, week: meta.week, domain: meta.domain },
      seconds: (Date.now() - started) / 1000
    };
  } finally {
    await api.destroy();
  }
}

self.onmessage = async (event) => {
  try {
    const result = await prove(event.data);
    self.postMessage({ type: "done", ...result });
  } catch (e) {
    self.postMessage({ type: "error", message: e && e.message ? e.message : String(e) });
  }
};
