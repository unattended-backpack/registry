// The proving worker. It runs off the main thread and pulls in snarkjs and the
// circuit artifacts locally. Nothing here contacts a server on the author's
// behalf: every URL it loads is one the operator configured (the vendored
// snarkjs, and the artifact base holding the WASM, the zkey, and the input
// generator). The raw email text is handled only inside this worker.
//
// The input generator is operator-supplied because it is circuit-specific and
// WASM-backed (ZK Email's relayer-utils). Place a UMD build at
// `${artifactBase}/zkemail-input.js` that defines:
//
//   self.zkemailInput = {
//     // Parse a raw .eml and build the circom inputs for email_auth, plus the
//     // scalar fields the EmailProof carries. `command` is the exact command
//     // the email body must contain, so the generator can locate and mask it.
//     async generate(emlText, { command }) {
//       return {
//         inputs,   // the circom witness inputs object
//         meta: {
//           domainName, publicKeyHash, timestamp, maskedCommand,
//           emailNullifier, accountSalt, isCodeExist
//         }
//       };
//     }
//   };

function report (message) {
  self.postMessage({ type: "progress", message });
}

self.onmessage = async (ev) => {
  const { emlText, command, artifactBase, snarkjsUrl } = ev.data;
  try {
    report("Loading the prover ...");
    importScripts(snarkjsUrl);
    if (typeof self.snarkjs === "undefined") {
      throw new Error("snarkjs did not load from the vendored bundle.");
    }

    report("Loading the input generator ...");
    try {
      importScripts(`${artifactBase}/zkemail-input.js`);
    } catch (_) {
      throw new Error("Could not load zkemail-input.js from the artifact "
        + "base. See the frontend README for how to host the prover "
        + "artifacts, or use the Import Proof path.");
    }
    if (!self.zkemailInput || typeof self.zkemailInput.generate !== "function") {
      throw new Error("zkemail-input.js did not define zkemailInput.generate.");
    }

    report("Parsing the email and building the witness inputs ...");
    const { inputs, meta } = await self.zkemailInput.generate(
      emlText, { command }
    );
    if (!meta) {
      throw new Error("The input generator returned no meta fields.");
    }

    report("Generating the proof (this can take minutes) ...");
    const wasmUrl = `${artifactBase}/email_auth.wasm`;
    const zkeyUrl = `${artifactBase}/emailauth_final.zkey`;
    const { proof, publicSignals } = await self.snarkjs.groth16.fullProve(
      inputs, wasmUrl, zkeyUrl
    );

    report("Proof complete.");
    self.postMessage({ type: "done", proof, publicSignals, meta });
  } catch (e) {
    self.postMessage({ type: "error", message: e && e.message ? e.message : String(e) });
  }
};
