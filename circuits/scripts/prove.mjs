#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// Prove a Registry email from the command line.
//
//   node scripts/prove.mjs <email.eml> --salt <secret> --controller <address>
//     --chain-id <id> --registry <address> [--key <dkim.txt>]
//     [--domain ethereum.org] [--out <proof.json>]
//
// Reads a raw email (Gmail: "Download original"), builds the circuit inputs
// with the same module the browser uses, proves with Barretenberg for EVM
// verification, verifies the proof locally, and writes the EmailProof JSON the
// Registry's `register` and `setController` take (and the frontend's Import
// Proof box accepts). The email's subject must be the one `subject.mjs`
// printed for this secret, controller, chain, and registry. The secret never
// leaves this process.
//
// The DKIM key comes from `--key` (a file holding the DNS TXT record) or, when
// omitted, from a DNS lookup of the signature's selector through this
// machine's own resolver. Nothing else touches the network except
// Barretenberg's one-time download of its reference string, which it caches.

import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { resolveTxt } from "node:dns/promises";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildInputs, decodePublicInputs, decodePublicOutputs, signedHeader
} from "../../frontend/email-input.js";



const here = path.dirname(fileURLToPath(import.meta.url));
const CIRCUIT_PATH = path.join(here, "..", "target", "email_proof.json");

function usage (message) {
  if (message) {
    console.error(message);
  }
  console.error("usage: node scripts/prove.mjs <email.eml> --salt <secret> "
    + "--controller <address> --chain-id <id> --registry <address> "
    + "[--key <dkim.txt>] [--domain <domain>] [--out <proof.json>]");
  process.exit(1);
}

const OPTIONS = ["--key", "--domain", "--out", "--salt", "--controller", "--chain-id", "--registry"];

function parseArgs (argv) {
  const args = { domain: "ethereum.org" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (OPTIONS.includes(a)) {
      args[a.slice(2).replace(/-(.)/g, (_, c) => c.toUpperCase())] = argv[++i];
    } else if (a.startsWith("--")) {
      usage(`unknown option ${a}`);
    } else {
      args.eml = a;
    }
  }
  if (!args.eml || !args.salt || !args.controller || !args.chainId || !args.registry) {
    usage();
  }
  return args;
}

async function lookupKey (raw, domain) {
  const { tags } = signedHeader(raw, { domain });
  const name = `${tags.s}._domainkey.${tags.d}`;
  console.error(`Looking up the DKIM key at ${name} ...`);
  const records = await resolveTxt(name);
  const record = records.map((chunks) => chunks.join("")).find((r) => r.includes("p="));
  if (!record) {
    throw new Error(`No DKIM key published at ${name}.`);
  }
  return record;
}

/**
  Prove an email. `authorization` holds the profile's `salt` and the
  `controller`, `chainId`, and `registry` its subject commits to. Returns the
  EmailProof object, with `proof` as 0x-hex, and the controller, chain, and
  registry the proof binds, plus `publicInputs` for inspection.
*/
export async function proveEmail (raw, { key, domain, threads, log = () => {}, ...authorization } = {}) {
  const { inputs, meta } = buildInputs(raw, { key, domain, ...authorization });
  log(`Proving the authorization of ${authorization.controller} by `
    + `${meta.sender} for profile ${meta.profileId} (week of ${meta.week}) ...`);

  const circuit = JSON.parse(fs.readFileSync(CIRCUIT_PATH, "utf8"));
  const noir = new Noir(circuit);
  const { witness, returnValue } = await noir.execute(inputs);

  const api = await Barretenberg.new({ threads });
  try {
    const backend = new UltraHonkBackend(circuit.bytecode, api);
    const proofData = await backend.generateProof(witness, { verifierTarget: "evm" });
    if (!(await backend.verifyProof(proofData, { verifierTarget: "evm" }))) {
      throw new Error("The proof did not verify locally.");
    }
    const decoded = decodePublicInputs(proofData.publicInputs);
    const expected = decodePublicOutputs(returnValue);
    for (const k of Object.keys(expected)) {
      if (decoded[k] !== expected[k]) {
        throw new Error(`Public output ${k} differs from the execution result.`);
      }
    }
    if (decoded.profileId !== meta.profileId || decoded.domainName !== meta.domain) {
      throw new Error("The proof's profile or domain differs from the email's.");
    }
    if (BigInt(decoded.controller) !== BigInt(authorization.controller)
      || BigInt(decoded.registry) !== BigInt(authorization.registry)
      || BigInt(decoded.chainId) !== BigInt(authorization.chainId)) {
      throw new Error("The proof binds a different authorization than requested.");
    }
    const { controller, chainId, registry, ...emailProof } = decoded;
    return {
      ...emailProof,
      proof: "0x" + Buffer.from(proofData.proof).toString("hex"),
      controller,
      chainId,
      registry,
      publicInputs: proofData.publicInputs
    };
  } finally {
    await api.destroy();
  }
}

async function main () {
  const args = parseArgs(process.argv.slice(2));
  const raw = fs.readFileSync(args.eml);
  const key = args.key
    ? fs.readFileSync(args.key, "utf8")
    : await lookupKey(raw, args.domain);
  const started = Date.now();
  const emailProof = await proveEmail(raw, {
    key,
    domain: args.domain,
    salt: args.salt,
    controller: args.controller,
    chainId: args.chainId,
    registry: args.registry,
    log: (m) => console.error(m)
  });
  console.error(`Proved and verified in ${((Date.now() - started) / 1000).toFixed(1)}s.`);
  const json = JSON.stringify(emailProof, null, 2) + "\n";
  if (args.out) {
    fs.writeFileSync(args.out, json);
    console.error(`Wrote ${args.out}`);
  } else {
    process.stdout.write(json);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch((e) => {
    console.error(e.message || e);
    process.exit(1);
  });
}
