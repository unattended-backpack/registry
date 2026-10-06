#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// Compute the DKIM key hash management honors in the Registry.
//
//   node scripts/key-hash.mjs <selector>._domainkey.<domain>
//   node scripts/key-hash.mjs --file <dkim.txt>
//
// The hash is computed by executing the `dkim_key_hash` circuit, which calls
// the very function the email circuit uses, so the value management submits
// with `setDKIMPublicKeyHash` cannot drift from what proofs reveal. The first
// form looks the key up through this machine's own DNS resolver.

import { Noir } from "@noir-lang/noir_js";
import { resolveTxt } from "node:dns/promises";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseDkimKey, toLimbs } from "../../frontend/email-input.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const CIRCUIT_PATH = path.join(here, "..", "target", "dkim_key_hash.json");

/**
  Hash a DKIM key given its DNS TXT record. Returns the hash as 0x-hex bytes32.
*/
export async function dkimKeyHash (txt) {
  const { modulus, exponent } = parseDkimKey(txt);
  if (exponent !== 65537n) {
    throw new Error("The key's exponent is not 65537; proofs cannot use it.");
  }
  if (modulus.toString(2).length !== 2048) {
    throw new Error("The key is not 2048 bits; proofs cannot use it.");
  }
  const circuit = JSON.parse(fs.readFileSync(CIRCUIT_PATH, "utf8"));
  const { returnValue } = await new Noir(circuit).execute({ modulus: toLimbs(modulus) });
  return "0x" + BigInt(returnValue).toString(16).padStart(64, "0");
}

async function main () {
  const args = process.argv.slice(2);
  let txt;
  if (args[0] === "--file" && args[1]) {
    txt = fs.readFileSync(args[1], "utf8");
  } else if (args[0] && !args[0].startsWith("--")) {
    const records = await resolveTxt(args[0]);
    txt = records.map((chunks) => chunks.join("")).find((r) => r.includes("p="));
    if (!txt) {
      throw new Error(`No DKIM key published at ${args[0]}.`);
    }
  } else {
    console.error("usage: node scripts/key-hash.mjs <selector>._domainkey.<domain>");
    console.error("       node scripts/key-hash.mjs --file <dkim.txt>");
    process.exit(1);
  }
  console.log(await dkimKeyHash(txt));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch((e) => {
    console.error(e.message || e);
    process.exit(1);
  });
}
