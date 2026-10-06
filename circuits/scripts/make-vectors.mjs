#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// Regenerate the proof vectors the contract tests load (`test/vectors/`).
//
//   node scripts/make-vectors.mjs
//
// Synthetic vectors come from emails signed by mailauth, an independent DKIM
// implementation, with the throwaway key in `test/fixtures/test-dkim.pem`, from
// a fictional `alice@ethereum.org`; the emails themselves are saved beside it
// (`synthetic-*.eml`) for demos. They register, renew, and rotate one
// profile on the anvil deployment the demo uses (chain 31337, registry
// 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0), with the test secret 0x7e57.
//
// Real vectors come from the real ethereum.org emails in `test/fixtures/`,
// when present (`ethereum-org-private-{register,renew,rotate}.eml`), proved
// against ethereum.org's published key. They carry real addresses in their
// signed headers; delete the fixtures and the `real-*` vectors to publish
// without them, and the synthetic vectors still cover every contract test.

import { dkimSign } from "mailauth/lib/dkim/sign.js";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { privateSubject } from "../../frontend/email-input.js";
import { proveEmail } from "./prove.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(here, "..", "test", "fixtures");
const vectors = path.join(here, "..", "test", "vectors");

const ANVIL_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ANVIL_1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const BINDING = {
  chainId: 31337,
  registry: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
  salt: "0x0000000000000000000000000000000000000000000000000000000000007e57"
};

// The synthetic emails' signing times: the register email, then an hour and
// two hours later.
const SYNTHETIC_TIME = 1_790_377_636;

function testKey () {
  const pemPath = path.join(fixtures, "test-dkim.pem");
  if (!fs.existsSync(pemPath)) {
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    fs.writeFileSync(pemPath, privateKey.export({ type: "pkcs8", format: "pem" }));
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(pemPath));
  const publicKey = crypto.createPublicKey(privateKey);
  const txt = "v=DKIM1; k=rsa; p="
    + publicKey.export({ type: "spki", format: "der" }).toString("base64");
  fs.writeFileSync(path.join(fixtures, "test-dkim.txt"), txt + "\n");
  return { privateKey, txt };
}

async function syntheticEmail (privateKey, controller, time, nonce) {
  const subject = privateSubject({ controller, ...BINDING });
  const message = [
    "From: Alice <alice@ethereum.org>",
    "To: alice@example.net",
    `Date: ${new Date(time * 1000).toUTCString()}`,
    `Message-ID: <synthetic-${nonce}@ethereum.org>`,
    `Subject: ${subject}`
  ].join("\r\n") + "\r\n\r\nA synthetic Registry test email.\r\n";
  const { signatures } = await dkimSign(message, {
    signTime: new Date(time * 1000),
    signatureData: [{
      signingDomain: "ethereum.org",
      selector: "test",
      privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
      algorithm: "rsa-sha256",
      canonicalization: "relaxed/relaxed"
    }]
  });
  return Buffer.from(signatures + message);
}

async function write (name, raw, key, controller) {
  const proof = await proveEmail(raw, { key, domain: "ethereum.org", controller, ...BINDING });
  fs.writeFileSync(path.join(vectors, `${name}.proof.json`), JSON.stringify(proof, null, 2) + "\n");
  console.error(`wrote ${name}.proof.json (profile ${proof.profileId}, week ${proof.timestamp})`);
}

async function main () {
  fs.mkdirSync(vectors, { recursive: true });
  const { privateKey, txt } = testKey();
  const scenarios = [
    ["synthetic-register", ANVIL_0, SYNTHETIC_TIME],
    ["synthetic-renew", ANVIL_0, SYNTHETIC_TIME + 3600],
    ["synthetic-rotate", ANVIL_1, SYNTHETIC_TIME + 7200]
  ];
  for (const [name, controller, time] of scenarios) {
    const raw = await syntheticEmail(privateKey, controller, time, name);
    fs.writeFileSync(path.join(fixtures, `${name}.eml`), raw);
    await write(name, raw, txt, controller);
  }

  const gmailKey = fs.readFileSync(path.join(fixtures, "gmail._domainkey.ethereum.org.txt"), "utf8");
  const real = [["register", ANVIL_0], ["renew", ANVIL_0], ["rotate", ANVIL_1]];
  for (const [step, controller] of real) {
    const file = path.join(fixtures, `ethereum-org-private-${step}.eml`);
    if (fs.existsSync(file)) {
      await write(`real-${step}`, fs.readFileSync(file), gmailKey, controller);
    } else {
      console.error(`skipped real-${step}: no ${path.basename(file)}`);
    }
  }
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
