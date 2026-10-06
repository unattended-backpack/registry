// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// Tests for the email circuit and its input generator.
//
// Real ethereum.org emails (fixtures/), when present, pin the generator to
// what Google actually signs. Synthetic emails are signed by mailauth, an independent DKIM
// implementation, with the throwaway key in fixtures/test-dkim.pem, so the
// generator's canonicalization is never checked only against itself. Every
// tamper test mutates one input of a valid email and expects the circuit to
// refuse it; the refusals that matter most (a wrong secret, controller,
// registry, or chain, a reply, a stale subject) bypass the generator's own
// pre-check so the circuit alone has to catch them.
//
// Run with `npm test` (after `nargo compile --workspace`).

import { Noir } from "@noir-lang/noir_js";
import { dkimSign } from "mailauth/lib/dkim/sign.js";
import { dkimVerify } from "mailauth/lib/dkim/verify.js";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  buildInputs, COMMITMENT_TAG, commitmentPreimage, decodePublicOutputs,
  generateSalt, parseDkimKey, privateProfileId, privateSubject, redcParam,
  sha256, signedHeader, SUBJECT_LENGTH, toLimbs
} from "../../frontend/email-input.js";
import { dkimKeyHash } from "../scripts/key-hash.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => fs.readFileSync(path.join(here, "fixtures", name));
const GMAIL_KEY = fixture("gmail._domainkey.ethereum.org.txt").toString();
const present = (name) => fs.existsSync(path.join(here, "fixtures", name));
const REAL_EMAILS = ["register", "renew", "rotate"]
  .map((step) => `ethereum-org-private-${step}.eml`).filter(present);

const ANVIL_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ANVIL_1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const BINDING = {
  chainId: 31337,
  registry: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
  salt: "0x0000000000000000000000000000000000000000000000000000000000007e57"
};
const TIME = 1_790_377_636;

const circuit = JSON.parse(fs.readFileSync(
  path.join(here, "..", "target", "email_proof.json"), "utf8"));
const noir = new Noir(circuit);
const execute = async (inputs) => decodePublicOutputs((await noir.execute(inputs)).returnValue);
const nodeSha256 = (b) => "0x" + crypto.createHash("sha256").update(b).digest("hex");
const clone = (x) => JSON.parse(JSON.stringify(x));

// The committed throwaway test key, and its DNS record.
const TEST_PRIVATE = crypto.createPrivateKey(fixture("test-dkim.pem"));
const TEST_KEY = fixture("test-dkim.txt").toString();

async function signEmail (headers, body = "hello\r\n") {
  const message = headers.join("\r\n") + "\r\n\r\n" + body;
  const { signatures } = await dkimSign(message, {
    signTime: new Date(TIME * 1000),
    signatureData: [{
      signingDomain: "ethereum.org",
      selector: "test",
      privateKey: TEST_PRIVATE.export({ type: "pkcs8", format: "pem" }),
      algorithm: "rsa-sha256",
      canonicalization: "relaxed/relaxed"
    }]
  });
  return Buffer.from(signatures + message);
}

const authorizing = (controller, subject, from = "Alice <alice@ethereum.org>") => signEmail([
  `From: ${from}`, "To: alice@example.net",
  `Subject: ${subject ?? privateSubject({ controller, ...BINDING })}`
]);

async function mailauthPasses (raw, txt) {
  const resolver = async () => [[txt.trim().replace(/\s*;\s*/g, ";").replace(/"/g, "")]];
  const { results } = await dkimVerify(raw, { resolver });
  return results.some((r) => r.status.result === "pass");
}

describe("input generator", () => {
  it("rebuilds exactly the header Google signed for real ethereum.org emails",
    { skip: !REAL_EMAILS.length && "no real ethereum.org fixtures" }, async () => {
    const key = crypto.createPublicKey({
      key: Buffer.from(/p=([^;\s]+)/.exec(GMAIL_KEY)[1], "base64"), format: "der", type: "spki"
    });
    for (const name of REAL_EMAILS) {
      const raw = fixture(name);
      assert.ok(await mailauthPasses(raw, GMAIL_KEY), "mailauth verifies the email");
      const { canonical, tags } = signedHeader(raw, { domain: "ethereum.org" });
      const signature = Buffer.from(tags.b.replace(/\s/g, ""), "base64");
      assert.ok(crypto.verify("sha256", Buffer.from(canonical, "latin1"), key, signature));
    }
  });

  it("hashes exactly as node:crypto does", () => {
    for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 130, 1000]) {
      const bytes = crypto.randomBytes(n);
      assert.equal("0x" + Buffer.from(sha256(new Uint8Array(bytes))).toString("hex"), nodeSha256(bytes));
    }
  });

  it("lays out the subject commitment and profile id as specified", () => {
    const preimage = commitmentPreimage({ controller: ANVIL_0, ...BINDING });
    const expected = Buffer.concat([
      Buffer.from(COMMITMENT_TAG),
      Buffer.from(ANVIL_0.slice(2), "hex"),
      Buffer.from(BigInt(BINDING.chainId).toString(16).padStart(64, "0"), "hex"),
      Buffer.from(BINDING.registry.slice(2), "hex"),
      Buffer.from(BigInt(BINDING.salt).toString(16).padStart(64, "0"), "hex")
    ]);
    assert.deepEqual(Buffer.from(preimage), expected);
    const subject = privateSubject({ controller: ANVIL_0, ...BINDING });
    assert.equal(subject, "Set controller to " + nodeSha256(expected));
    assert.equal(subject.length, SUBJECT_LENGTH);
    assert.equal(
      privateProfileId("Tim.Clancy@ethereum.org", BINDING.salt),
      nodeSha256(Buffer.concat([
        Buffer.from(BigInt(BINDING.salt).toString(16).padStart(64, "0"), "hex"),
        Buffer.from("tim.clancy@ethereum.org")
      ]))
    );
  });

  it("generates secrets inside the field, and refuses ones outside it", () => {
    for (let i = 0; i < 20; i++) {
      assert.match(generateSalt(), /^0x00[0-9a-f]{62}$/);
    }
    assert.throws(() => privateSubject({ controller: ANVIL_0, ...BINDING, salt: "0x0" }), /out of range/);
    assert.throws(() => privateSubject({ controller: ANVIL_0, ...BINDING, salt: "0x" + "f".repeat(64) }), /out of range/);
    assert.throws(() => privateSubject({ controller: ANVIL_0, ...BINDING, salt: "7e57" }), /0x-prefixed/);
  });

  it("encodes the key the way the bignum library expects", () => {
    const { modulus, exponent } = parseDkimKey(GMAIL_KEY);
    assert.equal(exponent, 65537n);
    assert.equal(modulus.toString(2).length, 2048);
    const limbs = toLimbs(modulus).map(BigInt);
    assert.equal(limbs.reduce((acc, limb, i) => acc + (limb << (120n * BigInt(i))), 0n), modulus);
    assert.equal(redcParam(modulus), (1n << 4102n) / modulus);
  });

  it("refuses an email whose subject is not the authorization, with a reason", async () => {
    const raw = await authorizing(ANVIL_0);
    assert.throws(
      () => buildInputs(raw, { key: TEST_KEY, controller: ANVIL_1, ...BINDING }),
      /need exactly "Set controller to 0x/
    );
    const unsigned = Buffer.from("From: a@ethereum.org\r\nSubject: hi\r\n\r\nbody\r\n");
    assert.throws(
      () => buildInputs(unsigned, { key: TEST_KEY, controller: ANVIL_0, ...BINDING }),
      /no DKIM signature/
    );
  });
});

describe("circuit", () => {
  it("proves an authorization and reveals only the domain, week, key, nullifier, and id", async () => {
    const raw = await authorizing(ANVIL_0);
    assert.ok(await mailauthPasses(raw, TEST_KEY));
    const { inputs, meta } = buildInputs(raw, { key: TEST_KEY, controller: ANVIL_0, ...BINDING });
    const out = await execute(inputs);
    assert.deepEqual(Object.keys(out).sort(),
      ["domainName", "emailNullifier", "profileId", "publicKeyHash", "timestamp"]);
    assert.equal(out.domainName, "ethereum.org");
    assert.equal(out.timestamp, String(Math.floor(TIME / 604800) * 604800));
    assert.equal(out.profileId, privateProfileId("alice@ethereum.org", BINDING.salt));
    assert.equal(out.profileId, meta.profileId);
    assert.equal(out.publicKeyHash, await dkimKeyHash(TEST_KEY));
  });

  it("ties one email and one secret to one nullifier, and one secret to one id", async () => {
    const raw = await authorizing(ANVIL_0);
    const a = await execute(buildInputs(raw, { key: TEST_KEY, controller: ANVIL_0, ...BINDING }).inputs);
    const other = generateSalt();
    const rawOther = await authorizing(ANVIL_0, privateSubject({ controller: ANVIL_0, ...BINDING, salt: other }));
    const b = await execute(buildInputs(rawOther, { key: TEST_KEY, controller: ANVIL_0, ...BINDING, salt: other }).inputs);
    assert.notEqual(a.profileId, b.profileId, "another secret, another profile");
    assert.notEqual(a.emailNullifier, b.emailNullifier);
    const renew = await authorizing(ANVIL_0, undefined, "alice@ethereum.org");
    const c = await execute(buildInputs(renew, { key: TEST_KEY, controller: ANVIL_0, ...BINDING }).inputs);
    assert.equal(c.profileId, a.profileId, "same address and secret, same profile");
  });

  it("lowercases the sender and ignores a display name holding '<'", async () => {
    const raw = await authorizing(ANVIL_0, undefined, '"Eve <eve@ethereum.org>" <Alice@Ethereum.ORG>');
    const out = await execute(buildInputs(raw, { key: TEST_KEY, controller: ANVIL_0, ...BINDING }).inputs);
    assert.equal(out.profileId, privateProfileId("alice@ethereum.org", BINDING.salt));
    assert.equal(out.domainName, "ethereum.org");
  });

  it("reads a folded subject exactly as relaxed canonicalization unfolds it", async () => {
    const subject = privateSubject({ controller: ANVIL_0, ...BINDING });
    const folded = subject.replace("to 0x", "to\r\n 0x");
    const raw = await authorizing(ANVIL_0, folded);
    assert.ok(await mailauthPasses(raw, TEST_KEY));
    await execute(buildInputs(raw, { key: TEST_KEY, controller: ANVIL_0, ...BINDING }).inputs);
  });

  const refusals = {
    "a reply to an authorization": async () => buildInputs(
      await authorizing(ANVIL_0, "Re: " + privateSubject({ controller: ANVIL_0, ...BINDING })),
      { key: TEST_KEY, controller: ANVIL_0, ...BINDING, unchecked: true }).inputs,
    "a subject in uppercase hex": async () => buildInputs(
      await authorizing(ANVIL_0, privateSubject({ controller: ANVIL_0, ...BINDING }).replace(/0x([0-9a-f]+)$/, (_, h) => "0x" + h.toUpperCase())),
      { key: TEST_KEY, controller: ANVIL_0, ...BINDING, unchecked: true }).inputs,
    "an old plaintext command naming the controller": async () => buildInputs(
      await authorizing(ANVIL_0, `Set controller to ${ANVIL_0} ${BINDING.chainId}:${BINDING.registry}`),
      { key: TEST_KEY, controller: ANVIL_0, ...BINDING, unchecked: true }).inputs
  };
  for (const [name, build] of Object.entries(refusals)) {
    it(`refuses ${name}`, async () => {
      await assert.rejects(noir.execute(await build()));
    });
  }

  it("refuses every tampered input of a valid email", async (t) => {
    const raw = await authorizing(ANVIL_0);
    const { inputs: base, canonical } = buildInputs(raw, { key: TEST_KEY, controller: ANVIL_0, ...BINDING });
    const header = Buffer.from(canonical).toString("latin1");
    const hex = (x) => "0x" + BigInt(x).toString(16);
    const tampered = {
      "a wrong secret": (i) => { i.salt = hex(BigInt(i.salt) + 1n); },
      "a wrong controller": (i) => { i.controller = hex(ANVIL_1); },
      "a wrong registry": (i) => { i.registry = hex(ANVIL_1); },
      "a wrong chain": (i) => { i.chain_id = hex(1); },
      "a controller wider than an address": (i) => { i.controller = hex(BigInt(ANVIL_0) + (1n << 160n)); },
      "a flipped subject byte": (i) => {
        const at = Number(i.subject.index) + 40;
        i.header.storage[at] = String(Number(i.header.storage[at]) ^ 1);
      },
      "a header one byte short": (i) => { i.header.len = String(Number(i.header.len) - 1); },
      "a subject run pointed at the To field": (i) => {
        const to = header.indexOf("\r\nto:") + 2;
        i.subject = { index: String(to), length: String(header.indexOf("\r\n", to) - to) };
      },
      "a From run stretched across the next line": (i) => { i.from.length = String(Number(i.from.length) + 5); },
      "an address shifted by one byte": (i) => {
        i.address.index = String(Number(i.address.index) + 1);
        i.address.length = String(Number(i.address.length) - 1);
        i.at = String(Number(i.at) - 1);
      },
      "an '@' offset that misses the '@'": (i) => { i.at = String(Number(i.at) + 1); },
      "a timestamp read from x= instead of t=": (i) => {
        const x = header.indexOf("x=", Number(i.dkim.index));
        if (x < 0) {
          i.timestamp_index = String(Number(i.timestamp_index) + 1);
        } else {
          i.timestamp_index = String(x + 2);
        }
      },
      "a DKIM-Signature run that does not end the header": (i) => { i.dkim.length = String(Number(i.dkim.length) - 1); },
      "the signature plus the modulus": (i) => {
        const join = (limbs) => limbs.map(BigInt).reduce((a, l, k) => a + (l << (120n * BigInt(k))), 0n);
        i.signature = toLimbs(join(i.signature) + join(i.modulus));
      },
      "a different DKIM key": (i) => {
        const other = parseDkimKey(GMAIL_KEY).modulus;
        i.modulus = toLimbs(other);
        i.redc = toLimbs(redcParam(other));
      }
    };
    for (const [name, mutate] of Object.entries(tampered)) {
      await t.test(name, async () => {
        const inputs = clone(base);
        mutate(inputs);
        await assert.rejects(noir.execute(inputs));
      });
    }
  });

  it("cannot be steered by a wrong Barrett parameter", async () => {
    const raw = await authorizing(ANVIL_0);
    const { inputs: base } = buildInputs(raw, { key: TEST_KEY, controller: ANVIL_0, ...BINDING });
    const honest = await execute(base);
    const inputs = clone(base);
    inputs.redc[0] = "0x" + (BigInt(inputs.redc[0]) + 1n).toString(16);
    let out = null;
    try {
      out = await execute(inputs);
    } catch (_) {
      return;
    }
    assert.deepEqual(out, honest, "a wrong redc changes nothing a proof reveals");
  });
});

describe("real ethereum.org authorizations", () => {
  const steps = [["register", ANVIL_0], ["renew", ANVIL_0], ["rotate", ANVIL_1]];
  for (const [step, controller] of steps) {
    const name = `ethereum-org-private-${step}.eml`;
    it(`proves the real ${step} email`, { skip: !present(name) && `no ${name}` }, async () => {
      const raw = fixture(name);
      assert.ok(await mailauthPasses(raw, GMAIL_KEY), "mailauth verifies the email");
      const { inputs, meta } = buildInputs(raw, { key: GMAIL_KEY, domain: "ethereum.org", controller, ...BINDING });
      const out = await execute(inputs);
      assert.equal(out.domainName, "ethereum.org");
      assert.equal(out.profileId, meta.profileId);
      assert.equal(out.timestamp, String(meta.week));
      assert.equal(out.publicKeyHash, await dkimKeyHash(GMAIL_KEY));
    });
  }
});
