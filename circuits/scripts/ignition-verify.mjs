#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// Verify, from Aztec's public transcripts, that the Registry's proofs rest on
// the AZTEC Ignition ceremony, and that nothing between the ceremony and the
// deployed verifier was substituted.
//
//   node scripts/ignition-verify.mjs [--signers all|<address>,<address>...]
//
// UltraHonk proves over a universal reference string: the powers of a secret
// tau, produced by Ignition (176 participants, October 2019 to January 2020).
// If any one participant destroyed their randomness, nobody knows tau and no
// proof can be forged. The verifier holds tau in G2; the verification key's
// commitments were computed from tau's powers in G1. This script checks, with
// its own pairing arithmetic (noble-curves) and no trust in Aztec's tools:
//
//   1. The ceremony. Every participant's first G1 point x.[1] and G2 points
//      x.[2] and z.[2], fetched by byte range from their published transcript,
//      satisfy x_i = z_i * x_(i-1), in the order the ceremony manifest
//      records, from the generator through all 176 participants to the sealed
//      output. Each transcript's G1 and G2 points agree.
//   2. The sealed tau. The sealed x.[2] equals the manifest's published tau,
//      the verifier's hardcoded G2 point, and the frontend's G2 file.
//   3. The reference string. The first 2^18 sealed G1 points are consecutive
//      powers of that tau (one randomized pairing check), and the frontend's
//      compressed points are exactly them.
//   4. The derivation. bb, cut off from the network, derives the verification
//      key and the Solidity verifier from a reference string built only from
//      those verified points; the result must match the vendored verifier.
//
// Steps 1 to 4 prove the published transcripts compose into exactly the
// reference string the Registry uses. They do not prove the transcripts are
// the participants' own: whoever controls the bucket could have published a
// fabricated chain. `--signers` closes that gap for the participants you
// name: it streams each one's full first transcript (322 MB, never written to
// disk), checks its BLAKE2b checksum, recovers the signer of its SHA-256 from
// the published signature, and requires the points step 1 used to be those
// very bytes. One honest signer you recognize is enough.
//
// Downloads are cached under `.toolchain/ignition/`; the deep mode's streams
// are not.

import { bn254 } from "@noble/curves/bn254.js";
import { pippenger } from "@noble/curves/abstract/curve.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(here, "..", "..");
const CACHE = path.join(ROOT, ".toolchain", "ignition");
const BUCKET = "https://aztec-ignition.s3.eu-west-2.amazonaws.com/MAIN%20IGNITION";

// The ceremony manifest's SHA-256. The ceremony ended in January 2020 and its
// records are immutable; this pin makes that assumption checkable.
const MANIFEST_SHA256 = "d231a1defd9804721ded32c75dd6f956efbf61c254b3ebcec4bb6596ba9941b8";

// The transcript layout (see AztecProtocol/ignition-verification,
// Transcript_spec.md): a 28-byte manifest, 5,040,000 G1 points of 64 bytes,
// then, in the first transcript only, two G2 points of 128 bytes, then a
// 64-byte BLAKE2b checksum of everything before it.
const HEADER = 28;
const POINTS_PER_TRANSCRIPT = 5_040_000;
const G2_OFFSET = HEADER + 64 * POINTS_PER_TRANSCRIPT;
const TRANSCRIPT0_LENGTH = G2_OFFSET + 256 + 64;

// The reference string the circuit needs: the generator and 2^18 powers.
const SRS_POINTS = 2 ** 18;

const { Fp2, Fp12 } = bn254.fields;
const G1 = bn254.G1.Point;
const G2 = bn254.G2.Point;

const log = (m) => console.log(m);
const fail = (m) => {
  throw new Error(m);
};

// A field element in Ignition's layout: four 64-bit words, least significant
// word first, each word big-endian.
function ignitionField (bytes, at) {
  let v = 0n;
  for (let w = 0; w < 4; w++) {
    v |= BigInt("0x" + Buffer.from(bytes.subarray(at + 8 * w, at + 8 * w + 8)).toString("hex")) << BigInt(64 * w);
  }
  return v;
}

function ignitionG1 (bytes, at) {
  const p = G1.fromAffine({ x: ignitionField(bytes, at), y: ignitionField(bytes, at + 32) });
  p.assertValidity();
  return p;
}

function ignitionG2 (bytes, at) {
  const x = Fp2.create({ c0: ignitionField(bytes, at), c1: ignitionField(bytes, at + 32) });
  const y = Fp2.create({ c0: ignitionField(bytes, at + 64), c1: ignitionField(bytes, at + 96) });
  const p = G2.fromAffine({ x, y });
  p.assertValidity();
  if (!p.isTorsionFree()) {
    fail("A G2 point lies outside the prime-order subgroup.");
  }
  return p;
}

const beHex = (x) => x.toString(16).padStart(64, "0");
const toBytesBE = (x) => Buffer.from(beHex(x), "hex");

async function fetchBytes (url, range) {
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await fetch(url, range ? { headers: { Range: `bytes=${range[0]}-${range[1]}` } } : {});
      if (!response.ok) {
        fail(`${response.status} for ${url}`);
      }
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (range && bytes.length !== range[1] - range[0] + 1) {
        fail(`Short read from ${url}: ${bytes.length} bytes.`);
      }
      return bytes;
    } catch (e) {
      if (attempt >= 4) {
        throw e;
      }
      await new Promise((r) => setTimeout(r, 1000 * attempt));
    }
  }
}

async function cached (name, produce) {
  const file = path.join(CACHE, name);
  if (fs.existsSync(file)) {
    return new Uint8Array(fs.readFileSync(file));
  }
  const bytes = await produce();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, bytes);
  return bytes;
}

// e(a1, a2) == e(b1, b2), as one batched pairing against the identity.
const pairingsEqual = (a1, a2, b1, b2) =>
  Fp12.eql(bn254.pairingBatch([{ g1: a1, g2: a2 }, { g1: b1.negate(), g2: b2 }]), Fp12.ONE);

async function inBatches (items, size, fn) {
  const out = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(...await Promise.all(items.slice(i, i + size).map(fn)));
  }
  return out;
}

// --- The ceremony order ----------------------------------------------------

async function loadManifest () {
  const bytes = await cached("manifest.json", () => fetchBytes(`${BUCKET}/manifest.json`));
  const digest = Buffer.from(sha256(bytes)).toString("hex");
  if (digest !== MANIFEST_SHA256) {
    fail(`The ceremony manifest's SHA-256 is ${digest}, not the pinned ${MANIFEST_SHA256}.`);
  }
  const manifest = JSON.parse(Buffer.from(bytes).toString("utf8"));
  const participants = [...manifest.participants].sort((a, b) => a.position - b.position);
  const positions = participants.map((p) => p.position);
  const invalid = manifest.invalidated.map((p) => p.position);
  const all = [...positions, ...invalid].sort((a, b) => a - b);
  if (new Set(positions).size !== positions.length || new Set(all).size !== all.length) {
    fail("The manifest repeats a position.");
  }
  if (all.length !== all[all.length - 1] || all.some((p, i) => p !== i + 1)) {
    fail("The manifest's participants and invalidated slots do not fill positions 1 to the last.");
  }
  if (manifest.pointsPerTranscript !== POINTS_PER_TRANSCRIPT || manifest.numG1Points !== 20 * POINTS_PER_TRANSCRIPT) {
    fail("The manifest's transcript sizes differ from the specification.");
  }
  log(`ok manifest: SHA-256 pinned; ${participants.length} participants in positions 1 to ${all.length}, `
    + `${invalid.length} invalidated slots accounted for`);
  return { manifest, participants };
}

const folder = (p) => `${String(p.position).padStart(3, "0")}_${p.address.toLowerCase()}`;

// The first G1 point and both G2 points of a transcript's first file.
async function transcriptPoints (dir, key) {
  const head = await cached(`points/${key}.head`, () => fetchBytes(`${BUCKET}/${dir}/transcript00.dat`, [0, HEADER + 63]));
  const tail = await cached(`points/${key}.g2`, () => fetchBytes(`${BUCKET}/${dir}/transcript00.dat`, [G2_OFFSET, G2_OFFSET + 255]));
  const ints = [0, 4, 8, 12, 16, 20, 24].map((i) => Buffer.from(head.subarray(i, i + 4)).readUInt32BE());
  if (ints[0] !== 0 || ints[1] !== 20 || ints[4] !== POINTS_PER_TRANSCRIPT || ints[5] !== 2 || ints[6] !== 0) {
    fail(`${key}: an unexpected transcript manifest ${ints.join(",")}.`);
  }
  return { head, tail, g1: ignitionG1(head, HEADER), x2: ignitionG2(tail, 0), z2: ignitionG2(tail, 128) };
}

async function verifyChain (participants) {
  const steps = [...participants.map((p) => ({ dir: folder(p), key: folder(p), address: p.address })),
    { dir: "sealed", key: "sealed", address: "sealed" }];
  const points = await inBatches(steps, 12, (s) => transcriptPoints(s.dir, s.key));
  let previous = G1.BASE;
  let trivial = 0;
  for (let i = 0; i < steps.length; i++) {
    const { g1, x2, z2 } = points[i];
    if (!pairingsEqual(g1, G2.BASE, G1.BASE, x2)) {
      fail(`${steps[i].key}: its G1 and G2 points disagree.`);
    }
    if (!pairingsEqual(g1, G2.BASE, previous, z2)) {
      fail(`${steps[i].key}: does not build on the previous contribution.`);
    }
    if (z2.equals(G2.ZERO) || z2.equals(G2.BASE)) {
      trivial += 1;
    }
    previous = g1;
  }
  log(`ok chain: x_i = z_i * x_(i-1) from the generator through ${participants.length} participants `
    + `to the sealed output (${2 * steps.length} pairing checks); ${trivial} trivial contributions`);
  return { steps, points, sealed: points[points.length - 1] };
}

// --- The sealed tau, and every place it is baked in -------------------------

function g2FromBigEndianWords (words) {
  const p = G2.fromAffine({
    x: Fp2.create({ c0: words[0], c1: words[1] }),
    y: Fp2.create({ c0: words[2], c1: words[3] })
  });
  p.assertValidity();
  return p;
}

function verifierG2Points () {
  const source = fs.readFileSync(path.join(ROOT, "contracts", "src", "vendor", "HonkVerifier.sol"), "utf8");
  const grab = (label) => {
    const at = source.indexOf(label);
    if (at < 0) {
      fail(`The vendored verifier has no "${label}".`);
    }
    const words = [...source.slice(at).matchAll(/uint256\((0x[0-9a-fA-F]{64})\)/g)].slice(0, 4).map((m) => BigInt(m[1]));
    // EIP-197 order: x.c1, x.c0, y.c1, y.c0.
    return g2FromBigEndianWords([words[1], words[0], words[3], words[2]]);
  };
  return { fixed: grab("// Fixed G2 point"), tau: grab("// G2 point from VK") };
}

function verifySealedTau (manifest, sealed) {
  const published = g2FromBigEndianWords(manifest.crs.t2.map(BigInt));
  const { fixed, tau } = verifierG2Points();
  const g2File = fs.readFileSync(path.join(ROOT, "frontend", "crs", "bn254_g2.dat"));
  const frontend = g2FromBigEndianWords([0, 32, 64, 96].map((i) => BigInt("0x" + g2File.subarray(i, i + 32).toString("hex"))));
  if (!sealed.x2.equals(published)) {
    fail("The sealed transcript's tau differs from the manifest's published tau.");
  }
  if (!tau.equals(sealed.x2)) {
    fail("The vendored verifier's G2 point is not Ignition's tau.");
  }
  if (!fixed.equals(G2.BASE)) {
    fail("The vendored verifier's fixed G2 point is not the BN254 generator.");
  }
  if (!frontend.equals(sealed.x2)) {
    fail("The frontend's G2 file is not Ignition's tau.");
  }
  log("ok tau: the sealed tau.[2] is the manifest's, the vendored verifier's, and the frontend's; "
    + "the verifier's other G2 point is the generator");
}

// --- The reference string ----------------------------------------------------

async function loadSrs (sealed) {
  const count = SRS_POINTS;
  const bytes = await cached(`sealed-g1-${count}.bin`, () => fetchBytes(`${BUCKET}/sealed/transcript00.dat`, [HEADER, HEADER + 64 * count - 1]));
  if (!Buffer.from(bytes.subarray(0, 64)).equals(Buffer.from(sealed.head.subarray(HEADER, HEADER + 64)))) {
    fail("The reference string's first point differs from the sealed transcript's.");
  }
  const points = [G1.BASE];
  for (let k = 0; k < count; k++) {
    points.push(ignitionG1(bytes, 64 * k));
  }
  return points;
}

function verifySrsStructure (srs, tau2) {
  // With fresh 128-bit weights r_k, e(sum r_k S_(k+1), [1]) = e(sum r_k S_k, tau.[1])
  // holds for random weights only if every S_(k+1) = tau * S_k.
  const n = srs.length - 1;
  const weights = new BigUint64Array(2 * n);
  for (let i = 0; i < weights.length; i += 8192) {
    crypto.getRandomValues(weights.subarray(i, i + 8192));
  }
  const scalars = Array.from({ length: n }, (_, k) => (weights[2 * k] << 64n) | weights[2 * k + 1] | 1n);
  const started = Date.now();
  const shifted = pippenger(G1, srs.slice(1), scalars);
  const base = pippenger(G1, srs.slice(0, n), scalars);
  if (!pairingsEqual(shifted, G2.BASE, base, tau2)) {
    fail("The reference string's points are not consecutive powers of the sealed tau.");
  }
  log(`ok reference string: ${srs.length} points (the generator and ${n} powers) are consecutive powers `
    + `of the sealed tau (${((Date.now() - started) / 1000).toFixed(0)}s)`);
}

function verifyFrontendSrs (srs) {
  const file = fs.readFileSync(path.join(ROOT, "frontend", "crs", "bn254_g1_compressed.dat"));
  const count = file.length / 32;
  for (let k = 0; k < count; k++) {
    const { x, y } = srs[k].toAffine();
    const word = Buffer.from(file.subarray(32 * k, 32 * k + 32));
    const odd = (word[0] & 0x80) !== 0;
    word[0] &= 0x3f;
    if (BigInt("0x" + word.toString("hex")) !== x || odd !== ((y & 1n) === 1n)) {
      fail(`The frontend's reference point ${k} is not Ignition's.`);
    }
  }
  log(`ok frontend: its ${count} compressed reference points are Ignition's, point for point`);
}

// --- The derivation ------------------------------------------------------------

function verifyDerivation (srs) {
  const crsDir = path.join(CACHE, "crs");
  fs.mkdirSync(crsDir, { recursive: true });
  const file = path.join(crsDir, "bn254_g1.dat");
  const g1 = Buffer.concat(srs.map((p) => {
    const { x, y } = p.toAffine();
    return Buffer.concat([toBytesBE(x), toBytesBE(y)]);
  }));
  fs.writeFileSync(file, g1);
  // bb takes an empty `crs.lock` file lock in the directory; anything else it
  // wrote would be points of its own.
  const snapshot = () => fs.readdirSync(crsDir)
    .filter((n) => !(n === "crs.lock" && fs.statSync(path.join(crsDir, n)).size === 0))
    .map((n) => n + ":" + fs.statSync(path.join(crsDir, n)).size).join(",");
  const before = snapshot();

  const bb = path.join(ROOT, ".toolchain", "bin", "bb");
  const circuit = path.join(ROOT, "circuits", "target", "email_proof.json");
  const out = path.join(CACHE, "derived");
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out, { recursive: true });
  const isolated = spawnSync("unshare", ["-rn", "true"]).status === 0;
  const run = (args) => {
    const [cmd, argv] = isolated ? ["unshare", ["-rn", bb, ...args]] : [bb, args];
    execFileSync(cmd, argv, { stdio: "ignore" });
  };
  run(["write_vk", "-b", circuit, "-o", out, "-t", "evm", "--crs_path", crsDir]);
  run(["write_solidity_verifier", "-k", path.join(out, "vk"), "-o", path.join(out, "HonkVerifier.sol"), "-t", "evm", "--crs_path", crsDir]);
  if (snapshot() !== before || !Buffer.from(fs.readFileSync(file)).equals(g1)) {
    fail("bb changed the reference string directory, so it may have fetched points of its own.");
  }
  const derived = fs.readFileSync(path.join(out, "HonkVerifier.sol"));
  const vendored = fs.readFileSync(path.join(ROOT, "contracts", "src", "vendor", "HonkVerifier.sol"));
  if (!derived.equals(vendored)) {
    fail("The verifier bb derives from Ignition's points differs from the vendored verifier.");
  }
  log(`ok derivation: bb${isolated ? ", with no network," : " (WITHOUT network isolation: unshare -rn is unavailable)"} `
    + "derives the vendored verifier byte for byte from Ignition's points alone");
}

// --- Signatures (deep mode) -------------------------------------------------------

async function verifySigner (step, points) {
  const url = `${BUCKET}/${step.dir}/transcript00.dat`;
  const response = await fetch(url);
  if (!response.ok) {
    fail(`${response.status} for ${url}`);
  }
  const whole = sha256.create();
  const checksum = blake2b.create({ dkLen: 64 });
  const tail = new Uint8Array(64);
  const head = new Uint8Array(HEADER + 64);
  const g2 = new Uint8Array(256);
  let offset = 0;
  const copyInto = (target, start, chunk) => {
    const from = Math.max(start, offset);
    const to = Math.min(start + target.length, offset + chunk.length);
    if (from < to) {
      target.set(chunk.subarray(from - offset, to - offset), from - start);
    }
  };
  for await (const chunk of response.body) {
    whole.update(chunk);
    const bodyEnd = TRANSCRIPT0_LENGTH - 64;
    if (offset < bodyEnd) {
      checksum.update(chunk.subarray(0, Math.max(0, Math.min(chunk.length, bodyEnd - offset))));
    }
    copyInto(head, 0, chunk);
    copyInto(g2, G2_OFFSET, chunk);
    copyInto(tail, bodyEnd, chunk);
    offset += chunk.length;
  }
  if (offset !== TRANSCRIPT0_LENGTH) {
    fail(`${step.key}: the transcript is ${offset} bytes, not ${TRANSCRIPT0_LENGTH}.`);
  }
  if (!Buffer.from(checksum.digest()).equals(Buffer.from(tail))) {
    fail(`${step.key}: the transcript's BLAKE2b checksum does not match.`);
  }
  if (!Buffer.from(head).equals(Buffer.from(points.head)) || !Buffer.from(g2).equals(Buffer.from(points.tail))) {
    fail(`${step.key}: the points the chain used are not the bytes of the full transcript.`);
  }
  const digest = whole.digest();
  const sigHex = Buffer.from(await fetchBytes(`${BUCKET}/${step.dir}/transcript00.sig`)).toString("utf8").trim().replace(/^0x/, "");
  const sig = Buffer.from(sigHex, "hex");
  const v = sig[64] >= 27 ? sig[64] - 27 : sig[64];
  const message = keccak_256(Buffer.concat([Buffer.from("\x19Ethereum Signed Message:\n32"), digest]));
  const publicKey = secp256k1.Signature.fromBytes(sig.subarray(0, 64), "compact").addRecoveryBit(v)
    .recoverPublicKey(message).toBytes(false);
  const signer = "0x" + Buffer.from(keccak_256(publicKey.subarray(1))).toString("hex").slice(-40);
  if (signer !== step.address.toLowerCase()) {
    fail(`${step.key}: the transcript is signed by ${signer}, not the participant.`);
  }
  log(`ok signer ${step.address}: signed this exact transcript (SHA-256 ${Buffer.from(digest).toString("hex").slice(0, 16)}...), `
    + "its checksum holds, and the chain used its bytes");
}

// --- Main ------------------------------------------------------------------------------

async function main () {
  const argv = process.argv.slice(2);
  const signersArg = argv[argv.indexOf("--signers") + 1];
  const signers = argv.includes("--signers") ? signersArg : "";
  fs.mkdirSync(CACHE, { recursive: true });

  const { manifest, participants } = await loadManifest();
  const { steps, points, sealed } = await verifyChain(participants);
  verifySealedTau(manifest, sealed);
  const srs = await loadSrs(sealed);
  verifySrsStructure(srs, sealed.x2);
  verifyFrontendSrs(srs);
  verifyDerivation(srs);

  if (signers) {
    const wanted = signers === "all"
      ? steps.slice(0, -1)
      : signers.split(",").map((a) => {
        const i = steps.findIndex((s) => s.address.toLowerCase() === a.trim().toLowerCase());
        if (i < 0) {
          fail(`${a} is not an Ignition participant.`);
        }
        return i;
      }).map((i) => steps[i]);
    const indices = wanted.map((w) => steps.indexOf(w));
    await inBatches(indices, 4, (i) => verifySigner(steps[i], points[i]));
    log("IGNITION VERIFIED, WITH SIGNATURES: the named participants signed their contributions, the chain "
      + "carries them into the sealed tau, and the Registry's verifier derives from it.");
  } else {
    log("IGNITION CHAIN VERIFIED: the published transcripts compose into exactly the reference string and "
      + "tau the Registry's verifier uses.");
    log("This does not yet show the transcripts are the participants' own. Check the signature of at least "
      + "one participant you trust:");
    log("  make ignition-verify SIGNERS=<address>[,<address>...]   (or SIGNERS=all: 176 x 322 MB, streamed)");
    log("Participants include " + participants.slice(0, 4).map((p) => p.address).join(", ") + ", ...; see "
      + ".toolchain/ignition/manifest.json for all of them.");
  }
}

main().catch((e) => {
  console.error("FAILED: " + (e.message || e));
  process.exit(1);
});
