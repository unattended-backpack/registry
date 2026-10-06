// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// Turn a raw email into the inputs of the Registry's email circuit.
//
// This module has no dependencies and makes no network calls. It runs
// unchanged in the browser (the frontend's proving worker) and in Node (the
// command-line prover in `circuits/scripts`), so both provers feed the circuit
// the same bytes.
//
// The circuit proves a DKIM signature over the signed header alone. This
// module rebuilds that signed header exactly as the signer did (relaxed
// canonicalization, RFC 6376 section 3.4.2), locates the From, Subject, and
// DKIM-Signature fields inside it, and encodes the RSA values as the 120-bit
// limbs the circuit's bignum library expects. It also computes, from a
// profile's secret salt, the subject an email must carry and the profile's
// id, exactly as the circuit does; the salt never leaves this module's
// caller.

// The circuit's limits. They must match `circuits/lib/src/lib.nr`.
export const CIRCUIT = Object.freeze({
  MAX_HEADER_LENGTH: 1024,
  KEY_BITS: 2048,
  KEY_LIMBS: 18,
  MAX_FROM_LENGTH: 256,
  MAX_ADDRESS_LENGTH: 128,
  MAX_DOMAIN_LENGTH: 93,
  MAX_DKIM_LENGTH: 512,
  PUBLIC_INPUTS: 3,
  PUBLIC_OUTPUTS: 8,
  WEEK: 604800
});

// The private subject line. An email authorizes a controller by carrying, as
// its whole subject, `SUBJECT_PREFIX` followed by the lowercase hex SHA-256 of
// the commitment preimage below. The circuit recomputes the hash from the
// controller, chain, and registry (public) and the profile's salt (secret),
// and never reveals the subject, so no email holder can match the subject to
// anything on chain.
export const SUBJECT_PREFIX = "Set controller to 0x";
export const COMMITMENT_TAG = "registry.set-controller.v1";
export const SUBJECT_LENGTH = SUBJECT_PREFIX.length + 64;

// A compact, synchronous SHA-256, so this module needs neither WebCrypto nor
// Node's crypto. Checked against node:crypto in the circuit tests.
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

export function sha256 (bytes) {
  const length = bytes.length;
  const padded = new Uint8Array(((length + 9 + 63) >> 6) << 6);
  padded.set(bytes);
  padded[length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(length / 0x20000000));
  view.setUint32(padded.length - 4, (length << 3) >>> 0);
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(off + 4 * i);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g))
        + K256[i] + w[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0; h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  h.forEach((word, i) => outView.setUint32(4 * i, word));
  return out;
}

const hexOf = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

// The BN254 scalar field modulus; a salt must lie below it.
const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// A nonnegative integer as `size` big-endian bytes.
function toBytesBE (x, size) {
  const value = BigInt(x);
  if (value < 0n || value >> BigInt(8 * size)) {
    throw new Error(`Value does not fit ${size} bytes.`);
  }
  const out = new Uint8Array(size);
  let v = value;
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
  Parse and check a profile secret: the salt, as 0x-hex, below the field
  modulus. Returns it as a BigInt.
*/
export function parseSalt (salt) {
  const s = String(salt).trim();
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(s)) {
    throw new Error("A profile secret is 0x-prefixed hex.");
  }
  const value = BigInt(s);
  if (value === 0n || value >= FIELD_MODULUS) {
    throw new Error("The profile secret is out of range.");
  }
  return value;
}

/**
  Generate a fresh profile secret: 31 random bytes, which always lie below
  the field modulus. Uses the platform's cryptographic randomness.
*/
export function generateSalt () {
  const bytes = new Uint8Array(31);
  crypto.getRandomValues(bytes);
  if (bytes.every((b) => b === 0)) {
    bytes[30] = 1;
  }
  return "0x" + hexOf(bytes).padStart(64, "0");
}

/**
  The bytes the subject commits to: the tag, the controller (20 bytes), the
  chain id (32 bytes), the registry (20 bytes), and the salt (32 bytes), all
  big-endian.
*/
export function commitmentPreimage ({ controller, chainId, registry, salt }) {
  const tag = new TextEncoder().encode(COMMITMENT_TAG);
  const parts = [
    tag,
    toBytesBE(BigInt(controller), 20),
    toBytesBE(BigInt(chainId), 32),
    toBytesBE(BigInt(registry), 20),
    toBytesBE(parseSalt(salt), 32)
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/// The exact subject an email must carry to authorize `controller`.
export function privateSubject (args) {
  return SUBJECT_PREFIX + hexOf(sha256(commitmentPreimage(args)));
}

/**
  The Registry profile id of an address and its secret: the SHA-256 of the
  salt (32 bytes, big-endian) followed by the lowercased address. Only the
  holder of the secret can compute it.
*/
export function privateProfileId (address, salt) {
  const saltBytes = toBytesBE(parseSalt(salt), 32);
  const addressBytes = new TextEncoder().encode(address.trim().toLowerCase());
  const preimage = new Uint8Array(32 + addressBytes.length);
  preimage.set(saltBytes);
  preimage.set(addressBytes, 32);
  return "0x" + hexOf(sha256(preimage));
}

const LIMB_BITS = 120n;
const LIMB_MASK = (1n << LIMB_BITS) - 1n;

// Bytes and "binary strings" (one char per byte) convert losslessly, which
// lets the parsing below use ordinary string operations on raw octets.
function bytesToBinary (bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return s;
}

function binaryToBytes (s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(i) & 0xff;
  }
  return out;
}

function toBinary (raw) {
  if (typeof raw === "string") {
    return bytesToBinary(new TextEncoder().encode(raw));
  }
  return bytesToBinary(raw instanceof Uint8Array ? raw : new Uint8Array(raw));
}

function base64ToBytes (b64) {
  const clean = b64.replace(/[\s]/g, "");
  if (typeof atob === "function") {
    return binaryToBytes(atob(clean));
  }
  return new Uint8Array(Buffer.from(clean, "base64"));
}

function bytesToBigInt (bytes) {
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return hex.length ? BigInt("0x" + hex) : 0n;
}

// Split the header block into raw fields, keeping folded continuation lines
// with the field they continue.
function parseFields (headerBlock) {
  const fields = [];
  for (const line of headerBlock.split("\r\n")) {
    if (line === "") {
      continue;
    }
    if ((line[0] === " " || line[0] === "\t") && fields.length) {
      fields[fields.length - 1].raw += "\r\n" + line;
      continue;
    }
    const colon = line.indexOf(":");
    if (colon < 1) {
      throw new Error("Malformed header line: " + line.slice(0, 60));
    }
    fields.push({ name: line.slice(0, colon).trim().toLowerCase(), raw: line });
  }
  return fields;
}

// Relaxed header canonicalization of one raw field (RFC 6376, 3.4.2).
function relaxedField (raw) {
  const colon = raw.indexOf(":");
  const name = raw.slice(0, colon).replace(/[ \t]+$/, "").toLowerCase();
  const value = raw.slice(colon + 1)
    .replace(/\r\n/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/^ /, "")
    .replace(/ $/, "");
  return name + ":" + value;
}

// Parse a DKIM tag list (`k=v; k=v`) into a map of trimmed values.
function parseTags (value) {
  const tags = {};
  for (const part of value.replace(/\r\n/g, "").split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) {
      continue;
    }
    tags[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return tags;
}

// A minimal DER reader, enough for an RSA public key.
function readTLV (bytes, offset) {
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let start = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) {
      length = (length << 8) | bytes[start + i];
    }
    start += count;
  }
  return { tag, start, end: start + length };
}

/**
  Read an RSA public key from a DKIM DNS TXT record (`v=DKIM1; k=rsa; p=...`)
  or from its bare `p=` value. Accepts SubjectPublicKeyInfo or PKCS#1 DER.
*/
export function parseDkimKey (txt) {
  const trimmed = txt.trim().replace(/^"|"$/g, "").replace(/"\s*"/g, "");
  const p = trimmed.includes("p=") ? parseTags(trimmed).p : trimmed;
  if (!p) {
    throw new Error("The DKIM record holds no key (p= is empty or missing).");
  }
  const der = base64ToBytes(p);
  let seq = readTLV(der, 0);
  let first = readTLV(der, seq.start);
  if (first.tag === 0x30) {
    // SubjectPublicKeyInfo: skip the algorithm, open the BIT STRING.
    const bits = readTLV(der, first.end);
    seq = readTLV(der, bits.start + 1);
    first = readTLV(der, seq.start);
  }
  const exponentTLV = readTLV(der, first.end);
  const modulus = bytesToBigInt(der.subarray(first.start, first.end));
  const exponent = bytesToBigInt(der.subarray(exponentTLV.start, exponentTLV.end));
  return { modulus, exponent };
}

/// Encode a nonnegative integer as the circuit's little-endian 120-bit limbs.
export function toLimbs (x, limbs = CIRCUIT.KEY_LIMBS) {
  if (x >> (LIMB_BITS * BigInt(limbs))) {
    throw new Error("Value does not fit the circuit's limbs.");
  }
  const out = [];
  for (let i = 0n; i < BigInt(limbs); i++) {
    out.push("0x" + ((x >> (LIMB_BITS * i)) & LIMB_MASK).toString(16));
  }
  return out;
}

/// The bignum library's Barrett reduction parameter: 2^(2k + 6) / n.
export function redcParam (modulus, bits = CIRCUIT.KEY_BITS) {
  return (1n << BigInt(2 * bits + 6)) / modulus;
}

// Find the unique signed field named `name`, as a run of the canonical header.
function fieldSequence (canonical, name, { last = false } = {}) {
  const hits = [];
  const needle = name + ":";
  if (canonical.startsWith(needle)) {
    hits.push(0);
  }
  let at = canonical.indexOf("\r\n" + needle);
  while (at >= 0) {
    hits.push(at + 2);
    at = canonical.indexOf("\r\n" + needle, at + 2);
  }
  if (!hits.length) {
    throw new Error(`The DKIM signature does not cover a ${name} field.`);
  }
  if (hits.length > 1 && !last) {
    throw new Error(`The signed header holds more than one ${name} field.`);
  }
  const index = hits[hits.length - 1];
  const stop = canonical.indexOf("\r\n", index);
  const end = stop < 0 ? canonical.length : stop;
  return { index, length: end - index, value: canonical.slice(index + needle.length, end) };
}

/**
  Rebuild the signed header for the email's DKIM signature from `domain`, the
  way the signer computed it. Returns the canonical header and the signature's
  tags. Throws, with a message a person can act on, whenever the email cannot
  be proven.
*/
export function signedHeader (raw, { domain } = {}) {
  const text = toBinary(raw).replace(/\r?\n/g, "\r\n");
  const split = text.indexOf("\r\n\r\n");
  const headerBlock = split < 0 ? text : text.slice(0, split + 2);
  const fields = parseFields(headerBlock);

  const signatures = fields
    .filter((f) => f.name === "dkim-signature")
    .map((f) => ({ field: f, tags: parseTags(f.raw.slice(f.raw.indexOf(":") + 1)) }));
  if (!signatures.length) {
    throw new Error("The email carries no DKIM signature. Mail you send to "
      + "yourself is not signed; send it to a different inbox.");
  }
  const wanted = domain ? domain.toLowerCase() : null;
  const chosen = signatures.find((s) =>
    (s.tags.d || "").toLowerCase() === wanted) || (wanted ? null : signatures[0]);
  if (!chosen) {
    throw new Error(`No DKIM signature from ${domain}; found `
      + signatures.map((s) => s.tags.d).join(", ") + ".");
  }
  const { tags } = chosen;
  if ((tags.a || "").toLowerCase() !== "rsa-sha256") {
    throw new Error("The DKIM signature is not rsa-sha256.");
  }
  if (!(tags.c || "simple/simple").toLowerCase().startsWith("relaxed")) {
    throw new Error("The DKIM signature uses simple header canonicalization, "
      + "which this circuit does not support.");
  }

  // Signed fields, each instance taken from the bottom up (RFC 6376, 5.4.2).
  // A name listed more often than it occurs contributes nothing.
  const used = {};
  let canonical = "";
  for (const listed of tags.h.split(":")) {
    const name = listed.trim().toLowerCase();
    const instances = fields.filter((f) => f.name === name && f !== chosen.field);
    const pick = instances.length - 1 - (used[name] || 0);
    used[name] = (used[name] || 0) + 1;
    if (pick >= 0) {
      canonical += relaxedField(instances[pick].raw) + "\r\n";
    }
  }

  // The signature's own field, with its b= value emptied, and no CRLF.
  const own = relaxedField(chosen.field.raw);
  const colon = own.indexOf(":");
  const emptied = own.slice(colon + 1).replace(/(^|;)( ?b=)[^;]*/, "$1$2");
  canonical += own.slice(0, colon + 1) + emptied;

  return { canonical, tags };
}

/**
  Build the circuit inputs for an email. `key` is the DKIM key, as a DNS TXT
  record string or as `{ modulus, exponent }`. `domain`, when given, selects
  the DKIM signature from that domain. `salt` is the profile's secret, and
  `controller`, `chainId`, and `registry` name the authorization the email's
  subject must commit to. `unchecked` skips the subject pre-check, for tests
  that need the circuit itself to refuse a wrong subject.

  Returns `{ inputs, meta }`: `inputs` is the circuit's input map; `meta`
  describes the email for the person proving it (the exact timestamp and the
  sender stay local; the proof reveals neither).
*/
export function buildInputs (raw, { key, domain, salt, controller, chainId, registry, unchecked } = {}) {
  const { canonical, tags } = signedHeader(raw, { domain });
  const { modulus, exponent } = typeof key === "string" ? parseDkimKey(key) : key;
  if (exponent !== 65537n) {
    throw new Error("The DKIM key's exponent is not 65537.");
  }
  if (modulus.toString(2).length !== CIRCUIT.KEY_BITS) {
    throw new Error("The DKIM key is not 2048 bits.");
  }
  if (canonical.length > CIRCUIT.MAX_HEADER_LENGTH) {
    throw new Error(`The signed header is ${canonical.length} bytes; the `
      + `circuit takes at most ${CIRCUIT.MAX_HEADER_LENGTH}.`);
  }

  const signature = bytesToBigInt(base64ToBytes(tags.b || ""));
  if (signature >= modulus) {
    throw new Error("The DKIM signature is not below the key's modulus.");
  }

  // From: the address is the run inside the last <...>, or the whole value.
  const from = fieldSequence(canonical, "from");
  if (from.value.length > CIRCUIT.MAX_FROM_LENGTH) {
    throw new Error("The From field is too long for the circuit.");
  }
  const bracket = from.value.lastIndexOf("<");
  let addressIndex;
  let address;
  if (bracket >= 0) {
    if (!from.value.endsWith(">")) {
      throw new Error("The From field must end with the address in <...>.");
    }
    address = from.value.slice(bracket + 1, -1);
    addressIndex = from.index + 5 + bracket + 1;
  } else {
    address = from.value;
    addressIndex = from.index + 5;
  }
  const lowered = address.toLowerCase();
  if (!/^[a-z0-9._+'-]+@[a-z0-9._+'-]+$/.test(lowered)) {
    throw new Error("The sender address holds characters the circuit rejects: "
      + address);
  }
  if (lowered.length > CIRCUIT.MAX_ADDRESS_LENGTH) {
    throw new Error("The sender address is too long for the circuit.");
  }
  const at = lowered.indexOf("@");
  const senderDomain = lowered.slice(at + 1);
  if (senderDomain.length > CIRCUIT.MAX_DOMAIN_LENGTH) {
    throw new Error("The sender domain is too long for the circuit.");
  }

  // Subject: exactly the authorization this salt and controller commit to.
  const subject = fieldSequence(canonical, "subject");
  const expected = privateSubject({ controller, chainId, registry, salt });
  if (subject.value !== expected && !unchecked) {
    throw new Error(`The email's subject reads "${subject.value}", but this `
      + `profile secret and controller need exactly "${expected}". Check the `
      + "secret, the controller, and the Registry, or send a new email.");
  }

  // DKIM-Signature: the last field; its t= tag is the timestamp.
  const dkim = fieldSequence(canonical, "dkim-signature", { last: true });
  if (dkim.index + dkim.length !== canonical.length) {
    throw new Error("The signed header does not end with its DKIM-Signature.");
  }
  if (dkim.value.length > CIRCUIT.MAX_DKIM_LENGTH) {
    throw new Error("The DKIM-Signature field is too long for the circuit.");
  }
  const t = /;( ?)t=(\d{10});/.exec(dkim.value);
  if (!t) {
    throw new Error("The DKIM signature carries no ten-digit t= timestamp.");
  }
  const timestampIndex = dkim.index + 15 + t.index + 1 + t[1].length + 2;

  const headerBytes = binaryToBytes(canonical);
  const storage = new Array(CIRCUIT.MAX_HEADER_LENGTH).fill("0");
  headerBytes.forEach((b, i) => { storage[i] = String(b); });

  const inputs = {
    controller: "0x" + BigInt(controller).toString(16),
    chain_id: "0x" + BigInt(chainId).toString(16),
    registry: "0x" + BigInt(registry).toString(16),
    header: { storage, len: String(headerBytes.length) },
    modulus: toLimbs(modulus),
    redc: toLimbs(redcParam(modulus)),
    signature: toLimbs(signature),
    salt: "0x" + parseSalt(salt).toString(16),
    from: { index: String(from.index), length: String(from.length) },
    address: { index: String(addressIndex), length: String(address.length) },
    at: String(at),
    subject: { index: String(subject.index), length: String(subject.length) },
    dkim: { index: String(dkim.index), length: String(dkim.length) },
    timestamp_index: String(timestampIndex)
  };
  const meta = {
    signingDomain: tags.d,
    selector: tags.s,
    domain: senderDomain,
    sender: lowered,
    subject: subject.value,
    timestamp: Number(t[2]),
    week: Math.floor(Number(t[2]) / CIRCUIT.WEEK) * CIRCUIT.WEEK,
    profileId: privateProfileId(lowered, salt),
    subjectMatches: subject.value === expected,
    headerLength: headerBytes.length
  };
  return { inputs, meta, canonical: headerBytes };
}

// Unpack big-endian 31-byte fields into the string they carry.
function unpackString (fields) {
  const bytes = [];
  for (const f of fields) {
    const hex = BigInt(f).toString(16).padStart(62, "0");
    for (let i = 0; i < 62; i += 2) {
      bytes.push(parseInt(hex.slice(i, i + 2), 16));
    }
  }
  const end = bytes.indexOf(0);
  return bytesToBinary(new Uint8Array(end < 0 ? bytes : bytes.slice(0, end)));
}

const toBytes32 = (x) => "0x" + BigInt(x).toString(16).padStart(64, "0");

/**
  Decode the circuit's eight public outputs into the fields of the on-chain
  `EmailProof` (every field but `proof`).
*/
export function decodePublicOutputs (outputs) {
  if (outputs.length !== CIRCUIT.PUBLIC_OUTPUTS) {
    throw new Error(`Expected ${CIRCUIT.PUBLIC_OUTPUTS} public outputs.`);
  }
  const high = BigInt(outputs[6]).toString(16).padStart(32, "0");
  const low = BigInt(outputs[7]).toString(16).padStart(32, "0");
  return {
    domainName: unpackString(outputs.slice(0, 3)),
    publicKeyHash: toBytes32(outputs[3]),
    emailNullifier: toBytes32(outputs[4]),
    timestamp: BigInt(outputs[5]).toString(),
    profileId: "0x" + high + low
  };
}

/**
  Decode a proof's full public inputs: the three the caller supplies (the
  controller, the chain id, the registry), then the eight outputs.
*/
export function decodePublicInputs (inputs) {
  const n = CIRCUIT.PUBLIC_INPUTS;
  if (inputs.length !== n + CIRCUIT.PUBLIC_OUTPUTS) {
    throw new Error(`Expected ${n + CIRCUIT.PUBLIC_OUTPUTS} public inputs.`);
  }
  const address = (x) => "0x" + BigInt(x).toString(16).padStart(40, "0");
  return {
    controller: address(inputs[0]),
    chainId: BigInt(inputs[1]).toString(),
    registry: address(inputs[2]),
    ...decodePublicOutputs(inputs.slice(n))
  };
}

/// Render circuit inputs as a nargo `Prover.toml`.
export function toProverToml (inputs) {
  const scalar = (v) => `"${v}"`;
  const lines = [];
  const tables = [];
  for (const [k, v] of Object.entries(inputs)) {
    if (Array.isArray(v)) {
      lines.push(`${k} = [${v.map(scalar).join(", ")}]`);
    } else if (typeof v === "object") {
      const body = Object.entries(v).map(([kk, vv]) => Array.isArray(vv)
        ? `${kk} = [${vv.map(scalar).join(", ")}]`
        : `${kk} = ${scalar(vv)}`);
      tables.push(`[${k}]\n${body.join("\n")}`);
    } else {
      lines.push(`${k} = ${scalar(v)}`);
    }
  }
  return lines.concat(tables).join("\n") + "\n";
}
