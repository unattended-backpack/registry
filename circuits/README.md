# Circuits

The Registry's email circuit, in [Noir](https://noir-lang.org/), proven with
UltraHonk by [Barretenberg](https://github.com/AztecProtocol/aztec-packages).
A proof says: a DKIM key signed an email header from an address at a given
domain, and the email's subject authorizes a given controller, on a given
registry and chain, for the private profile a secret salt defines. The
address, the subject, the salt, and the exact time stay hidden.

- `lib/`: the constraints (`registry_email`), shared by both programs below
- `email_proof/`: the circuit a proof runs
- `dkim_key_hash/`: a program management executes (never proves) to compute
  the key hash it honors, from the same function the circuit calls
- `scripts/subject.mjs`: prints a profile's secret and subject line
- `scripts/prove.mjs`: the command-line prover
- `scripts/key-hash.mjs`: management's key hash tool
- `scripts/make-vectors.mjs`: regenerates the proof vectors the contract
  tests load
- `scripts/ignition-verify.mjs`: verifies the Ignition ceremony and the
  chain of custody from it to the vendored verifier
- `scripts/fixture-time.mjs`: the chain time at which every fixture email is
  usable, for `make demo-anvil` and `make e2e`
- `test/e2e.mjs`: the browser end-to-end test (`make e2e`)
- `scripts/bundle-prover.mjs` and `prover/`: the source of the frontend's
  vendored browser prover
- `test/`: the circuit and input generator tests, the emails they run on,
  and the proof vectors the contract tests load

The input generator lives in `frontend/email-input.js`, so the browser and
the command line feed the circuit the same bytes and compute the same subject
lines and profile IDs.

## What the circuit checks

The circuit takes the DKIM signing input: the signed header fields in relaxed
canonical form, ending with the DKIM-Signature field itself with its `b=`
value emptied. Relaxed canonicalization lowercases every field name and
unfolds every value, so each CRLF in that input ends exactly one field. Its
public inputs are the controller, the chain ID, and the registry; its private
witness is the header, the key, the signature, the salt, and the offsets of
the fields it reads. The circuit then:

1. hashes the header with SHA-256 and verifies the RSA-2048 PKCS#1 v1.5
   signature over it, with the signature constrained below the modulus so
   one email cannot yield two nullifiers;
2. pins a `subject` field to one whole line of the header and requires its
   value to be exactly `Set controller to 0x` followed by the lowercase hex
   SHA-256 of `registry.set-controller.v1 || controller (20 bytes) ||
   chain ID (32) || registry (20) || salt (32)`, all big-endian, and nothing
   else; `to_be_bytes` also constrains the controller and the registry to be
   addresses;
3. pins a `from` field the same way, takes the address inside its last
   `<...>` (or the whole value when there is no bracket), requires exactly
   one `@`, and lowercases it;
4. pins the `dkim-signature` field, which must end the header (and so is the
   verified signature's own), and reads its ten-digit `t=` tag at a tag
   boundary.

It returns eight public outputs, which follow the three public inputs in the
order the on-chain `Verifier` rebuilds them: the domain (three 31-byte
fields, big-endian, zero-padded, no zero byte inside), the Pedersen hash of
the key's modulus limbs, the Pedersen hash of the signature limbs and the
salt as the email nullifier, the `t=` timestamp rounded down to a multiple of
one week, and the profile ID `sha256(salt || lowercased address)` as high and
low halves. One salt feeds the commitment, the nullifier, and the ID, so an
email authorizes exactly one profile.

The limits are constants in `lib/src/lib.nr`: a signed header of at most
1024 bytes (Gmail's run near 700), a subject of exactly 84 bytes, a 2048-bit
key with exponent 65537. The body is never read, so the circuit is about
171,000 gates.

## Trust

UltraHonk proves over a universal reference string, the powers of a secret
tau from the AZTEC Ignition ceremony, so there is no circuit-specific setup.
Soundness rests on the circuit, on the verification key baked into the
generated `HonkVerifier.sol`, and on nobody knowing tau: the verifier holds
tau in G2, and the key's commitments were computed from tau's powers in G1.

`make ignition-verify` (`scripts/ignition-verify.mjs`) checks all of that
from Aztec's public transcripts with its own pairing arithmetic
(`@noble/curves`), caching a few megabytes under `.toolchain/ignition/`:

1. The manifest matches its pinned SHA-256, and its 176 participants and 21
   invalidated slots fill positions 1 to 197 exactly.
2. For every participant in that order, and for the sealed output, the first
   G1 point and both G2 points of the first transcript file (fetched by byte
   range) satisfy x_i = z_i * x_(i-1), starting from the generator, and each
   transcript's G1 and G2 points agree.
3. The sealed tau is the manifest's, the verifier's hardcoded G2 point, and
   the frontend's G2 file; the verifier's other G2 point is the generator.
4. The first 2^18 sealed G1 points are consecutive powers of that tau (one
   pairing over two random linear combinations), and the frontend's
   compressed points are exactly them.
5. bb, run under `unshare -rn` with no network, derives the verification key
   and the Solidity verifier from a reference string built only from those
   points, and the result is the vendored verifier, byte for byte.

These prove the published transcripts compose into exactly what the Registry
uses. That the transcripts are the participants' own is a matter of their
signatures: `SIGNERS=<address>,...` (or `all`) streams each named
participant's full first transcript (322 MB), checks its BLAKE2b checksum,
recovers the Ethereum address that signed its SHA-256, and requires the
points of step 2 to be those very bytes. Trusting any one signer you verify
is enough.

The toolchain is pinned in the root `Makefile`: Barretenberg 5.2.0 and the
Noir compiler it pins, 1.0.0-beta.25 (git `75061fab`). The libraries are
pinned by tag in `lib/Nargo.toml`: `noir_rsa` v0.12.0 and `noir-bignum`
v0.10.0-2 from zkpassport's maintained forks, and `sha256` v0.3.0 from
noir-lang. In this bignum version the Barrett reduction parameter only
steers witness generation and cannot make a false signature verify, so the
key hash commits to the modulus alone; a test confirms a wrong parameter
changes nothing a proof reveals.

## Use

From the repository root:

```sh
make toolchain                 # pinned nargo and bb, into .toolchain/
make circuits-install          # pinned JavaScript tooling
make circuits-test             # compile, then run the tests
make verifier-check            # the vendored verifier and circuit are ours
make ignition-verify           # the Ignition ceremony they rest on [SIGNERS=]
make subject CONTROLLER=0x... CHAIN_ID=1 REGISTRY=0x...   # a secret and its subject
make prove EML=message.eml SALT=0x... CONTROLLER=0x... CHAIN_ID=1 REGISTRY=0x...
make vectors                   # regenerate the contract tests' proof vectors
make key-hash SELECTOR=gmail   # the key hash for gmail._domainkey.<DOMAIN>
```

After changing the circuit, `make vendor` rewrites the vendored verifier and
the frontend's compiled circuit, and `make frontend-vendor` rebuilds the
browser prover.

The fixtures under `test/fixtures/` come in two kinds. The `synthetic-*`
emails are signed with the throwaway key `test-dkim.pem` and carry no real
person; every contract test runs on them. The `ethereum-org-private-*`
emails are real, sent from an `ethereum.org` account: their signed headers
carry the sender's and the recipient's addresses and cannot be redacted
without breaking the signature. The tests that use them skip when they are
absent, so they can be deleted, with the `real-*` vectors, before
publishing.
