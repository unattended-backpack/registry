# Registry frontend

A static, self-contained web client for the Registry. The directory you are
reading *is* the deployable site: there is no build step, no bundler, and no
server. Serve these files from anything, or pin them to IPFS.

```sh
cd frontend
python3 -m http.server 8080   # then open http://localhost:8080
```

```sh
ipfs add -r frontend          # pin the directory; open via any gateway
```

## What it does

- **Browse** the directory: read every profile and its text records over your
  configured RPC. Nothing is written.
- **Manage** a profile as its controller: set a record with an ordinary
  transaction (`setText`), or, for a signer that cannot transact (a bare
  ERC-1271 key), sign the record write (`setTextSigned`) for any relayer to
  submit. Rotate the controller with an email proof plus the current
  controller's signature.
- **Register** a profile: build the exact email command, prove the email
  locally, and submit.

## Sovereignty

The site makes no network calls of its own. The only endpoints it touches are
the ones you choose: your RPC (for reads), your wallet (for writes and
signatures), and the prover artifact location (for proving). ethers and
snarkjs are vendored under `vendor/`, so nothing is fetched from a CDN at
runtime. Your email, your keys, and your signatures never leave the browser.

Point `rpcUrl` at your own node for the fullest version of this. Everything in
`config.js` can also be changed at runtime in the Settings panel, which saves
to this browser only; edit `config.js` to change the defaults for everyone
before pinning.

## Local proof generation

Proving runs in a Web Worker (`worker.js`) on your machine. The circuit
artifacts are large (the ceremony zkey is gigabytes), so they are hosted
separately rather than shipped here. Set **Prover artifact base** in Settings
to a location (an IPFS path, a local server, a `file://` directory) that
holds:

- `email_auth.wasm` — the witness generator, from `make circuits`
  (`circuits/build/email_auth_js/email_auth.wasm`).
- `emailauth_final.zkey` — the ceremony proving key, the same file
  `make zkey-verify` validates. For browsers, a chunked variant is usually
  needed; see snarkjs's chunked-zkey guidance.
- `zkemail-input.js` — a UMD script that turns a raw `.eml` into the circuit
  inputs. It must define `self.zkemailInput.generate(emlText, { command })`
  returning `{ inputs, meta }`, where `meta` carries the EmailProof scalar
  fields (`domainName`, `publicKeyHash`, `timestamp`, `maskedCommand`,
  `emailNullifier`, `accountSalt`, `isCodeExist`). This wraps ZK Email's
  `relayer-utils` (WASM) for the `email_auth` circuit; it is circuit-specific,
  which is why it is supplied alongside the artifacts rather than vendored.

When the artifact base is empty, in-browser proving is disabled and the
**Import Proof** path takes over: prove with the local CLI and paste the
result. It accepts either a finished `EmailProof` JSON (with `proof` as
`0x`-hex bytes) or a snarkjs bundle `{ proof: {pi_a,pi_b,pi_c}, publicSignals,
meta }`, and packs the proof bytes exactly as the on-chain `Verifier` decodes
them.

## The register flow, end to end

1. Enter the controller address you will hold and build the command. It reads
   `Set controller to {address} {chainId}:{registry}`, checksummed and bound
   to this exact deployment.
2. From your `@ethereum.org` address, email that command to yourself, with
   your ZK Email invitation code in the body, and export the raw message
   ("Show original" in Gmail) as `.eml`.
3. Prove the `.eml` locally (or import a CLI proof). The proof yields your
   profile id, which is your ZK Email account salt.
4. Connect any wallet and submit. Whoever submits is irrelevant; the proof is
   the authority.

Records afterward are the controller's, by transaction or by relayed
signature, and never need another proof. Email is only for registration and
for rotating the controller.
