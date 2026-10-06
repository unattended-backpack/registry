# Registry

> Wherefore by their fruits ye shall know them.

An onchain directory of Ethereum Foundation personnel in which every profile
is private. Each profile is a key-value store of text records, and it is
gated by email: a zero-knowledge proof that an `@ethereum.org` address sent a
DKIM-signed email authorizing a controller is the only way a profile comes
into being, the only way its controller moves, and the only way it stays
alive.

## Status

The Registry runs on Sepolia, and the site's `frontend/config.js` points at
it by default; it is not yet on mainnet. Every contract is verified on
Etherscan:

- Registry:
  [`0xB3aBD4C3D27B071641A963a5539C48B2cA167778`](https://sepolia.etherscan.io/address/0xB3aBD4C3D27B071641A963a5539C48B2cA167778)
- Verifier:
  [`0x48C702f823c5bf073cEDad840f5b0f68C3fCc00e`](https://sepolia.etherscan.io/address/0x48C702f823c5bf073cEDad840f5b0f68C3fCc00e)
- HonkVerifier:
  [`0x0fB1c922415fd38c770D1525A7fd6aC1F33fA779`](https://sepolia.etherscan.io/address/0x0fB1c922415fd38c770D1525A7fd6aC1F33fA779)

Management is the deploying account,
`0x18091E9138251b9c854dCe077C0784A529eEc16D`, and it honors ethereum.org's
current Google DKIM key. To use the site, serve `frontend/` and connect it
to a Sepolia RPC, ideally your own node. [Trying it](#trying-it) shows how
to stand up a private deployment on a local chain instead.

## How it works

A profile belongs to an address and a secret. Its owner generates a random
salt, keeps it, and the profile's ID is `sha256(salt || lowercased address)`.
Nobody without the salt can compute an ID from an address or reverse one, so
the directory says how many verified staff hold profiles and nothing about
who they are. A person may hold several profiles, one per salt; the Registry
does not try to prevent it, because management could mint extra profiles
anyway (see below).

Email speaks only at identity events, through one subject line:

- `Set controller to 0x{commitment}`, where the commitment is the SHA-256 of
  a version tag, the controller, the chain ID, the Registry's address, and the
  salt. Registration (`register`) binds a controller, never zero. Renewal and
  rotation (`setController`) additionally require the current controller's
  EIP-712 signature over that exact email; renewal authorizes the current
  controller again. Neither the email nor the controller alone moves the
  root.

The circuit checks the subject against the commitment privately and never
reveals it. Anyone who can read the email (Google, Workspace admins, a
retention archive, the second inbox) sees an opaque hash that only the salt's
holder can open, so the email and the chain share no visible string. The
proof also withholds the sender's address and rounds the email's time down to
the week, and its nullifier hashes the DKIM signature together with the salt,
so holding the email is not enough to recognize its nullifier onchain. The
subject must match exactly: a reply or a forward prefixes it with `Re:` or
`Fwd:` and fails.

One link survives: timing. An email holder knows when the email was sent,
and the chain shows when its transaction landed. Every email stays usable for
at least four weeks after it is sent (at most five, because of the week
rounding), so its owner can prove it at once and broadcast the transaction
later, from an account with no link to them or through any relayer. The
controller itself is public, and is meant to be an account with no link to
its owner: it only signs, and never needs funds.

Proving an email takes nothing but the email. A staffer sends the subject
line from their `@ethereum.org` address to any other inbox they can read,
downloads the original message, and proves it on their own machine, in the
browser or on the command line. There is no relayer, no forwarder, and no
invitation to answer. The second inbox is the one requirement: Google signs
mail only as it leaves Google, so mail sent to one's own address carries no
DKIM signature at all.

A profile stays active for 90 days after its latest email. With the week
rounding, a renewal buys 83 to 90 days from the moment its email is sent,
and less if it is broadcast later. Its owner renews by sending a fresh
email. Someone who leaves the Foundation loses the mailbox, cannot renew, and
lapses on their own; offboarding is automatic and at most one renewal period
late. A lapsed profile is read-only until renewed, and keeps its records.
Once a profile lapses, anyone may flag it inactive ("former EF") with
`setActive`; its owner stopped proving membership, so saying so takes no
special power. A flagged profile can no longer renew unless management
restores it, and its owner registers a fresh one instead. A lost controller
key or a lost salt costs nothing permanent either: the profile lapses, and
its owner registers a fresh one.

The records are the controller's business only, and never cost a proof:
edited directly by transaction (`setText`, or `setTexts` for several at
once), or by a relayed EIP-712 signature (`setTextSigned`, or
`setTextsSigned` for a batch under one signature, each replay-protected by a
per-profile nonce) so that a controller that can sign but not transact, such
as a bare ERC-1271 signer, wields full control. A batch writes in order, so a
later write to a key overrides an earlier one. An empty signed batch writes
nothing and consumes the nonce, which revokes every signed write the
controller has handed out and not yet seen broadcast. The frontend always
takes the signed batch path: the controller signs every change to a
profile's records at once, and the page hands over one complete transaction
to copy to any relayer or to broadcast from any account.

Every email acts exactly once: its subject commits to one salt, so it has
one nullifier (`emailNullifier`), which the first use spends. The emails
honored for one profile never run backwards in time, so a relayer can
neither replay nor reorder them. Record keys may not be empty or contain
spaces.

**The sole administrative role is `management`**, a multisig: it maintains
the set of DKIM public key hashes honored for the domain, it may flag any
profile inactive (read-only, unable to renew) and it alone may restore one,
and it hands itself over in two steps. Management cannot edit or delete
profiles, and since IDs name nobody it can only flag a standing profile it
has some other reason to recognize. It can never move a profile's
controller either: renewal and rotation need that profile's controller
signature.

The DKIM authority lives in the Registry itself, so the Foundation is
sovereign over its own gate: key rotation answers to the management multisig
and to nobody else. The edge of that power is stated plainly: management
could honor a key of its own making and mint profiles at will. Every email's
key hash is emitted in `EmailAuthorized`, so anyone can check each profile's
key against the keys the domain publishes in DNS, and every honored key is
itself an onchain transaction. The verifier and the domain are pinned at
construction and immutable.

## The circuit

The circuit is ours. `circuits/` holds a Noir program that verifies an
RSA-2048 DKIM signature over an email's signed header, checks that the
subject commits to the controller, chain, and Registry it is given and to a
private salt, and reveals exactly what the Registry needs: the sender's
domain, the week of the email, the hash of the signing key, the salted
nullifier, and the profile ID. It never reads the body. At roughly 171,000
gates it proves on one browser thread in under twenty seconds.

We replaced the circuit. The ZK Email circuit this project once vendored
assumed a relayer that mails each user an invitation to reply to; that
workflow was fixed in its trusted setup, and no setting of the contracts
could remove it.

It proves with UltraHonk (Barretenberg 5.2.0, Noir 1.0.0-beta.25) over a
universal reference string: the powers of a secret tau, produced once, for
everyone, by the AZTEC Ignition ceremony (176 participants, October 2019 to
January 2020). If any one participant destroyed their randomness, nobody
knows tau and no proof can be forged. There is no circuit-specific setup to
run. Two goals carry the chain of custody from that ceremony to the deployed
bytecode, and neither trusts Aztec's tools:

- `make verifier-check` recompiles the circuit from source with the pinned
  toolchain, derives the Solidity verifier, and requires the vendored
  verifier and the frontend's compiled circuit to match byte for byte.
- `make ignition-verify` checks the ceremony itself, from Aztec's public
  transcripts, with its own pairing arithmetic. It verifies that every
  contribution builds on the last, in the manifest's order, from the
  generator through all 176 participants to the sealed output; that the
  sealed tau is the one hardcoded in the vendored verifier and shipped with
  the frontend; that the 2^18 reference points the circuit needs are
  consecutive powers of it (and are the frontend's, point for point); and
  that bb, cut off from the network, derives the vendored verifier byte for
  byte from those verified points alone. The download is a few megabytes and
  takes under a minute.

The transcripts compose correctly whoever published them; what makes them
trustworthy is that their participants signed them. `make ignition-verify
SIGNERS=<address>,...` streams each named participant's full transcript,
recovers the signer of its hash, and ties the points the chain used to those
signed bytes. One honest participant you recognize is enough; `SIGNERS=all`
checks every one (176 transcripts of 322 MB, streamed, never stored).

RSA and bignum arithmetic come from zkpassport's maintained forks of
`noir_rsa` and `noir-bignum`, SHA-256 from `noir-lang`, each pinned by tag.

## Layout

- `contracts/src/Registry.sol`: the registry
- `contracts/src/Verifier.sol`: the immutable proof verifier, which rebuilds
  the circuit's public inputs from an `EmailProof`, binding the calling
  registry and the current chain
- `contracts/src/vendor/HonkVerifier.sol`: the Barretenberg-generated
  UltraHonk verifier holding the circuit's verification key, vendored byte
  for byte
- `contracts/src/interfaces/`: `IVerifier` with `EmailProof`,
  `IHonkVerifier`, and CreateX
- `contracts/script/`: the deployments; `DeployVerifier` and `Deploy` for
  production through CreateX, `DeployLocal` for a local anvil, and
  `DeployDemo` for any other chain but mainnet
- `contracts/test/`: the unit, invariant, verifier, and fork suites
- `circuits/`: the email circuit, the DKIM key hash program, the input
  generator's tests, and the command-line prover (see `circuits/README.md`)
- `frontend/`: the static web client, which proves in the browser (see
  `frontend/README.md`)

## Development

The pinned proving toolchain installs into `.toolchain/`, never over a
global install, and each download is checked against its SHA-256. The
`contracts/` directory holds the [Foundry](https://getfoundry.sh/) project;
its dependencies ([Solady](https://github.com/Vectorized/solady), forge-std)
are managed with [Soldeer](https://soldeer.xyz/). From the repository root:

```sh
make toolchain         # nargo 1.0.0-beta.25 and bb 5.2.0, into .toolchain/
make circuits-install  # the pinned JavaScript tooling (npm ci)
make circuits-test     # compile the circuit; run its tests
make verifier-check    # prove the vendored verifier is the circuit's
make ignition-verify   # prove it rests on the Ignition ceremony
make test              # the contract suites
make e2e               # the frontend, end to end, in headless Chromium
```

Solidity sources, except the generated HonkVerifier, are formatted with
`dove preen`. The Registry's unit tests
run against a mock verifier that accepts exactly the proofs a test builds for
a given controller, chain, and registry, so every policy check in the
registry itself (domain, key hashes, nullifier, email lifetime, timestamp
order, controller binding, controller signature, nonce, revocation, lapse and
renewal) is exercised in isolation from the circuit; the invariant campaign
drives a cast of identities, controllers, and managements through every
action. The verifier's tests run against real proofs, and register, renew,
rotate, and lapse a profile end to end at the exact address those proofs
bind. Their synthetic vectors come from emails signed with a throwaway test
key; real `ethereum.org` vectors, when present, run the same lifecycle
(`make vectors` regenerates both). The circuit's tests check the input
generator against an independent DKIM implementation and refuse a tampered
input for every constraint that matters. The fork tests (`make test-fork`)
rehearse the CreateX deployment on a fork of whatever chain `RPC_URL` in
`.env` names, the same chain the deployment goals target.

To register from the command line, make a secret and the subject line, send
the email, then prove it; the DKIM key is looked up in DNS through your own
resolver unless `KEY` names a file:

```sh
make subject CONTROLLER=0x... CHAIN_ID=1 REGISTRY=0x...   # prints a new secret
make prove EML=message.eml SALT=0x... CONTROLLER=0x... CHAIN_ID=1 REGISTRY=0x... OUT=proof.json
```

`make e2e` drives the real frontend in headless Chromium against its own
local chain, through every flow from registration to rotation, and fails if
the page contacts any host but the site and the chain.

## Trying it

To try the frontend by hand on a local chain:

1. Run `make demo-anvil` in one terminal. It starts anvil on port 8545
   (`DEMO_PORT` picks another) at the fixture emails' own time, so they stay
   usable; `DEMO_TIME=now` starts it at the present, for emails sent today.
2. Run `make demo-deploy`. It deploys the stack and honors the live
   ethereum.org key and the test key that signed the synthetic emails.
3. In `frontend/config.js`, set `chainId` to 31337, `registryAddress` to the
   address the deploy prints, and `deployBlock` to 0. To prove the synthetic
   emails, add the record in `circuits/test/fixtures/test-dkim.txt` to
   `dkimKeys` under the selector `test`.
4. Serve `frontend/` (`python3 -m http.server` will do) and enter the chain's
   URL as the RPC.

The fixtures use the secret `0x7e57` and the controller
`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, anvil's first development
account; import its key into your wallet to sign as it. Any funded anvil
account can broadcast.

To try it on any other chain but mainnet, `make demo-deploy-chain
DEMO_RPC_URL=<rpc> DEMO_PRIVATE_KEY=<funded key>` deploys a fresh stack there,
with the key's account as management, honoring the live key only. Point
`frontend/config.js` at what it prints: the chain, the Registry, and the
block to read records from. Nothing is pinned, so send fresh emails: a
subject line names its chain and its Registry, and the fixture emails name
the local anvil.

## Deployment

Deployment goes through the
[CreateX](https://github.com/pcaversaccio/createx) factory so each contract
can be pinned to a salt-ground address (CREATE3 addresses depend only on the
factory and the salt, not the creation code). Project-pinned defaults
(`DOMAIN`, `CREATEX`) live in `.env.maintainer`; deployer configuration (RPC,
deployer private key, ground salts and their expected addresses, the
verifier, the management multisig, the Etherscan key) is documented in
`.env.example`. From the repository root:

```sh
cp .env.example .env         # fill in the values
make deploy-verifier-dry     # simulate the verifier pair
make deploy-verifier         # deploy and verify the HonkVerifier and Verifier
make deploy-dry              # simulate the Registry; checks the CreateX address
make deploy                  # deploy and verify the Registry
make key-hash SELECTOR=gmail # the hash management honors for the live key
```

During `make deploy-verifier`, forge deploys the HonkVerifier's two linked
libraries, `RelationsLib` and `ZKTranscriptLib`, ahead of it and records
their addresses under `libraries` in the run's broadcast file
(`contracts/broadcast/DeployVerifier.s.sol/1/run-latest.json`). Before
deploying the Registry, copy the Verifier's address into `VERIFIER` and the
two library addresses into `RELATIONS_LIB` and `ZK_TRANSCRIPT_LIB`. Both
deploy goals verify their contracts on Etherscan as they go; `make verify`
re-runs that verification for the whole stack.

After deployment, management honors the domain's current DKIM key hash with
`setDKIMPublicKeyHash`, and the first email can then act. When the domain
rotates its key, management honors the new hash and, once the old key is
retired, revokes the old one. Point `frontend/config.js` at the deployment
(the chain, the Registry, and the block it was deployed in) before serving or
pinning the site. `make help` lists all goals.
