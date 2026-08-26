# Registry

> Wherefore by their fruits ye shall know them.

An onchain directory of Ethereum Foundation personnel. Each profile is a
key-value store of text records, in the shape of ENS text records so that it
mirrors cleanly onto `.eth`, `.wei`, and `.gwei` names, and it is gated by
email: a [ZK Email](https://zk.email/) proof that a DKIM-signed message from an
`@ethereum.org` address carried a specific command is the only way a profile
comes into being, and the only way its controller is set.

## How it works

A profile's identity is its ZK Email account salt, `poseidon(email,
accountCode)`; the email address itself never touches the chain. Anyone may
submit a proof, and the proof is the authority, so a profile can be
administered from any account-abstraction workflow rather than being tied to
one EOA. Email speaks only at identity events, through one command in the
body of the email, always ending in this deployment's binding tag
`{chainid}:{registry}`:

- `Set controller to {address} {binding}`: registration (`register`) binds a
  controller, never zero, and rotation (`setController`) additionally
  requires the current controller's EIP-712 signature over that exact email.
  Neither the email nor the controller alone moves the root.

The records are the controller's business only, and never cost a proof:
edited directly by transaction (`setText`), or by a relayed EIP-712 signature
(`setTextSigned`, replay-protected by a per-profile nonce) so that a
controller that can sign but not transact, such as a bare ERC-1271 signer,
wields full control. The first email from an identity must carry its account
code (`isCodeExist`), which binds the new profile to the email that created
it. Every email is single-use (`emailNullifier`), the emails honored for one
profile never run backwards in DKIM time, and commands are matched exactly
against the circuit's masked command, so a relayer can neither replay,
reorder, nor reinterpret a command. A lost controller key strands its profile
deliberately: register a fresh profile and let management flag the old one.
Record keys may not contain spaces, as hygiene for mirroring onto the name
registries.

**The sole administrative role is `management`**, a multisig: it flags a
profile inactive ("former EF") and back, it maintains the set of DKIM public
key hashes honored for the domain, and it hands itself over in two steps. An
inactive profile is read-only, by email and by controller alike; its records
stay in place so onchain routing built against it keeps resolving. Management
cannot edit or delete profiles. The DKIM authority lives in the Registry
itself, so the Foundation, and no external ZK Email contract, is sovereign
over its own gate: key rotation answers to the management multisig and to
nobody else. The edge of that power is stated plainly: management could
honor a key of its own making and mint proofs for fresh identities, though
it can never act on an existing profile without that profile's account code.
The verifier and the domain are pinned at construction and immutable; deploy
a verifier instance nobody can upgrade (the upstream implementation, deployed
without a proxy and with its ownership renounced, is exactly that).

- `contracts/src/Registry.sol`: the registry
- `contracts/src/Verifier.sol`: the immutable proof verifier (see below)
- `contracts/src/vendor/Groth16Verifier.sol`: the snarkjs-generated verifier
  holding the circuit's verifying key, vendored byte for byte
- `contracts/src/interfaces/`: the minimal ZK Email interfaces (`IVerifier`
  with `EmailProof`, mirroring ZK Email's `email-tx-builder-contracts` 1.0,
  and `IGroth16Verifier`) and CreateX
- `circuits/`: the vendored `email_auth` circuit and the zkey verification
  pipeline (see `circuits/README.md`)

**The verifier ships in this repository.** `Verifier.sol` is a sovereign,
immutable replacement for ZK Email's upgradeable `Verifier`: the same
public-signal packing, but no owner, no proxy, and no setter (the upstream
contract's owner can both upgrade it and swap its Groth16 verifier).
`vendor/Groth16Verifier.sol` holds the verifying key of the ZKEmail Ether
Email Auth V1 trusted-setup ceremony (finalized December 28th, 2024; 67
contributions on the `emailauth` circuit), exported from the ceremony's final
zkey with the pinned `snarkjs` 0.7.5. It is not upstream's checked-in
verifier: that one carries a pre-ceremony development key, and shipping it
would run a verifier no honest ceremony produced. The circuit is vendored
alongside it: `circuits/` carries the `email_auth` circom source, byte for
byte from `email-tx-builder` `v1.0.0` (commit `984b5919`) with its dependency
closure pinned, and the whole chain of custody is mechanically checkable with
`make zkey-verify`, which downloads the ceremony's phase-1 (`ppot_0080_23`),
r1cs, and final zkey (pinning each to the blake2b hash the ceremony records),
runs `snarkjs zkey verify`, exports the verifier the zkey implies, and diffs
it against the vendored file. That chain has been walked: the vendored source
compiled with the ceremony's circom 2.1.9 reproduces the ceremony r1cs byte
for byte, the final zkey verifies against it (`ZKey Ok!`), and every one of
the verifying key's 89 constants matches the ceremony's published verifier.
(The ceremony's own published `.sol` was exported by an older snarkjs whose
public-input range check is weaker; the vendored file uses the current
snarkjs export, same key, correct scaffolding.) `make deploy-verifier`
deploys the pair through CreateX to salt-ground addresses; the Registry is
then constructed against the immutable `Verifier`. Every command an email carries ends in this registry's binding
tag, `{chainid}:{registry}`, so no email can ever be replayed onto another
deployment.

## Development

The `contracts/` directory holds the [Foundry](https://getfoundry.sh/)
project; dependencies ([Solady](https://github.com/Vectorized/solady),
forge-std) are managed with [Soldeer](https://soldeer.xyz/). All commands run
from `contracts/`:

```sh
cd contracts
forge soldeer install   # fetch dependencies (first checkout only)
forge build
forge test
```

Solidity sources are formatted with `dove preen`. Unit tests run against a
mock verifier that accepts exactly the proofs a test marks valid, so every
policy check in the registry itself (domain, key hashes, nullifier, timestamp,
command, account code, active flag) is exercised in isolation from the
circuit; the invariant campaign drives a cast of identities, controllers, and
managements through every action. Mainnet fork tests (`make test-fork`) validate CreateX
deployment and need `MAINNET_RPC_URL` set in `.env`.

Deployment goes through the
[CreateX](https://github.com/pcaversaccio/createx) factory so the Registry can
be pinned to a salt-ground address (CREATE3 addresses depend only on the
factory and the salt, not the creation code). Project-pinned defaults
(`DOMAIN`, `CREATEX`) live in `.env.maintainer`; deployer configuration (RPC,
deployer private key, ground salt and its expected address, the ZK Email
verifier on the target chain, the management multisig) is documented in
`.env.example`. ZK Email publishes verifier deployments for Base, Sepolia,
and ZKSync Era, all upgradeable by ZK Email; deploy your own immutable
instance instead and pin it. After deployment, management honors the
domain's current DKIM key hashes with `setDKIMPublicKeyHash`, and the first
email can then act. From the repository root:

```sh
cp .env.example .env  # fill in the values
make deploy-verifier  # deploy the immutable verifier pair first
make deploy-dry       # simulate; verifies the CreateX address matches
make deploy           # broadcast
```

`make help` lists all goals.
