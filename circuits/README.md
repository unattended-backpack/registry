# Circuits

The ZK Email `email_auth` circuit, vendored verbatim from
[`zkemail/email-tx-builder`](https://github.com/zkemail/email-tx-builder) at
`v1.0.0` (commit `984b5919`, package `@zk-email/ether-email-auth-circom`
1.0.3): `src/` is theirs, byte for byte, including the generated regex
circuits. The circuit is the meaning of the Registry's verifying key; a
verifier without its circuit cannot be audited, so the circuit lives here.

Dependencies are pinned exactly (`@zk-email/circuits` 6.3.2,
`@zk-email/zk-regex-circom` 2.3.1, `circomlib` 2.0.5, `snarkjs` 0.7.5, the
versions the upstream release builds against) in `package.json` and locked in
`package-lock.json`. The `circom` compiler is a separate system tool, and the
r1cs it emits varies across compiler versions: the ceremony compiled with
**circom 2.1.9** (the version its record names), so pass
`CIRCOM=circom-2.1.9` to `make circuits` to reproduce the ceremony's exact
r1cs. The compiler is not itself a trust anchor. The Makefile pins the r1cs
blake2b (`R1CS_B2`) that the ceremony's zkey commits to; any compiler that
reproduces that hash is acceptable, and `make zkey-verify` aborts if the
local r1cs does not match it, so a wrong compiler is caught rather than
trusted.

From the repository root:

```sh
make circuits-install         # npm ci against the lockfile
make circuits CIRCOM=circom-2.1.9  # compile email_auth to the ceremony's r1cs
make zkey-verify              # fetch and verify the ceremony zkey; diff the verifier
```

`zkey-verify` is the goal that matters. It downloads the ZKEmail Ether Email
Auth V1 ceremony's phase-1 (`ppot_0080_23.ptau`, Perpetual Powers of Tau
contribution 80) and final `emailauth` zkey from the ceremony's public store,
pinning each to the blake2b hash the ceremony records; runs `snarkjs zkey
verify` to confirm the zkey is a valid phase-2 for this circuit's r1cs over
that phase-1; exports the Solidity verifier the zkey implies (with the pinned
`snarkjs` 0.7.5); and diffs it against
`contracts/src/vendor/Groth16Verifier.sol`. A match proves the vendored
verifying key is the ceremony's; a mismatch fails the goal with the
instruction to replace the vendored file with the exported one. That whole
chain has been walked and the vendored key is the ceremony's; this goal
re-checks it from a cold checkout. `zkey-dev` builds a throwaway zkey for
local end-to-end proof testing and must never back a production verifier.
