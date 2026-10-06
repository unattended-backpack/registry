# Registry frontend

A static, self-contained web client for the Registry. The directory you are
reading *is* the deployable site: there is no build step and no server.
Serve these files from anything, or pin them to IPFS.

```sh
cd frontend
python3 -m http.server 8080   # then open http://localhost:8080
```

```sh
ipfs add -r frontend          # pin the directory; open via any gateway
```

## What it does

- **Browse** the directory: every profile loads as soon as you connect, as a
  grid of cards with its status, when it must be renewed, its id, its
  controller, and all of its text records. Every field is the same kind of
  key and value row; ids and addresses show in full, each with a button that
  copies it. The search box narrows the grid live to the profiles whose
  record keys or values, controller, or id contain what you type. Every profile is
  private; its id says nothing about whose it is. Nothing is written.
- **Register** a profile: create a profile secret, build the exact subject
  line, email it, prove the email in this browser, and prepare the
  registration for broadcast, ideally later.
- **Manage** a profile as its controller: find it from your email address and
  secret (computed here, sent nowhere); edit its records in a table, where
  you change values in place, add records, and clear them, then sign every
  change at once (`setTextsSigned`); renew it every 90 days, or rotate its
  controller, with a fresh email proof the current controller signs off on.

Every write takes the two steps below, so the controller only ever signs.

## Every write, in two steps

First the controller signs, and the page shows the complete transaction the
signature produced: the chain, the Registry, and the calldata, with a plain
description of what it does under `about`. A registration needs no
signature, since the proof is its authority, so it goes straight to this
step. The page simulates the transaction against the chain at once and says
what it will cost, or why it would fail. Then choose:

- **Copy for a relayer.** Paste it into any relayer or broadcasting service
  you trust, or carry it to another device. It is a standard transaction
  request in JSON-RPC form (`chainId`, `to`, a `value` of zero, `data`), so
  any tool that sends one takes it whole; `about` is for you alone. The
  transaction carries its own authority, so whoever broadcasts it cannot
  change what it does.
- **Broadcast it myself.** Send it from whichever account your wallet has
  selected when you click. That need not be the account that signed: a
  funded account with no part in the profile keeps the controller unfunded
  and unlinked.

A failed simulation never disables the broadcast button, since the chain can
change before a transaction lands (a DKIM key honored in the meantime, say).
Every failure, from the simulation, the wallet, or the chain, is decoded from
the Registry's own errors into what went wrong and what to do about it.

## Sovereignty

The site makes no network calls of its own. The only endpoints it touches are
the ones you choose: your RPC (for reads and simulations) and your wallet
(for signatures, and for any transaction you broadcast yourself). Your profile
secret stays in this page and its proving worker. Everything proving needs
ships in this directory: the input generator (`email-input.js`), the compiled
circuit (`circuit/`), the prover (`vendor/prover/`, Barretenberg and Noir
bundled), and the prover's reference points (`crs/`). ethers is vendored under `vendor/` too. Your email, your
keys, your secret, and your signatures never leave the browser.

Barretenberg's browser build downloads its reference points from Aztec's CDN.
The vendored bundle replaces that loader with one that reads `crs/` from this
site, so proving contacts no third party. The points only serve the prover:
soundness rests on the verification key baked into the on-chain verifier,
and wrong points can only produce proofs that fail.

The page asks for one thing before it does anything: an RPC URL, which should
be your own node, ideally a local one. It checks that the endpoint serves the
configured chain and that the Registry exists there, then remembers it in
this browser. Everything else is fixed by `config.js`: the chain id, the
Registry address, the block the Registry was deployed in, the domain, and the
domain's DKIM keys. The page shows the chain id and the Registry address
beside the RPC field and offers no way to change any of them. Edit
`config.js` before pinning to point the site at another deployment.

Browse finds every record key from the Registry's `TextChanged` logs, read
from `deployBlock` onward in spans any node will serve, then reads each value
from the contract itself. A node that refuses to serve logs still shows the
default keys.

## The register flow, end to end

1. Create a profile secret, or paste one you already hold, and save it
   somewhere safe. Every renewal needs it. Lose it and the profile lapses at
   its next renewal; register a fresh one then.
2. Enter the controller address you will hold and build the subject line. It
   reads `Set controller to 0x{commitment}`, where the commitment binds the
   controller, this chain, this Registry, and your secret. Nobody without the
   secret can open it. The controller should be an account with no link to
   you: it only signs, and never needs funds.
3. From your `@ethereum.org` address, send an email whose subject is exactly
   that line, to **another inbox you can read**. The body can be anything.
   Mail sent to your own address carries no DKIM signature, so it cannot be
   proven. Open the email in the other inbox and download the original
   message ("Download original" in Gmail) as `.eml`.
4. Choose the `.eml` and prove it. Proving runs in a Web Worker on your
   machine, single-threaded, in under a minute. The page then shows your
   profile id, the week the proof reveals, and whether the Registry honors
   the DKIM key that signed the email.
5. Prepare the registration, then copy it to a relayer or broadcast it
   yourself from any account. Better, copy it and broadcast it later:
   whoever reads your mailbox knows when you sent the email, and the chain
   shows when the proof landed; waiting keeps the two apart. The email stays
   usable for four weeks. Whoever broadcasts is irrelevant; the proof is the
   authority.

Records afterward are the controller's: it signs each batch of changes,
anyone may broadcast it, and none needs another proof. Email is for registration, for
renewal every 90 days, and for rotating the controller. A profile that is not
renewed lapses: it keeps its records, but nothing can write them until a
fresh email renews it. Once it lapses, anyone may also flag it inactive
("former EF"), and then it cannot renew at all unless management restores
it; register a fresh profile instead.

## DKIM keys

The prover needs the public key that signed the email. `config.js` carries
the domain's keys by selector, exactly as DNS publishes them at
`<selector>._domainkey.<domain>`, so proving needs no DNS lookup. When the
domain rotates to a selector the site does not know, its maintainers add the
new TXT record to `config.js`; until then, an email signed under it cannot be
proven here. The key only has to be right for the proof to verify; the
Registry decides which keys it honors.

## Rebuilding the vendored prover

`make frontend-vendor` rebuilds `vendor/prover/` from the pinned packages and
checks the reference points in `crs/` against their pinned hashes;
`make vendor` rewrites `circuit/` from the circuit source, and
`make verifier-check` proves the shipped circuit is the compiled source.
