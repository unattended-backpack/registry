#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// Print the subject line that authorizes a controller for a private profile.
//
//   node scripts/subject.mjs --controller <address> --chain-id <id>
//     --registry <address> [--salt <secret>] [--email <address>]
//
// Without --salt, a fresh profile secret is generated and printed; keep it,
// because every renewal and rotation needs it. With --email, the profile's ID
// is printed too. Everything is computed locally, by the same module the
// browser and the prover use; nothing is sent anywhere.

import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateSalt, parseSalt, privateProfileId, privateSubject
} from "../../frontend/email-input.js";

const OPTIONS = ["--controller", "--chain-id", "--registry", "--salt", "--email"];

function parseArgs (argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (!OPTIONS.includes(argv[i])) {
      throw new Error(`unknown argument ${argv[i]}`);
    }
    args[argv[i].slice(2).replace(/-(.)/g, (_, c) => c.toUpperCase())] = argv[++i];
  }
  if (!args.controller || !args.chainId || !args.registry) {
    throw new Error("usage: node scripts/subject.mjs --controller <address> "
      + "--chain-id <id> --registry <address> [--salt <secret>] [--email <address>]");
  }
  return args;
}

function main () {
  const args = parseArgs(process.argv.slice(2));
  const fresh = !args.salt;
  const salt = fresh ? generateSalt() : args.salt;
  parseSalt(salt);
  const subject = privateSubject({
    controller: args.controller, chainId: args.chainId, registry: args.registry, salt
  });
  console.log(`secret:  ${salt}${fresh ? "   (new: keep it; renewals need it)" : ""}`);
  console.log(`subject: ${subject}`);
  if (args.email) {
    console.log(`profile: ${privateProfileId(args.email, salt)}`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try {
    main();
  } catch (e) {
    console.error(e.message || e);
    process.exit(1);
  }
}
