#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// Print a chain timestamp at which every fixture email is usable: an hour
// after the latest DKIM `t=` among `test/fixtures/*.eml`.
//
//   node scripts/fixture-time.mjs
//
// Emails are usable for five weeks after they are sent, so a local chain
// started at wall-clock time stops accepting the fixtures a month after they
// were made. Starting anvil at this timestamp (`anvil --timestamp ...`, as
// `make demo-anvil` and `make e2e` do) keeps them usable indefinitely.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signedHeader } from "../../frontend/email-input.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(here, "..", "test", "fixtures");

/// The latest DKIM `t=` among the fixture emails, plus an hour.
export function fixtureTime () {
  let latest = 0;
  for (const name of fs.readdirSync(FIXTURES).filter((n) => n.endsWith(".eml"))) {
    const { tags } = signedHeader(fs.readFileSync(path.join(FIXTURES, name)), { domain: "ethereum.org" });
    latest = Math.max(latest, Number(tags.t));
  }
  if (!latest) {
    throw new Error("No fixture emails carry a DKIM timestamp.");
  }
  return latest + 3600;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  console.log(fixtureTime());
}
