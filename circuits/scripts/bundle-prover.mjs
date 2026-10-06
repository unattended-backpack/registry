#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// Bundle the frontend's prover (`prover/entry.js`) into
// `frontend/vendor/prover/`, swapping bb.js's CDN reference-string loader for
// `prover/local-crs.js`, and leaving out the multithreaded WebAssembly build,
// which single-threaded proving never loads. Run by `make frontend-vendor`.

import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, "..");
const outdir = path.join(root, "..", "frontend", "vendor", "prover");

const fromBb = (args) =>
  args.importer.includes(`${path.sep}@aztec${path.sep}bb.js${path.sep}dest${path.sep}browser`);

const localCrs = {
  name: "local-crs",
  setup (b) {
    b.onResolve({ filter: /crs\/index\.js$/ }, (args) => (fromBb(args)
      ? { path: path.join(root, "prover", "local-crs.js") }
      : undefined));
    b.onResolve({ filter: /barretenberg-threads\.js$/ }, (args) => (fromBb(args)
      ? { path: "barretenberg-threads", namespace: "single-threaded" }
      : undefined));
    b.onLoad({ filter: /.*/, namespace: "single-threaded" }, () => ({
      contents: "throw new Error('This build proves single-threaded only.');",
      loader: "js"
    }));
  }
};

await build({
  entryPoints: { prover: path.join(root, "prover", "entry.js") },
  bundle: true,
  format: "esm",
  splitting: true,
  platform: "browser",
  target: "es2022",
  minify: true,
  outdir,
  entryNames: "[name]",
  chunkNames: "chunk-[hash]",
  loader: { ".wasm": "binary" },
  plugins: [localCrs],
  legalComments: "linked",
  logLevel: "info"
});
