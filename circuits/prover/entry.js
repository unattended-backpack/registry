// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
//
// The source of the frontend's vendored prover bundle (`frontend/vendor/prover/`).
// `make frontend-vendor` bundles this file with esbuild. It re-exports exactly
// what the proving worker needs, and it loads Noir's two WebAssembly modules
// from bytes compiled into the bundle, so nothing is fetched from anywhere.

import { BackendType, Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import initACVM from "@noir-lang/acvm_js/web/acvm_js.js";
import acvmWasm from "@noir-lang/acvm_js/web/acvm_js_bg.wasm";
import { Noir } from "@noir-lang/noir_js";
import initNoirC from "@noir-lang/noirc_abi/web/noirc_abi_wasm.js";
import noircWasm from "@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm";

let ready = null;

/// Initialize Noir's witness solver and ABI encoder, once.
export function initNoir () {
  ready = ready || Promise.all([
    initACVM({ module_or_path: acvmWasm }),
    initNoirC({ module_or_path: noircWasm })
  ]);
  return ready;
}

export { BackendType, Barretenberg, Noir, UltraHonkBackend };
