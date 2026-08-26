// Registry frontend configuration.
//
// This is the only file you edit to point the site at a deployment. It ships
// as plain data with no build step, so it can be changed in place before
// pinning the directory to IPFS or any static host. Every value can also be
// overridden at runtime from the Settings panel, which persists to the
// browser's localStorage; this file provides the defaults.

window.REGISTRY_CONFIG = {

  // The chain the Registry is deployed on.
  chainId: 1,

  // A read-only RPC endpoint. Reads (browsing the directory) go here; writes
  // go through the connected wallet. Point this at your own node for full
  // sovereignty. No other network calls are made by this site.
  rpcUrl: "https://ethereum-rpc.publicnode.com",

  // The Registry contract address. Fill this in for your deployment.
  registryAddress: "",

  // The email domain the Registry gates on, shown in the UI for clarity.
  domain: "ethereum.org",

  // Where the local prover's artifacts live: the circuit WASM, the ceremony
  // zkey, and the input generator. These are large (the zkey is gigabytes)
  // and are hosted separately from this site; set this to a directory (an
  // IPFS path, a local server, a file:// path) that holds:
  //   email_auth.wasm         the witness generator
  //   emailauth_final.zkey    the ceremony proving key (or a chunked variant)
  //   zkemail-input.js        a UMD script exposing self.zkemailInput.generate
  // Leave empty to disable in-browser proving and use the Import Proof path.
  proverArtifactBase: ""
};
