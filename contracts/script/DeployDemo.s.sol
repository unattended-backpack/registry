// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { Registry } from "../src/Registry.sol";
import { HonkVerifier } from "../src/vendor/HonkVerifier.sol";
import { Verifier } from "../src/Verifier.sol";
import { Script, console } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title DeployDemo
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Deploy a demonstration Registry onto any chain but mainnet, from one funded
  key. That key's account deploys the HonkVerifier's linked libraries, the
  HonkVerifier, the Verifier, and the Registry; it is the Registry's
  management, and it honors the DKIM key hashes given, comma-separated, as
  `DEMO_KEY_HASHES` (see `make key-hash`). Nothing is pinned: every address
  follows from the account's nonce, so the emails for this Registry must be
  sent after it exists, naming its chain and its address. It prints the block
  the frontend's `config.js` should read records from, which precedes the
  Registry's own. Run it as `make
  demo-deploy-chain`, which names the key's account as the deployer of the
  linked libraries.

  @custom:date September 30th, 2026.
*/
contract DeployDemo is
  Script {

  /// This error is emitted if the target chain is mainnet.
  error NotADemoChain ();

  /// Run the script.
  function run () external {
    if (block.chainid == 1) {
      revert NotADemoChain();
    }
    bytes32[] memory _keyHashes = vm.envBytes32("DEMO_KEY_HASHES", ",");
    vm.startBroadcast();
    (, address _account, ) = vm.readCallers();
    HonkVerifier _honk = new HonkVerifier();
    Verifier _verifier = new Verifier(address(_honk));
    Registry _registry =
      new Registry(address(_verifier), vm.envString("DOMAIN"), _account);
    for (uint256 i = 0; i < _keyHashes.length; ++i) {
      _registry.setDKIMPublicKeyHash(_keyHashes[i], true);
    }
    vm.stopBroadcast();
    console.log("Chain:       ", block.chainid);
    console.log("Management:  ", _account);
    console.log("HonkVerifier:", address(_honk));
    console.log("Verifier:    ", address(_verifier));
    console.log("Registry:    ", address(_registry));
    console.log("Read from:   ", block.number);
  }
}

