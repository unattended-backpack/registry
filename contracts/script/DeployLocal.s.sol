// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { Registry } from "../src/Registry.sol";
import { HonkVerifier } from "../src/vendor/HonkVerifier.sol";
import { Verifier } from "../src/Verifier.sol";
import { Script, console } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title DeployLocal
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Deploy a demonstration Registry onto a fresh local anvil chain, for trying
  the frontend end to end. Anvil's second account deploys the verifier stack
  (the HonkVerifier's linked libraries, the HonkVerifier, and the Verifier).
  Anvil's first account spends its first two nonces on two empty contracts
  and deploys the Registry at nonce 2, so the Registry always lands at
  `0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0` on chain 31337: the binding a
  demo email's subject names. The first account is management, and it honors
  the DKIM key hashes given, comma-separated, as `DEMO_KEY_HASHES` (see
  `make key-hash`). Never use this outside a local chain. Run it as `make
  demo-deploy`, which names the
  second account as the deployer of the HonkVerifier's linked libraries.

  @custom:date September 30th, 2026.
*/
contract DeployLocal is
  Script {

  /// This error is emitted if the chain or the deployment address is wrong.
  error NotAFreshAnvil ();

  /// Anvil's first account's well-known private key.
  uint256 internal constant ANVIL_0_KEY =
    0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

  /// Anvil's second account's well-known private key.
  uint256 internal constant ANVIL_1_KEY =
    0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

  /// Where the Registry must land.
  address internal constant BOUND_REGISTRY =
    0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

  /// Run the script.
  function run () external {
    if (block.chainid != 31337) {
      revert NotAFreshAnvil();
    }
    bytes32[] memory _keyHashes = vm.envBytes32("DEMO_KEY_HASHES", ",");
    address _account = vm.addr(ANVIL_0_KEY);
    if (vm.getNonce(_account) > 2) {
      revert NotAFreshAnvil();
    }

    // The verifier stack, from the second account.
    vm.startBroadcast(ANVIL_1_KEY);
    HonkVerifier _honk = new HonkVerifier();
    Verifier _verifier = new Verifier(address(_honk));
    vm.stopBroadcast();

    // The Registry, from the first account at nonce 2.
    vm.startBroadcast(ANVIL_0_KEY);
    for (uint256 i = vm.getNonce(_account); i < 2; ++i) {
      new Placeholder();
    }
    Registry _registry =
      new Registry(address(_verifier), vm.envString("DOMAIN"), _account);
    if (address(_registry) != BOUND_REGISTRY) {
      revert NotAFreshAnvil();
    }
    for (uint256 i = 0; i < _keyHashes.length; ++i) {
      _registry.setDKIMPublicKeyHash(_keyHashes[i], true);
    }
    vm.stopBroadcast();
    console.log("HonkVerifier:", address(_honk));
    console.log("Verifier:    ", address(_verifier));
    console.log("Registry:    ", address(_registry));
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Placeholder
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  An empty contract whose only purpose is to spend a deployer's nonce.

  @custom:date September 30th, 2026.
*/
contract Placeholder { }

