// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { ICreateX } from "../src/interfaces/ICreateX.sol";
import { HonkVerifier } from "../src/vendor/HonkVerifier.sol";
import { Verifier } from "../src/Verifier.sol";
import { Script, console } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title DeployVerifier
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Deploy the immutable email verifier pair through the CreateX factory to
  known, salt-ground addresses: first the Barretenberg-generated
  `HonkVerifier` holding the circuit's verification key, then the immutable
  `Verifier` pinned to it. Configuration comes from the environment: the
  maintainer-pinned `CREATEX` from `.env.maintainer`, and the
  deployer-supplied `DEPLOYER_PRIVATE_KEY`, `HONK_VERIFIER_SALT`,
  `HONK_VERIFIER_EXPECTED_ADDRESS`, `VERIFIER_SALT`, and
  `VERIFIER_EXPECTED_ADDRESS` from `.env`. Each deployment reverts if its
  deployed address does not match its expected address.

  @custom:date September 25th, 2026.
*/
contract DeployVerifier is
  Script {

  /// This error is emitted if an expected deployment address is incorrect.
  error UnexpectedAddress ();

  /// Run the script.
  function run () external {

    // Read configuration from environment.
    address _createX = vm.envAddress("CREATEX");
    bytes32 _honkSalt = vm.envBytes32("HONK_VERIFIER_SALT");
    address _expectedHonk = vm.envAddress("HONK_VERIFIER_EXPECTED_ADDRESS");
    bytes32 _verifierSalt = vm.envBytes32("VERIFIER_SALT");
    address _expectedVerifier = vm.envAddress("VERIFIER_EXPECTED_ADDRESS");
    uint256 _privateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
    console.log("Verifier Deployment Script");
    console.log("  CreateX:", _createX);

    // Deploy from the deployer account.
    address _account = vm.addr(_privateKey);
    console.log("");
    console.log("Deploying from account:", _account);
    vm.startBroadcast(_privateKey);

    // Deploy the UltraHonk verifier holding the circuit's verification key.
    address _honk =
      ICreateX(_createX).deployCreate3(
        _honkSalt, type(HonkVerifier).creationCode
      );
    console.log("  - HonkVerifier: %s", _honk);
    if (_honk != _expectedHonk) {
      revert UnexpectedAddress();
    }

    // Deploy the immutable Verifier pinned to it.
    address _verifier =
      ICreateX(_createX).deployCreate3(
        _verifierSalt,
        abi.encodePacked(type(Verifier).creationCode, abi.encode(_honk))
      );
    console.log("  - Verifier: %s", _verifier);
    if (_verifier != _expectedVerifier) {
      revert UnexpectedAddress();
    }
    vm.stopBroadcast();
    console.log("");
    console.log("Verifier deployment complete!");
    console.log("Set VERIFIER to the Verifier address in .env.");
  }
}

