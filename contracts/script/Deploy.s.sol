// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { ICreateX } from "../src/interfaces/ICreateX.sol";
import { Registry } from "../src/Registry.sol";
import { Script, console } from "forge-std/Script.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Deploy
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Deploy the Registry through the CreateX factory to a known, salt-ground
  address. Configuration comes from the environment: the maintainer-pinned
  `CREATEX` and `DOMAIN` from `.env.maintainer`, and the deployer-supplied
  `DEPLOYER_PRIVATE_KEY`, `SALT`, `EXPECTED_ADDRESS`, `VERIFIER`, and
  `MANAGEMENT` from `.env`. The deployment reverts if the
  deployed address does not match `EXPECTED_ADDRESS`.

  @custom:date August 21st, 2026.
*/
contract Deploy is
  Script {

  /// This error is emitted if an expected deployment address is incorrect.
  error UnexpectedAddress ();

  /// Run the script.
  function run () external {

    // Read configuration from environment.
    address _createX = vm.envAddress("CREATEX");
    address _verifier = vm.envAddress("VERIFIER");
    string memory _domain = vm.envString("DOMAIN");
    address _management = vm.envAddress("MANAGEMENT");
    bytes32 _salt = vm.envBytes32("SALT");
    address _expectedAddress = vm.envAddress("EXPECTED_ADDRESS");
    uint256 _privateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
    console.log("Registry Deployment Script");
    console.log("  CreateX:", _createX);
    console.log("  Verifier:", _verifier);
    console.log("  Domain:", _domain);
    console.log("  Management:", _management);

    // Deploy from the deployer account.
    address _account = vm.addr(_privateKey);
    console.log("");
    console.log("Deploying from account:", _account);
    vm.startBroadcast(_privateKey);

    // Deploy.
    address _newAddress =
      ICreateX(_createX).deployCreate3(
        _salt,
        abi.encodePacked(
          type(Registry).creationCode,
          abi.encode(_verifier, _domain, _management)
        )
      );
    console.log("  - Registry: %s", _newAddress);
    if (_newAddress != _expectedAddress) {
      revert UnexpectedAddress();
    }
    vm.stopBroadcast();
    console.log("");
    console.log("Registry deployment complete!");
  }
}

