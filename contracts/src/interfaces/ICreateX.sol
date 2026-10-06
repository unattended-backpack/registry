// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title ICreateX
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A minimal interface to the CreateX contract factory. CREATE3 deployment
  addresses are derived from the factory address and the salt alone,
  independent of the creation code, which is what allows grinding salts ahead
  of time to pin a contract to a specific known address.

  @custom:date July 24th, 2026.
*/
interface ICreateX {

  /**
    Deploy a contract to a salt-determined address via the CREATE3 pattern.

    @param _salt The salt determining the deployment address.
    @param _initCode The creation code of the contract to deploy, including any
      ABI-encoded constructor arguments.

    @return _ The address of the newly deployed contract.
  */
  function deployCreate3 (
    bytes32 _salt,
    bytes calldata _initCode
  ) external payable returns (address);
}

