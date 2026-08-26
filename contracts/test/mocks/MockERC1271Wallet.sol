// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { ECDSA } from "solady/utils/ECDSA.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title MockERC1271Wallet
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A minimal test stand-in for a smart account controller: it honors
  ERC-1271 signature checks exactly when the signature is a valid ECDSA
  signature from its underlying owner key.

  @custom:date August 25th, 2026.
*/
contract MockERC1271Wallet {

  /// The ERC-1271 magic value signaling a valid signature.
  bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

  /// The owner key standing behind this wallet.
  address public immutable owner;

  /**
    Construct the wallet around an owner key.

    @param _owner The owner key standing behind this wallet.
  */
  constructor (
    address _owner
  ) {
    owner = _owner;
  }

  /**
    Check a signature against the owner key, per ERC-1271.

    @param _hash The hash that was signed.
    @param _signature The signature to check.

    @return _ The ERC-1271 magic value if the signature is the owner's.
  */
  function isValidSignature (
    bytes32 _hash,
    bytes calldata _signature
  ) external view returns (bytes4) {
    return ECDSA.recoverCalldata(_hash, _signature) == owner ? MAGIC_VALUE :
    bytes4(
      0xffffffff
    );
  }
}

