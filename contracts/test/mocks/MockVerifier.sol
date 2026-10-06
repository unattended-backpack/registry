// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { EmailProof, IVerifier } from "../../src/interfaces/IVerifier.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title MockVerifier
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A minimal test stand-in for the email proof verifier. Its proof bytes are
  `abi.encode(VALID_PROOF, controller, chainId, registry)`, and it accepts a
  proof exactly when those name the controller asked about, the current
  chain, and the calling registry, as the real circuit's binding does. Tests
  forge a bad proof by writing anything else.

  @custom:date September 30th, 2026.
*/
contract MockVerifier is
  IVerifier {

  /// The tag a valid mock proof opens with.
  bytes32 public constant VALID_PROOF = keccak256("valid");

  /**
    Verify an email proof: the proof bytes must carry the valid tag and name
    `_controller`, this chain, and the caller.

    @param _proof The email proof to verify.
    @param _controller The controller the email must authorize.

    @return _ Whether the proof is valid.
  */
  function verifyEmailProof (
    EmailProof calldata _proof,
    address _controller
  ) external view returns (bool) {
    if (_proof.proof.length != 128) {
      return false;
    }
    (bytes32 _tag, address _authorized, uint256 _chainId, address _registry) =
    abi.decode(
      _proof.proof, (bytes32, address, uint256, address)
    );
    return _tag == VALID_PROOF && _authorized == _controller
    && _chainId == block.chainid && _registry == msg.sender;
  }
}

