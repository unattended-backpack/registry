// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { EmailProof, IVerifier } from "../../src/interfaces/IVerifier.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title MockVerifier
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A minimal test stand-in for the ZK Email proof verifier. It accepts exactly
  the proofs whose proof bytes read `valid`, and, like the real circuit, only
  commands that fit within its command length, so tests can forge a bad proof
  by writing anything else.

  @custom:date August 21st, 2026.
*/
contract MockVerifier is
  IVerifier {

  /// The maximum command length of the real email-tx-builder circuit.
  uint256 internal constant COMMAND_BYTES = 605;

  /// The hash of the proof bytes this mock accepts.
  bytes32 internal constant VALID_PROOF = keccak256("valid");

  /**
    Retrieve the maximum length in bytes of a command the circuit can carry.

    @return _ The maximum command length in bytes.
  */
  function commandBytes () external pure returns (uint256) {
    return COMMAND_BYTES;
  }

  /**
    Verify an email proof: the proof bytes must read `valid` and the command
    must fit the circuit.

    @param _proof The email proof to verify.

    @return _ Whether the proof is valid.
  */
  function verifyEmailProof (
    EmailProof calldata _proof
  ) external pure returns (bool) {
    if (bytes(_proof.maskedCommand).length > COMMAND_BYTES) {
      return false;
    }
    return keccak256(_proof.proof) == VALID_PROOF;
  }
}

