// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.36;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title IGroth16Verifier
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A minimal interface to the snarkjs-generated Groth16 verifier for the ZK
  Email `email_auth` circuit. The circuit's verifying key is baked into the
  generated contract as constants, so the contract is a pure function: proof
  points and public signals in, validity out.

  @custom:date August 25th, 2026.
*/
interface IGroth16Verifier {

  /**
    Verify a Groth16 proof against the circuit's verifying key.

    @param _pA The proof's A point.
    @param _pB The proof's B point.
    @param _pC The proof's C point.
    @param _pubSignals The public signals the proof commits to.

    @return _ Whether the proof is valid.
  */
  function verifyProof (
    uint256[2] calldata _pA,
    uint256[2][2] calldata _pB,
    uint256[2] calldata _pC,
    uint256[34] calldata _pubSignals
  ) external view returns (bool);
}

