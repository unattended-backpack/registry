// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title IHonkVerifier
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A minimal interface to the Barretenberg-generated UltraHonk verifier for the
  Registry's email circuit. The circuit's verification key is baked into the
  generated contract as constants, so the contract is a pure function: a proof
  and its public inputs in, validity out. It reverts, rather than returning
  false, on most malformed or invalid proofs.

  @custom:date September 25th, 2026.
*/
interface IHonkVerifier {

  /**
    Verify an UltraHonk proof against the circuit's verification key.

    @param _proof The proof.
    @param _publicInputs The public inputs the proof commits to, one field
      element per entry.

    @return _ Whether the proof is valid.
  */
  function verify (
    bytes calldata _proof,
    bytes32[] calldata _publicInputs
  ) external view returns (bool);
}

