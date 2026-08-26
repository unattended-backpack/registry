// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.36;

/**
  A ZK Email proof that a DKIM-signed email carried a command, mirroring
  `EmailProof` from ZK Email's `email-tx-builder-contracts` 1.0 field for field
  so that the deployed verifier is a drop-in.

  @param domainName The sender's domain, as revealed by the circuit.
  @param publicKeyHash The Poseidon hash of the DKIM public key that signed the
    email.
  @param timestamp The DKIM signature timestamp, or zero if the signature
    carried none.
  @param maskedCommand The command extracted from the email body, with any email
    address and invitation code inside it masked to zero bytes.
  @param emailNullifier A nullifier unique to the email, derived from its DKIM
    signature.
  @param accountSalt The sender's identity: `poseidon(email, accountCode)`.
  @param isCodeExist Whether the email carried the account code behind
    `accountSalt`, binding the salt to this very email.
  @param proof The Groth16 proof.
*/
struct EmailProof {
  string domainName;
  bytes32 publicKeyHash;
  uint256 timestamp;
  string maskedCommand;
  bytes32 emailNullifier;
  bytes32 accountSalt;
  bool isCodeExist;
  bytes proof;
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title IVerifier
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A minimal interface to the ZK Email proof verifier, mirroring `IVerifier`
  from ZK Email's `email-tx-builder-contracts` 1.0. The verifier checks a
  Groth16 proof against the public signals packed from an `EmailProof`; it says
  nothing about whether the DKIM key was valid, whether the email was used
  before, or whether the command means anything. That policy is the caller's.

  @custom:date August 21st, 2026.
*/
interface IVerifier {

  /**
    Retrieve the maximum length in bytes of a command the circuit can carry.

    @return _ The maximum command length in bytes.
  */
  function commandBytes () external view returns (uint256);

  /**
    Verify an email proof.

    @param _proof The email proof to verify.

    @return _ Whether the proof is valid.
  */
  function verifyEmailProof (
    EmailProof calldata _proof
  ) external view returns (bool);
}

