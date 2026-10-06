// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

/**
  A proof that a DKIM-signed email header, from an address at some domain,
  carried a subject authorizing a controller for a private profile, and the
  facts the proof reveals about that email. The sender's address, the subject,
  and the exact time stay hidden.

  @param domainName The sender's domain, lowercased, as the circuit revealed it.
  @param publicKeyHash The hash of the DKIM public key that signed the email:
    the Pedersen hash of its modulus limbs (see `circuits/dkim_key_hash`).
  @param timestamp The DKIM signature's `t=` timestamp, rounded down to a
    multiple of one week.
  @param emailNullifier A nullifier unique to the email and the profile, the
    Pedersen hash of the DKIM signature and the profile's salt, so nobody
    holding the email can compute it.
  @param profileId The profile's ID: the SHA-256 of its salt followed by the
    sender's lowercased address.
  @param proof The UltraHonk proof.
*/
struct EmailProof {
  string domainName;
  bytes32 publicKeyHash;
  uint256 timestamp;
  bytes32 emailNullifier;
  bytes32 profileId;
  bytes proof;
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title IVerifier
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A minimal interface to the Registry's email proof verifier. The verifier
  checks a proof against the public inputs built from an `EmailProof`, the
  controller the email must authorize, the calling registry, and the current
  chain; it says nothing about whether the DKIM key was valid, whether the
  email was used before, or how old it is. That policy is the caller's.

  @custom:date September 30th, 2026.
*/
interface IVerifier {

  /**
    Verify an email proof for the calling registry on the current chain.

    @param _proof The email proof to verify.
    @param _controller The controller the email's subject must authorize.

    @return _ Whether the proof is valid.
  */
  function verifyEmailProof (
    EmailProof calldata _proof,
    address _controller
  ) external view returns (bool);
}

