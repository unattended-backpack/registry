// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { IHonkVerifier } from "./interfaces/IHonkVerifier.sol";
import { EmailProof, IVerifier } from "./interfaces/IVerifier.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Verifier
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The immutable email proof verifier. It builds the eleven public inputs of the
  Registry's email circuit (`circuits/`) from an `EmailProof`, in the order the
  circuit takes them, and hands them to a fixed Barretenberg-generated
  UltraHonk verifier holding the circuit's verification key. There is no owner,
  no proxy, and no setter: what this contract verifies on the day it deploys
  is what it verifies forever.

  The first three inputs bind the email's authorization: the controller, the
  chain, and the registry. The chain comes from `block.chainid` and the
  registry from `msg.sender`, so a proof only ever verifies for the registry
  that asks, on the chain it lives on. The domain packs big-endian into 31-byte
  field elements, zero-padded; the circuit guarantees every byte inside it is
  nonzero, and this contract rejects a domain holding a zero byte, so no two
  domains share a packing. Every other input must already be a canonical field
  element, so no value aliases another modulo the field.

  @custom:date September 30th, 2026.
*/
contract Verifier is
  IVerifier {

  /// An address was the zero address where a real address is required.
  error ZeroAddress ();

  /// The number of field elements the circuit packs the domain into.
  uint256 public constant DOMAIN_FIELDS = 3;

  /// The maximum byte length of a domain in the circuit.
  uint256 public constant DOMAIN_BYTES = 93;

  /// The number of public inputs the circuit takes.
  uint256 public constant PUBLIC_INPUTS = 11;

  /// The BN254 scalar field modulus. Every public input must lie below it.
  uint256 internal constant R =
    21888242871839275222246405745257275088548364400416034343698204186575808495617;

  /// The fixed UltraHonk verifier holding the circuit's verification key.
  IHonkVerifier public immutable honkVerifier;

  /**
    Construct the verifier against an UltraHonk verifier.

    @param _honkVerifier The Barretenberg-generated UltraHonk verifier holding
      the email circuit's verification key.
  */
  constructor (
    address _honkVerifier
  ) {
    if (_honkVerifier == address(0)) {
      revert ZeroAddress();
    }
    honkVerifier = IHonkVerifier(_honkVerifier);
  }

  /**
    Check that a domain fits the circuit: no longer than its capacity, and free
    of zero bytes.

    @param _bytes The domain's bytes.

    @return _ Whether the domain fits.
  */
  function _fits (
    bytes memory _bytes
  ) internal pure returns (bool) {
    if (_bytes.length > DOMAIN_BYTES) {
      return false;
    }
    for (uint256 i = 0; i < _bytes.length; ++i) {
      if (_bytes[i] == 0) {
        return false;
      }
    }
    return true;
  }

  /**
    Build the circuit's public inputs, in the circuit's order: the controller,
    the chain ID, the registry, the domain (three fields), the key hash, the
    nullifier, the timestamp, and the profile ID as high and low 128-bit halves.

    @param _proof The email proof.
    @param _controller The controller the email must authorize.
    @param _chainId The chain the email must authorize.
    @param _registry The registry the email must authorize.

    @return _ The public inputs.
  */
  function publicInputs (
    EmailProof calldata _proof,
    address _controller,
    uint256 _chainId,
    address _registry
  ) public pure returns (bytes32[] memory) {
    bytes32[] memory _inputs = new bytes32[](PUBLIC_INPUTS);
    _inputs[0] = bytes32(uint256(uint160(_controller)));
    _inputs[1] = bytes32(_chainId);
    _inputs[2] = bytes32(uint256(uint160(_registry)));
    bytes memory _domain = bytes(_proof.domainName);
    for (uint256 i = 0; i < DOMAIN_FIELDS; ++i) {
      uint256 _acc = 0;
      for (uint256 j = 0; j < 31; ++j) {
        uint256 _k = i * 31 + j;
        uint256 _byte = _k < _domain.length ? uint256(uint8(_domain[_k])) : 0;
        _acc = (_acc << 8) | _byte;
      }
      _inputs[3 + i] = bytes32(_acc);
    }
    _inputs[6] = _proof.publicKeyHash;
    _inputs[7] = _proof.emailNullifier;
    _inputs[8] = bytes32(_proof.timestamp);
    _inputs[9] = bytes32(uint256(_proof.profileId) >> 128);
    _inputs[10] = bytes32(uint256(uint128(uint256(_proof.profileId))));
    return _inputs;
  }

  /**
    Verify an email proof for the calling registry on the current chain: build
    the circuit's public inputs and verify the UltraHonk proof against them.
    Claims the circuit could never have produced (an oversized or zero-holding
    domain, values outside the field) are rejected outright, and a verifier
    revert reads as invalid.

    @param _proof The email proof to verify.
    @param _controller The controller the email's subject must authorize.

    @return _ Whether the proof is valid.
  */
  function verifyEmailProof (
    EmailProof calldata _proof,
    address _controller
  ) external view returns (bool) {
    if (
      !_fits(bytes(_proof.domainName)) || uint256(_proof.publicKeyHash) >= R
      || uint256(_proof.emailNullifier) >= R || _proof.timestamp >= R
    ) {
      return false;
    }
    try honkVerifier.verify(
      _proof.proof, publicInputs(
        _proof, _controller, block.chainid, msg.sender
      )
    ) returns (bool _valid) {
      return _valid;
    } catch {
      return false;
    }
  }
}

