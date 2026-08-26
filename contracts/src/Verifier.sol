// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { IGroth16Verifier } from "./interfaces/IGroth16Verifier.sol";
import { EmailProof, IVerifier } from "./interfaces/IVerifier.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Verifier
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The immutable ZK Email proof verifier: the Foundation's sovereign
  replacement for ZK Email's own upgradeable `Verifier`. It packs an
  `EmailProof` into the public signals of the `email_auth` circuit byte for
  byte as the upstream contract does (`email-tx-builder` 1.0), then hands them
  to a fixed snarkjs-generated Groth16 verifier holding the circuit's
  verifying key. There is no owner, no proxy, and no setter: what this
  contract verifies on the day it deploys is what it verifies forever.

  Beyond the packing, two defensive caps mirror the check ZK Email performs in
  its `EmailAuth` contract: a domain or command longer than the circuit's
  fixed capacity is rejected outright, since bytes beyond that capacity could
  never have been attested by any proof.

  @custom:date August 25th, 2026.
*/
contract Verifier is
  IVerifier {

  /// An address was the zero address where a real address is required.
  error ZeroAddress ();

  /// A proof point is not a valid BN254 base field element.
  error InvalidProofPoints ();

  /// The number of field elements the circuit packs the domain into.
  uint256 public constant DOMAIN_FIELDS = 9;

  /// The padded byte capacity of the domain in the circuit.
  uint256 public constant DOMAIN_BYTES = 255;

  /// The number of field elements the circuit packs the command into.
  uint256 public constant COMMAND_FIELDS = 20;

  /// The maximum byte length of a command in the circuit.
  uint256 public constant COMMAND_BYTES = 605;

  /**
    The BN254 base field modulus. Proof points are curve coordinates and must
    lie below it.
  */
  uint256 internal constant Q =
    0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47;

  /// The fixed Groth16 verifier holding the circuit's verifying key.
  IGroth16Verifier public immutable groth16Verifier;

  /**
    Construct the verifier against a Groth16 verifier.

    @param _groth16Verifier The snarkjs-generated Groth16 verifier holding the
      `email_auth` circuit's verifying key.
  */
  constructor (
    address _groth16Verifier
  ) {
    if (_groth16Verifier == address(0)) {
      revert ZeroAddress();
    }
    groth16Verifier = IGroth16Verifier(_groth16Verifier);
  }

  /**
    Pack bytes into 31-byte little-endian field elements, exactly as the circuit
    packs its string inputs and exactly as ZK Email's upstream `Verifier` does.

    @param _bytes The bytes to pack.
    @param _paddedSize The circuit's fixed byte capacity for this input.

    @return _ The packed field elements.
  */
  function _packBytes2Fields (
    bytes memory _bytes,
    uint256 _paddedSize
  ) internal pure returns (uint256[] memory) {
    uint256 _remain = _paddedSize % 31;
    uint256 _numFields = (_paddedSize - _remain) / 31;
    if (_remain > 0) {
      _numFields += 1;
    }
    uint256[] memory _fields = new uint256[](_numFields);
    uint256 _idx = 0;
    uint256 _byteVal = 0;
    for (uint256 i = 0; i < _numFields; ++i) {
      for (uint256 j = 0; j < 31; ++j) {
        _idx = i * 31 + j;
        if (_idx >= _paddedSize) {
          break;
        }
        if (_idx >= _bytes.length) {
          _byteVal = 0;
        } else {
          _byteVal = uint256(uint8(_bytes[_idx]));
        }
        if (j == 0) {
          _fields[i] = _byteVal;
        } else {
          _fields[i] += (_byteVal << (8 * j));
        }
      }
    }
    return _fields;
  }

  /**
    Retrieve the maximum length in bytes of a command the circuit can carry.

    @return _ The maximum command length in bytes.
  */
  function commandBytes () external pure returns (uint256) {
    return COMMAND_BYTES;
  }

  /**
    Verify an email proof: pack its claims into the circuit's public signals and
    verify the Groth16 proof against them. Claims longer than the circuit's
    fixed capacity are rejected outright.

    @param _proof The email proof to verify.

    @return _ Whether the proof is valid.
  */
  function verifyEmailProof (
    EmailProof calldata _proof
  ) external view returns (bool) {
    if (
      bytes(_proof.domainName).length > DOMAIN_BYTES
      || bytes(_proof.maskedCommand).length > COMMAND_BYTES
    ) {
      return false;
    }
    (uint256[2] memory _pA, uint256[2][2] memory _pB, uint256[2] memory _pC) =
    abi.decode(
      _proof.proof, (uint256[2], uint256[2][2], uint256[2])
    );
    if (
      _pA[0] >= Q || _pA[1] >= Q || _pB[0][0] >= Q || _pB[0][1] >= Q
      || _pB[1][0] >= Q || _pB[1][1] >= Q || _pC[0] >= Q || _pC[1] >= Q
    ) {
      revert InvalidProofPoints();
    }
    uint256[DOMAIN_FIELDS + COMMAND_FIELDS + 5] memory _pubSignals;
    uint256[] memory _fields =
      _packBytes2Fields(bytes(_proof.domainName), DOMAIN_BYTES);
    for (uint256 i = 0; i < DOMAIN_FIELDS; ++i) {
      _pubSignals[i] = _fields[i];
    }
    _pubSignals[DOMAIN_FIELDS] = uint256(_proof.publicKeyHash);
    _pubSignals[DOMAIN_FIELDS + 1] = uint256(_proof.emailNullifier);
    _pubSignals[DOMAIN_FIELDS + 2] = _proof.timestamp;
    _fields = _packBytes2Fields(bytes(_proof.maskedCommand), COMMAND_BYTES);
    for (uint256 i = 0; i < COMMAND_FIELDS; ++i) {
      _pubSignals[DOMAIN_FIELDS + 3 + i] = _fields[i];
    }
    _pubSignals[DOMAIN_FIELDS + 3 + COMMAND_FIELDS] = uint256(
      _proof.accountSalt
    );
    uint256 _codeExists = _proof.isCodeExist ? 1 : 0;
    _pubSignals[DOMAIN_FIELDS + 4 + COMMAND_FIELDS] = _codeExists;
    return groth16Verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
  }
}

