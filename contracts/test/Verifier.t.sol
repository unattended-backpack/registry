// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { EmailProof } from "../src/interfaces/IVerifier.sol";
import { Registry } from "../src/Registry.sol";
import { Groth16Verifier } from "../src/vendor/Groth16Verifier.sol";
import { Verifier } from "../src/Verifier.sol";
import { Test } from "forge-std/Test.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title VerifierTest
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The test suite for the immutable Verifier, run against the real vendored
  Groth16Verifier: the packing is pinned to hand-computed vectors, malformed
  proofs revert, oversized claims are rejected outright, and a proof that is
  not a proof fails the real pairing check, both directly and through the
  Registry.

  @custom:date August 25th, 2026.
*/
contract VerifierTest is
  Test {

  /// A DKIM key hash management honors for the domain.
  bytes32 internal constant KEY_HASH = keccak256("ethereum.org dkim key");

  /// The real vendored Groth16 verifier.
  Groth16Verifier internal groth16;

  /// The immutable verifier under test.
  Verifier internal verifier;

  /// A harness exposing the verifier's packing for vector tests.
  VerifierHarness internal harness;

  /// The management multisig.
  address internal management = makeAddr("management");

  /// A wallet Alice binds as her controller.
  address internal aliceWallet = makeAddr("aliceWallet");

  /// Deploy the real Groth16 verifier, the verifier, and the harness.
  function setUp () public {
    groth16 = new Groth16Verifier();
    verifier = new Verifier(address(groth16));
    harness = new VerifierHarness(address(groth16));
  }

  /**
    Build proof bytes that decode to well-formed field elements without being a
    proof of anything.

    @return _ The proof bytes.
  */
  function _fakeProofBytes () internal pure returns (bytes memory) {
    uint256[2] memory _pA = [uint256(1), uint256(2)];
    uint256[2][2] memory _pB =
      [[uint256(1), uint256(2)], [uint256(3), uint256(4)]];
    uint256[2] memory _pC = [uint256(1), uint256(2)];
    return abi.encode(_pA, _pB, _pC);
  }

  /**
    Build an email proof around the given proof bytes.

    @param _proofBytes The proof bytes.

    @return _ The email proof.
  */
  function _proof (
    bytes memory _proofBytes
  ) internal view returns (EmailProof memory) {
    return EmailProof({
      domainName: "ethereum.org",
      publicKeyHash: bytes32(uint256(123)),
      timestamp: block.timestamp,
      maskedCommand: "Set text record url to https://x.example 1:0x0",
      emailNullifier: bytes32(uint256(456)),
      accountSalt: bytes32(uint256(789)),
      isCodeExist: true,
      proof: _proofBytes
    });
  }

  /// The constructor pins the Groth16 verifier and rejects zero.
  function test_constructor () public {
    assertEq(address(verifier.groth16Verifier()), address(groth16));
    assertEq(verifier.commandBytes(), 605);
    vm.expectRevert(Verifier.ZeroAddress.selector);
    new Verifier(address(0));
  }

  /// A proof that is not a proof fails the real pairing check.
  function test_verifyEmailProof_rejectsNonProof () public view {
    assertFalse(verifier.verifyEmailProof(_proof(_fakeProofBytes())));
  }

  /// Proof bytes that do not decode to proof points revert.
  function test_verifyEmailProof_revertsOnMalformedBytes () public {
    vm.expectRevert();
    verifier.verifyEmailProof(_proof(hex"deadbeef"));
  }

  /// Proof points outside the BN254 base field revert.
  function test_verifyEmailProof_revertsOnOutOfFieldPoints () public {
    uint256[2] memory _pA = [type(uint256).max, uint256(2)];
    uint256[2][2] memory _pB =
      [[uint256(1), uint256(2)], [uint256(3), uint256(4)]];
    uint256[2] memory _pC = [uint256(1), uint256(2)];
    EmailProof memory _p = _proof(abi.encode(_pA, _pB, _pC));
    vm.expectRevert(Verifier.InvalidProofPoints.selector);
    verifier.verifyEmailProof(_p);
  }

  /// Claims longer than the circuit's fixed capacity are rejected outright.
  function test_verifyEmailProof_rejectsOversizedClaims () public view {
    EmailProof memory _p = _proof(_fakeProofBytes());
    _p.maskedCommand = new string(606);
    assertFalse(verifier.verifyEmailProof(_p));
    _p = _proof(_fakeProofBytes());
    _p.domainName = new string(256);
    assertFalse(verifier.verifyEmailProof(_p));
  }

  /// The packing matches the circuit's 31-byte little-endian layout exactly.
  function test_packBytes2Fields_knownVectors () public view {
    uint256[] memory _fields = harness.packBytes2Fields(bytes("abc"), 62);
    assertEq(_fields.length, 2);
    assertEq(_fields[0], 0x636261);
    assertEq(_fields[1], 0);
    _fields = harness.packBytes2Fields(bytes("ethereum.org"), 255);
    assertEq(_fields.length, 9);
    assertEq(_fields[0], 0x67726f2e6d75657265687465);
    for (uint256 i = 1; i < 9; ++i) {
      assertEq(_fields[i], 0);
    }

    // The 31st byte of a field lands in its top packed position.
    bytes memory _bytes = new bytes(31);
    _bytes[30] = 0xff;
    _fields = harness.packBytes2Fields(_bytes, 62);
    assertEq(
      _fields[0],
      0xff000000000000000000000000000000000000000000000000000000000000
    );
    assertEq(_fields[1], 0);
  }

  /// The registry surfaces a failed pairing as an invalid email proof.
  function test_registryIntegration_rejectsNonProof () public {
    Registry _registry =
      new Registry(address(verifier), "ethereum.org", management);
    vm.prank(management);
    _registry.setDKIMPublicKeyHash(KEY_HASH, true);
    EmailProof memory _p = EmailProof({
      domainName: "ethereum.org",
      publicKeyHash: KEY_HASH,
      timestamp: block.timestamp,
      maskedCommand: _registry.setControllerCommand(aliceWallet),
      emailNullifier: keccak256("verifier integration email"),
      accountSalt: keccak256("alice@ethereum.org|code"),
      isCodeExist: true,
      proof: _fakeProofBytes()
    });
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    _registry.register(_p, aliceWallet);
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title VerifierHarness
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  A thin harness exposing the Verifier's internal packing so tests can pin it
  to hand-computed vectors.

  @custom:date August 25th, 2026.
*/
contract VerifierHarness is
  Verifier {

  /**
    Construct the harness against a Groth16 verifier.

    @param _groth16Verifier The Groth16 verifier to pin.
  */
  constructor (
    address _groth16Verifier
  ) Verifier(_groth16Verifier) { }

  /**
    Pack bytes into 31-byte little-endian field elements.

    @param _bytes The bytes to pack.
    @param _paddedSize The circuit's fixed byte capacity for this input.

    @return _ The packed field elements.
  */
  function packBytes2Fields (
    bytes memory _bytes,
    uint256 _paddedSize
  ) external pure returns (uint256[] memory) {
    return _packBytes2Fields(_bytes, _paddedSize);
  }
}

