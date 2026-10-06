// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { EmailProof } from "../src/interfaces/IVerifier.sol";
import { Registry } from "../src/Registry.sol";
import { HonkVerifier } from "../src/vendor/HonkVerifier.sol";
import { Verifier } from "../src/Verifier.sol";
import { Test } from "forge-std/Test.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title VerifierTest
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The test suite for the immutable Verifier, run against the real vendored
  HonkVerifier and real proofs (see `circuits/test/`). The synthetic vectors
  come from emails signed with a throwaway test key by an independent DKIM
  implementation; the real vectors, when present, come from real
  ethereum.org emails. The packing is pinned to the prover's own public
  inputs, the binding to controller, registry, and chain is checked from every
  side, every claim is tamper-checked, aliases modulo the field are refused,
  and a profile registers, renews, rotates, and lapses end to end at the exact
  registry address its emails bind.

  @custom:date September 30th, 2026.
*/
contract VerifierTest is
  Test {

  /// Where the proof vectors live.
  string internal constant VECTORS = "../circuits/test/vectors/";

  /// The BN254 scalar field modulus.
  uint256 internal constant R =
    21888242871839275222246405745257275088548364400416034343698204186575808495617;

  /// Anvil's first account: the controller the register and renew emails name.
  address internal constant ANVIL_0 =
    0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

  /// Anvil's first account's well-known private key.
  uint256 internal constant ANVIL_0_KEY =
    0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

  /// Anvil's second account: the controller the rotate email names.
  address internal constant ANVIL_1 =
    0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

  /// The registry address every vector binds: anvil's first account at
  /// nonce 2.
  address internal constant BOUND_REGISTRY =
    0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

  /// The real vendored UltraHonk verifier.
  HonkVerifier internal honk;

  /// The immutable verifier under test.
  Verifier internal verifier;

  /// The management multisig.
  address internal management = makeAddr("management");

  /**
    Deploy the real UltraHonk verifier and the verifier, on the chain the
    vectors bind.
  */
  function setUp () public {
    vm.chainId(31337);
    honk = new HonkVerifier();
    verifier = new Verifier(address(honk));
  }

  /**
    Load an email proof from a vector.

    @param _name The vector's name.

    @return _ The email proof.
    @return _ The controller the proof binds.
    @return _ The public inputs the prover produced.
  */
  function _load (
    string memory _name
  ) internal view returns (EmailProof memory, address, bytes32[] memory) {
    string memory _json =
      vm.readFile(string.concat(VECTORS, _name, ".proof.json"));
    EmailProof memory _proof = EmailProof({
      domainName: vm.parseJsonString(_json, ".domainName"),
      publicKeyHash: vm.parseJsonBytes32(_json, ".publicKeyHash"),
      timestamp: vm.parseJsonUint(_json, ".timestamp"),
      emailNullifier: vm.parseJsonBytes32(_json, ".emailNullifier"),
      profileId: vm.parseJsonBytes32(_json, ".profileId"),
      proof: vm.parseJsonBytes(_json, ".proof")
    });
    return (_proof, vm.parseJsonAddress(_json, ".controller"),
    vm.parseJsonBytes32Array(_json, ".publicInputs"));
  }

  /**
    Verify a proof as the bound registry would.

    @param _proof The email proof.
    @param _controller The controller to verify against.

    @return _ Whether the proof verifies.
  */
  function _verifyAsRegistry (
    EmailProof memory _proof,
    address _controller
  ) internal returns (bool) {
    vm.prank(BOUND_REGISTRY);
    return verifier.verifyEmailProof(_proof, _controller);
  }

  /// The constructor pins the UltraHonk verifier and rejects zero.
  function test_constructor () public {
    assertEq(address(verifier.honkVerifier()), address(honk));
    assertEq(verifier.PUBLIC_INPUTS(), 11);
    vm.expectRevert(Verifier.ZeroAddress.selector);
    new Verifier(address(0));
  }

  /// The public inputs reproduce the prover's exactly, for every vector.
  function test_publicInputs_matchTheProver () public view {
    string[3] memory _names =
      ["synthetic-register", "synthetic-renew", "synthetic-rotate"];
    for (uint256 i = 0; i < _names.length; ++i) {
      (EmailProof memory _p, address _c, bytes32[] memory _inputs) = _load(
        _names[i]
      );
      bytes32[] memory _built =
        verifier.publicInputs(_p, _c, 31337, BOUND_REGISTRY);
      assertEq(_built.length, _inputs.length, "input count");
      for (uint256 j = 0; j < _inputs.length; ++j) {
        assertEq(_built[j], _inputs[j], "input differs");
      }
    }
  }

  /// The layout is controller, chain, registry, then the circuit's outputs.
  function test_publicInputs_knownLayout () public view {
    EmailProof memory _p;
    _p.domainName = "ethereum.org";
    _p.publicKeyHash = bytes32(uint256(6));
    _p.emailNullifier = bytes32(uint256(7));
    _p.timestamp = 8;
    _p.profileId = bytes32(uint256(0xAA) << 128 | 0xBB);
    bytes32[] memory _inputs = verifier.publicInputs(_p, ANVIL_0, 5, ANVIL_1);
    assertEq(address(uint160(uint256(_inputs[0]))), ANVIL_0);
    assertEq(uint256(_inputs[1]), 5);
    assertEq(address(uint160(uint256(_inputs[2]))), ANVIL_1);
    assertEq(
      uint256(_inputs[3]), uint256(0x657468657265756d2e6f7267) << (19 * 8)
    );
    assertEq(uint256(_inputs[4]), 0);
    assertEq(uint256(_inputs[6]), 6);
    assertEq(uint256(_inputs[7]), 7);
    assertEq(uint256(_inputs[8]), 8);
    assertEq(uint256(_inputs[9]), 0xAA);
    assertEq(uint256(_inputs[10]), 0xBB);
  }

  /// Every vector verifies for the registry, chain, and controller it binds.
  function test_verifyEmailProof_vectors () public {
    (EmailProof memory _p, address _c, ) = _load("synthetic-register");
    assertTrue(_verifyAsRegistry(_p, _c), "register");
    (_p, _c, ) = _load("synthetic-renew");
    assertTrue(_verifyAsRegistry(_p, _c), "renew");
    (_p, _c, ) = _load("synthetic-rotate");
    assertTrue(_verifyAsRegistry(_p, _c), "rotate");
  }

  /// A proof verifies for its own controller, registry, and chain only.
  function test_verifyEmailProof_bindsAuthorization () public {
    (EmailProof memory _p, address _c, ) = _load("synthetic-register");
    assertFalse(_verifyAsRegistry(_p, ANVIL_1), "another controller");
    assertFalse(verifier.verifyEmailProof(_p, _c), "another registry");
    vm.chainId(1);
    assertFalse(_verifyAsRegistry(_p, _c), "another chain");
  }

  /// Changing any claim, or the proof, invalidates it.
  function test_verifyEmailProof_rejectsTampering () public {
    (EmailProof memory _p, address _c, ) = _load("synthetic-register");
    _p.domainName = "ethereum.orh";
    assertFalse(_verifyAsRegistry(_p, _c), "domain");
    (_p, _c, ) = _load("synthetic-register");
    _p.publicKeyHash = bytes32(uint256(_p.publicKeyHash) + 1);
    assertFalse(_verifyAsRegistry(_p, _c), "key hash");
    (_p, _c, ) = _load("synthetic-register");
    _p.emailNullifier = bytes32(uint256(_p.emailNullifier) + 1);
    assertFalse(_verifyAsRegistry(_p, _c), "nullifier");
    (_p, _c, ) = _load("synthetic-register");
    _p.timestamp += 1 weeks;
    assertFalse(_verifyAsRegistry(_p, _c), "timestamp");
    (_p, _c, ) = _load("synthetic-register");
    _p.profileId = bytes32(uint256(_p.profileId) ^ 1);
    assertFalse(_verifyAsRegistry(_p, _c), "profile");
    (_p, _c, ) = _load("synthetic-register");
    _p.proof[100] = bytes1(uint8(_p.proof[100]) ^ 1);
    assertFalse(_verifyAsRegistry(_p, _c), "proof bytes");
    (_p, _c, ) = _load("synthetic-register");
    _p.proof = hex"deadbeef";
    assertFalse(_verifyAsRegistry(_p, _c), "malformed proof");
  }

  /// No claim aliases another: not modulo the field, not by a trailing zero.
  function test_verifyEmailProof_rejectsAliases () public {
    (EmailProof memory _p, address _c, ) = _load("synthetic-register");
    _p.emailNullifier = bytes32(uint256(_p.emailNullifier) + R);
    assertFalse(_verifyAsRegistry(_p, _c), "nullifier + r");
    (_p, _c, ) = _load("synthetic-register");
    _p.timestamp += R;
    assertFalse(_verifyAsRegistry(_p, _c), "timestamp + r");
    (_p, _c, ) = _load("synthetic-register");
    _p.publicKeyHash = bytes32(uint256(_p.publicKeyHash) + R);
    assertFalse(_verifyAsRegistry(_p, _c), "key hash + r");
    (_p, _c, ) = _load("synthetic-register");
    _p.domainName = string.concat(_p.domainName, "\x00");
    assertFalse(_verifyAsRegistry(_p, _c), "domain + zero byte");
    (_p, _c, ) = _load("synthetic-register");
    _p.domainName = string(new bytes(94));
    assertFalse(_verifyAsRegistry(_p, _c), "oversized domain");
  }

  /**
    Deploy a registry at the address the vectors bind, and honor the key that
    signed them.

    @param _keyHash The DKIM key hash to honor.

    @return _ The registry.
  */
  function _boundRegistry (
    bytes32 _keyHash
  ) internal returns (Registry) {
    vm.setNonce(ANVIL_0, 2);
    vm.prank(ANVIL_0);
    Registry _registry =
      new Registry(address(verifier), "ethereum.org", management);
    assertEq(
      address(_registry), BOUND_REGISTRY, "the vectors bind this address"
    );
    vm.prank(management);
    _registry.setDKIMPublicKeyHash(_keyHash, true);
    return _registry;
  }

  /**
    Sign the current controller's authorization of one email.

    @param _registry The registry.
    @param _nullifier The email's nullifier.

    @return _ The signature.
  */
  function _authorization (
    Registry _registry,
    bytes32 _nullifier
  ) internal view returns (bytes memory) {
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      ANVIL_0_KEY, _registry.authorizationDigest(_nullifier)
    );
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Run a profile's whole life from three vectors: register, renew, rotate,
    refuse every replay, and lapse.

    @param _prefix The vector names' prefix, `synthetic-` or `real-`.
  */
  function _lifecycle (
    string memory _prefix
  ) internal {
    (EmailProof memory _register, address _c0, ) = _load(
      string.concat(_prefix, "register")
    );
    (EmailProof memory _renew, , ) = _load(string.concat(_prefix, "renew"));
    (EmailProof memory _rotate, address _c1, ) = _load(
      string.concat(_prefix, "rotate")
    );
    assertEq(_c0, ANVIL_0);
    assertEq(_c1, ANVIL_1);
    assertEq(_register.profileId, _renew.profileId, "one profile");
    assertEq(_register.profileId, _rotate.profileId, "one profile");
    bytes32 _id = _register.profileId;
    Registry _registry = _boundRegistry(_register.publicKeyHash);
    vm.warp(_register.timestamp + 2 weeks);

    // The controller the email names, and no other.
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    _registry.register(_register, ANVIL_1);
    vm.prank(makeAddr("relayer"));
    _registry.register(_register, ANVIL_0);
    (address _controller, bool _active, , uint256 _last) = _registry.profiles(
      _id
    );
    assertEq(_controller, ANVIL_0);
    assertTrue(_active);
    assertEq(_last, _register.timestamp);
    assertTrue(_registry.isActive(_id));
    assertEq(_registry.expiresAt(_id), _register.timestamp + 90 days);
    vm.prank(ANVIL_0);
    _registry.setText(_id, "url", "https://ethereum.org");

    // Renewal: a fresh email for the same controller, co-signed.
    _registry.setController(
      _renew, ANVIL_0, _authorization(_registry, _renew.emailNullifier)
    );
    assertEq(_registry.expiresAt(_id), _renew.timestamp + 90 days);

    // No email acts twice.
    vm.expectRevert(
      abi.encodeWithSelector(Registry.AlreadyRegistered.selector, _id)
    );
    _registry.register(_register, ANVIL_0);
    bytes memory _again = _authorization(_registry, _renew.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(
        Registry.EmailAlreadyUsed.selector, _renew.emailNullifier
      )
    );
    _registry.setController(_renew, ANVIL_0, _again);

    // Rotation, co-signed by the current controller.
    _registry.setController(
      _rotate, ANVIL_1, _authorization(_registry, _rotate.emailNullifier)
    );
    (_controller, , , ) = _registry.profiles(_id);
    assertEq(_controller, ANVIL_1);

    // The profile lapses without another email.
    vm.warp(_rotate.timestamp + 90 days);
    assertFalse(_registry.isActive(_id));
    vm.prank(ANVIL_1);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.LapsedProfile.selector, _id)
    );
    _registry.setText(_id, "url", "https://elsewhere.example");
    assertEq(
      _registry.text(_id, "url"), "https://ethereum.org", "records kept"
    );
  }

  /// A profile lives its whole life from synthetic emails.
  function test_registry_syntheticLifecycle () public {
    _lifecycle("synthetic-");
  }

  /**
    A profile lives its whole life from real ethereum.org emails, when those
    fixtures are present.
  */
  function test_registry_realLifecycle () public {
    vm.skip(!vm.exists(string.concat(VECTORS, "real-register.proof.json")));
    _lifecycle("real-");
  }

  /// An email older than its lifetime cannot act, however valid its proof.
  function test_registry_rejectsExpiredEmail () public {
    (EmailProof memory _p, , ) = _load("synthetic-register");
    Registry _registry = _boundRegistry(_p.publicKeyHash);
    vm.warp(_p.timestamp + 5 weeks + 1);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.ExpiredEmail.selector, _p.timestamp)
    );
    _registry.register(_p, ANVIL_0);
  }

  /// A key management has not honored is refused.
  function test_registry_rejectsUnhonoredKey () public {
    (EmailProof memory _p, , ) = _load("synthetic-register");
    Registry _registry = _boundRegistry(_p.publicKeyHash);
    vm.warp(_p.timestamp + 1 days);
    vm.prank(management);
    _registry.setDKIMPublicKeyHash(_p.publicKeyHash, false);
    vm.expectRevert(
      abi.encodeWithSelector(
        Registry.InvalidDKIMPublicKeyHash.selector, _p.publicKeyHash
      )
    );
    _registry.register(_p, ANVIL_0);
  }

  /// A registry anywhere else refuses the email: the binding is exact.
  function test_registry_rejectsForeignBinding () public {
    Registry _registry =
      new Registry(address(verifier), "ethereum.org", management);
    (EmailProof memory _p, , ) = _load("synthetic-register");
    vm.prank(management);
    _registry.setDKIMPublicKeyHash(_p.publicKeyHash, true);
    vm.warp(_p.timestamp + 1 days);
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    _registry.register(_p, ANVIL_0);
  }
}

