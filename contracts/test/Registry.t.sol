// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { EmailProof } from "../src/interfaces/IVerifier.sol";
import { Registry } from "../src/Registry.sol";
import { MockERC1271Wallet } from "./mocks/MockERC1271Wallet.sol";
import { MockVerifier } from "./mocks/MockVerifier.sol";
import { Test } from "forge-std/Test.sol";
import { LibString } from "solady/utils/LibString.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RegistryTest
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The test suite for the Registry, run against a mock verifier that accepts
  exactly the proofs a test builds for a given controller, chain, and
  registry, so every policy check the registry performs itself (domain, key
  hashes, nullifier, email lifetime, timestamp order, controller binding,
  controller signature, nonce, revocation, lapse and renewal) is exercised in
  isolation from the circuit.

  @custom:date October 1st, 2026.
*/
contract RegistryTest is
  Test {
  using LibString for uint256;

  /// The pinned email domain.
  string internal constant DOMAIN = "ethereum.org";

  /// A DKIM key hash management honors for the domain.
  bytes32 internal constant KEY_HASH = keccak256("ethereum.org dkim key");

  /// Alice's identity: the hash of her address. Immutable, not constant:
  /// a constant would re-call the SHA-256 precompile at every use, and that
  /// call would consume the next prank or expected revert.
  bytes32 internal immutable ALICE = sha256("alice@ethereum.org");

  /// Bob's identity: the hash of his address.
  bytes32 internal immutable BOB = sha256("bob@ethereum.org");

  /// Carol's identity: the hash of her address.
  bytes32 internal immutable CAROL = sha256("carol@ethereum.org");

  /// The mock proof verifier.
  MockVerifier internal verifier;

  /// The registry under test.
  Registry internal registry;

  /// The management multisig.
  address internal management = makeAddr("management");

  /// A wallet Alice binds as her controller.
  address internal aliceWallet;

  /// The key behind Alice's wallet.
  uint256 internal aliceKey;

  /// A wallet Bob binds as his controller.
  address internal bobWallet;

  /// The key behind Bob's wallet.
  uint256 internal bobKey;

  /// Whoever relays proofs to the chain; it has no authority of its own.
  address internal relayer = makeAddr("relayer");

  /// The number of emails built so far, so each gets a fresh nullifier.
  uint256 internal emailsSent;

  /// Deploy the mock verifier and the registry, and honor one DKIM key.
  function setUp () public {
    (aliceWallet, aliceKey) = makeAddrAndKey("aliceWallet");
    (bobWallet, bobKey) = makeAddrAndKey("bobWallet");
    verifier = new MockVerifier();
    registry = new Registry(address(verifier), DOMAIN, management);
    vm.prank(management);
    registry.setDKIMPublicKeyHash(KEY_HASH, true);

    // A realistic clock, so DKIM timestamps read like the real thing.
    vm.warp(1_800_000_000);
  }

  /**
    Build the mock proof bytes authorizing a controller on a registry and chain.

    @param _controller The controller the email authorizes.
    @param _chainId The chain the email authorizes.
    @param _registry The registry the email authorizes.

    @return _ The proof bytes.
  */
  function _proofBytes (
    address _controller,
    uint256 _chainId,
    address _registry
  ) internal pure returns (bytes memory) {
    return abi.encode(keccak256("valid"), _controller, _chainId, _registry);
  }

  /**
    Build an email proof the mock verifier accepts for the registry under test,
    with a fresh nullifier.

    @param _profileId The ID of the profile the email acts on.
    @param _controller The controller the email authorizes.
    @param _timestamp The week-rounded DKIM timestamp of the email.

    @return _ The email proof.
  */
  function _proof (
    bytes32 _profileId,
    address _controller,
    uint256 _timestamp
  ) internal returns (EmailProof memory) {
    return EmailProof({
      domainName: DOMAIN,
      publicKeyHash: KEY_HASH,
      timestamp: _timestamp,
      emailNullifier: keccak256(abi.encode("email", ++emailsSent)),
      profileId: _profileId,
      proof: _proofBytes(_controller, block.chainid, address(registry))
    });
  }

  /**
    Build a current email for a profile.

    @param _profileId The ID of the profile the email acts on.
    @param _controller The controller the email authorizes.

    @return _ The email proof.
  */
  function _email (
    bytes32 _profileId,
    address _controller
  ) internal returns (EmailProof memory) {
    return _proof(_profileId, _controller, block.timestamp);
  }

  /**
    Sign a controller's authorization of one email.

    @param _key The controller's private key.
    @param _emailNullifier The nullifier of the email to authorize.

    @return _ The signature.
  */
  function _sign (
    uint256 _key,
    bytes32 _emailNullifier
  ) internal view returns (bytes memory) {
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      _key, registry.authorizationDigest(_emailNullifier)
    );
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Sign a controller's relayed text-record write at the current nonce.

    @param _key The controller's private key.
    @param _profileId The ID of the profile.
    @param _recordKey The record key.
    @param _value The record value.

    @return _ The signature.
  */
  function _signText (
    uint256 _key,
    bytes32 _profileId,
    string memory _recordKey,
    string memory _value
  ) internal view returns (bytes memory) {
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      _key, registry.setTextDigest(_profileId, _recordKey, _value)
    );
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Sign a controller's relayed batch of text-record writes at the current
    nonce.

    @param _key The controller's private key.
    @param _profileId The ID of the profile.
    @param _keys The record keys.
    @param _values The record values.

    @return _ The signature.
  */
  function _signTexts (
    uint256 _key,
    bytes32 _profileId,
    string[] memory _keys,
    string[] memory _values
  ) internal view returns (bytes memory) {
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      _key, registry.setTextsDigest(_profileId, _keys, _values)
    );
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Build an empty list of strings.

    @return _ The list.
  */
  function _list () internal pure returns (string[] memory) {
    return new string[](0);
  }

  /**
    Build a list of one string.

    @param _a The string.

    @return _ The list.
  */
  function _list (
    string memory _a
  ) internal pure returns (string[] memory) {
    string[] memory _out = new string[](1);
    _out[0] = _a;
    return _out;
  }

  /**
    Build a list of two strings.

    @param _a The first string.
    @param _b The second string.

    @return _ The list.
  */
  function _list (
    string memory _a,
    string memory _b
  ) internal pure returns (string[] memory) {
    string[] memory _out = new string[](2);
    _out[0] = _a;
    _out[1] = _b;
    return _out;
  }

  /**
    Build a list of three strings.

    @param _a The first string.
    @param _b The second string.
    @param _c The third string.

    @return _ The list.
  */
  function _list (
    string memory _a,
    string memory _b,
    string memory _c
  ) internal pure returns (string[] memory) {
    string[] memory _out = new string[](3);
    _out[0] = _a;
    _out[1] = _b;
    _out[2] = _c;
    return _out;
  }

  /**
    Compute the registry's EIP-712 domain separator from first principles.

    @return _ The domain separator.
  */
  function _domainSeparator () internal view returns (bytes32) {
    return keccak256(
      abi.encode(
        keccak256(
          abi.encodePacked(
            "EIP712Domain(string name,string version,uint256 chainId,",
            "address verifyingContract)"
          )
        ), keccak256(bytes("Registry")), keccak256(bytes("1")), block.chainid,
        address(registry)
      )
    );
  }

  /**
    Register a profile by email, binding a controller.

    @param _sender The hash of the sender's address.
    @param _controller The controller to bind.
  */
  function _register (
    bytes32 _sender,
    address _controller
  ) internal {
    registry.register(_email(_sender, _controller), _controller);
  }

  /**
    Retrieve a profile.

    @param _sender The profile ID.

    @return _ The profile's controller, active flag, registration time, and last
      honored DKIM timestamp.
  */
  function _profile (
    bytes32 _sender
  ) internal view returns (address, bool, uint256, uint256) {
    return registry.profiles(_sender);
  }

  /**
    Retrieve a profile's controller.

    @param _sender The profile ID.

    @return _ The profile's controller.
  */
  function _controllerOf (
    bytes32 _sender
  ) internal view returns (address) {
    (address _c, , , ) = registry.profiles(_sender);
    return _c;
  }

  /**
    Retrieve a profile's last honored DKIM timestamp.

    @param _sender The profile ID.

    @return _ The profile's last honored DKIM timestamp.
  */
  function _lastTimestamp (
    bytes32 _sender
  ) internal view returns (uint256) {
    (, , , uint256 _t) = registry.profiles(_sender);
    return _t;
  }

  /// The constructor wires up the verifier, the domain, and management.
  function test_constructor () public view {
    assertEq(address(registry.verifier()), address(verifier));
    assertTrue(registry.dkimPublicKeyHashes(KEY_HASH));
    assertEq(registry.domain(), DOMAIN);
    assertEq(registry.management(), management);
    assertEq(registry.pendingManagement(), address(0));
    assertEq(registry.profileCount(), 0);
  }

  /// The constructor rejects zero addresses.
  function test_constructor_revertsOnZeroAddresses () public {
    vm.expectRevert(Registry.ZeroAddress.selector);
    new Registry(address(0), DOMAIN, management);
    vm.expectRevert(Registry.ZeroAddress.selector);
    new Registry(address(verifier), DOMAIN, address(0));
  }

  /// The constructor rejects an empty domain.
  function test_constructor_revertsOnEmptyDomain () public {
    vm.expectRevert(Registry.EmptyDomain.selector);
    new Registry(address(verifier), "", management);
  }

  /// A registration email creates the profile and binds the controller.
  function test_register () public {
    EmailProof memory _p = _email(ALICE, aliceWallet);
    vm.expectEmit(address(registry));
    emit Registry.EmailAuthorized(
      ALICE, _p.emailNullifier, KEY_HASH, block.timestamp
    );
    vm.expectEmit(address(registry));
    emit Registry.Registered(ALICE);
    vm.expectEmit(address(registry));
    emit Registry.ControllerSet(ALICE, aliceWallet);
    registry.register(_p, aliceWallet);
    (address _c, bool _active, uint256 _registeredAt, uint256 _t) = _profile(
      ALICE
    );
    assertEq(_c, aliceWallet);
    assertTrue(_active, "new profiles are active");
    assertEq(_registeredAt, block.timestamp);
    assertEq(_t, block.timestamp, "the DKIM timestamp is recorded");
    assertEq(registry.profileCount(), 1);
    assertEq(registry.profileIds(0), ALICE);
    assertTrue(registry.usedNullifiers(_p.emailNullifier), "email consumed");
  }

  /// Anyone may relay a proof; the email, not the sender, is the authority.
  function test_email_anyoneMaySubmit () public {
    EmailProof memory _p = _email(ALICE, aliceWallet);
    vm.prank(relayer);
    registry.register(_p, aliceWallet);
    assertEq(_controllerOf(ALICE), aliceWallet);

    // The relayer gained nothing by relaying.
    vm.prank(relayer);
    vm.expectRevert(Registry.NotController.selector);
    registry.setText(ALICE, "avatar", "x");
  }

  /// Every profile is a two-of-two from birth: no zero controllers.
  function test_register_requiresNonzeroController () public {
    EmailProof memory _p = _email(ALICE, address(0));
    vm.expectRevert(Registry.ZeroAddress.selector);
    registry.register(_p, address(0));
  }

  /// An identity registers exactly once.
  function test_register_once () public {
    _register(ALICE, aliceWallet);
    EmailProof memory _p = _email(ALICE, bobWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.AlreadyRegistered.selector, ALICE)
    );
    registry.register(_p, bobWallet);
    assertEq(_controllerOf(ALICE), aliceWallet, "controller unmoved");
  }

  /**
    An email authorizes exactly one controller, on exactly this registry, on
    exactly this chain.
  */
  function test_register_bindsController () public {

    // The email authorizes bob's wallet; the call claims alice's.
    EmailProof memory _p = _email(ALICE, bobWallet);
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    registry.register(_p, aliceWallet);

    // The right controller on another registry.
    _p = _email(ALICE, aliceWallet);
    _p.proof = _proofBytes(aliceWallet, block.chainid, bobWallet);
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    registry.register(_p, aliceWallet);

    // The right controller and registry on another chain.
    _p = _email(ALICE, aliceWallet);
    _p.proof = _proofBytes(aliceWallet, 999, address(registry));
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    registry.register(_p, aliceWallet);
    assertEq(registry.profileCount(), 0, "nothing registered");
  }

  /// Rotation needs email and the current controller's signature together.
  function test_setController_requiresControllerSignature () public {
    _register(ALICE, aliceWallet);
    EmailProof memory _p = _email(ALICE, bobWallet);

    // No signature.
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setController(_p, bobWallet, "");

    // A signature from a key that is not the controller's.
    bytes memory _strangerSig = _sign(bobKey, _p.emailNullifier);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setController(_p, bobWallet, _strangerSig);

    // The controller's signature over a different email.
    bytes memory _foreignSig = _sign(aliceKey, keccak256("some other email"));
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setController(_p, bobWallet, _foreignSig);

    // Email plus the controller's signature over this email.
    registry.setController(_p, bobWallet, _sign(aliceKey, _p.emailNullifier));
    assertEq(_controllerOf(ALICE), bobWallet);

    // The signing power moved with the rotation.
    _p = _email(ALICE, aliceWallet);
    bytes memory _staleSig = _sign(aliceKey, _p.emailNullifier);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setController(_p, aliceWallet, _staleSig);
    registry.setController(_p, aliceWallet, _sign(bobKey, _p.emailNullifier));
    assertEq(_controllerOf(ALICE), aliceWallet);
    assertEq(registry.profileCount(), 1, "no re-registration");
  }

  /// Rotation binds the controller exactly, just as registration does.
  function test_setController_bindsController () public {
    _register(ALICE, aliceWallet);

    // The email authorizes bob's wallet; the call claims carol's.
    EmailProof memory _p = _email(ALICE, bobWallet);
    bytes memory _sig = _sign(aliceKey, _p.emailNullifier);
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    registry.setController(_p, makeAddr("carol"), _sig);
    assertEq(_controllerOf(ALICE), aliceWallet, "controller unmoved");
  }

  /// Rotation never unbinds: the two-of-two is permanent.
  function test_setController_rejectsZero () public {
    _register(ALICE, aliceWallet);
    EmailProof memory _p = _email(ALICE, address(0));
    bytes memory _sig = _sign(aliceKey, _p.emailNullifier);
    vm.expectRevert(Registry.ZeroAddress.selector);
    registry.setController(_p, address(0), _sig);
  }

  /// Rotation acts only on registered profiles; nothing auto-registers.
  function test_setController_requiresRegistration () public {
    EmailProof memory _p = _email(BOB, bobWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.UnknownProfile.selector, BOB)
    );
    registry.setController(_p, bobWallet, "");
    assertEq(registry.profileCount(), 0);
  }

  /// An execution-less smart account controls a profile through ERC-1271.
  function test_controller_supportsERC1271Accounts () public {
    MockERC1271Wallet _wallet = new MockERC1271Wallet(aliceWallet);
    _register(ALICE, address(_wallet));

    // A stranger's key does not satisfy the wallet.
    bytes memory _strangerSig = _signText(bobKey, ALICE, "avatar", "a");
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextSigned(ALICE, "avatar", "a", _strangerSig);

    // The wallet's underlying key does, and it rotates the root too.
    registry.setTextSigned(
      ALICE, "avatar", "a", _signText(aliceKey, ALICE, "avatar", "a")
    );
    assertEq(registry.text(ALICE, "avatar"), "a");

    // So does a batch, under one signature.
    string[] memory _keys = _list("avatar", "url");
    string[] memory _values = _list("b", "https://alice.example");
    bytes memory _strangerBatchSig = _signTexts(bobKey, ALICE, _keys, _values);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextsSigned(ALICE, _keys, _values, _strangerBatchSig);
    registry.setTextsSigned(
      ALICE, _keys, _values, _signTexts(aliceKey, ALICE, _keys, _values)
    );
    assertEq(registry.text(ALICE, "avatar"), "b");
    assertEq(registry.text(ALICE, "url"), "https://alice.example");
    EmailProof memory _p = _email(ALICE, bobWallet);
    registry.setController(_p, bobWallet, _sign(aliceKey, _p.emailNullifier));
    assertEq(_controllerOf(ALICE), bobWallet);
  }

  /// The authorization digest is exactly the documented EIP-712 digest.
  function test_authorizationDigest () public view {
    bytes32 _nullifier = keccak256("some email");
    bytes32 _domainTypehash =
      keccak256(
        abi.encodePacked(
          "EIP712Domain(string name,string version,uint256 chainId,",
          "address verifyingContract)"
        )
      );
    bytes32 _domainSeparator =
      keccak256(
        abi.encode(
          _domainTypehash, keccak256(bytes("Registry")), keccak256(bytes("1")),
          block.chainid, address(registry)
        )
      );
    bytes32 _structHash =
      keccak256(
        abi.encode(registry.EMAIL_AUTHORIZATION_TYPEHASH(), _nullifier)
      );
    assertEq(
      registry.authorizationDigest(_nullifier),
      keccak256(abi.encodePacked(hex"1901", _domainSeparator, _structHash))
    );
  }

  /// Emails from any other domain are rejected, whatever key signed them.
  function test_email_revertsOnWrongDomain () public {

    // Even an honored key hash cannot speak for a foreign domain.
    EmailProof memory _p = _email(ALICE, aliceWallet);
    _p.domainName = "ethereum.com";
    vm.expectRevert(
      abi.encodeWithSelector(Registry.WrongDomain.selector, "ethereum.com")
    );
    registry.register(_p, aliceWallet);
  }

  /// Emails signed with a key management does not honor are rejected.
  function test_email_revertsOnUnknownDKIMKey () public {
    EmailProof memory _p = _email(ALICE, aliceWallet);
    _p.publicKeyHash = keccak256("some other key");
    vm.expectRevert(
      abi.encodeWithSelector(
        Registry.InvalidDKIMPublicKeyHash.selector, _p.publicKeyHash
      )
    );
    registry.register(_p, aliceWallet);

    // A revoked key stops working at once.
    vm.prank(management);
    registry.setDKIMPublicKeyHash(KEY_HASH, false);
    _p = _email(ALICE, aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(
        Registry.InvalidDKIMPublicKeyHash.selector, KEY_HASH
      )
    );
    registry.register(_p, aliceWallet);
  }

  /// Only management maintains the honored DKIM key hashes.
  function test_setDKIMPublicKeyHash_onlyManagement () public {
    bytes32 _newKey = keccak256("rotated ethereum.org dkim key");
    vm.prank(aliceWallet);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.setDKIMPublicKeyHash(_newKey, true);

    // A rotation: the new key is honored, the old key is revoked.
    vm.prank(management);
    vm.expectEmit(address(registry));
    emit Registry.DKIMPublicKeyHashSet(_newKey, true);
    registry.setDKIMPublicKeyHash(_newKey, true);
    vm.prank(management);
    registry.setDKIMPublicKeyHash(KEY_HASH, false);
    assertTrue(registry.dkimPublicKeyHashes(_newKey));
    assertFalse(registry.dkimPublicKeyHashes(KEY_HASH));

    // Old-key emails fail; new-key emails act.
    EmailProof memory _p = _email(ALICE, aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(
        Registry.InvalidDKIMPublicKeyHash.selector, KEY_HASH
      )
    );
    registry.register(_p, aliceWallet);
    _p = _email(ALICE, aliceWallet);
    _p.publicKeyHash = _newKey;
    registry.register(_p, aliceWallet);
    assertEq(_controllerOf(ALICE), aliceWallet);
  }

  /// Every email is single-use, whatever it is resubmitted as.
  function test_email_isSingleUse () public {
    EmailProof memory _p = _email(ALICE, aliceWallet);
    registry.register(_p, aliceWallet);

    // The registration email cannot register anyone else.
    EmailProof memory _r = _email(BOB, bobWallet);
    _r.emailNullifier = _p.emailNullifier;
    vm.expectRevert(
      abi.encodeWithSelector(
        Registry.EmailAlreadyUsed.selector, _p.emailNullifier
      )
    );
    registry.register(_r, bobWallet);

    // Nor can it be re-spent as an authorized rotation.
    EmailProof memory _q = _email(ALICE, bobWallet);
    _q.emailNullifier = _p.emailNullifier;
    bytes memory _sig = _sign(aliceKey, _q.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(
        Registry.EmailAlreadyUsed.selector, _p.emailNullifier
      )
    );
    registry.setController(_q, bobWallet, _sig);
  }

  /// Emails honored for a profile never run backwards in DKIM time.
  function test_email_mustNotRunBackwards () public {
    uint256 _now = block.timestamp;
    _register(ALICE, aliceWallet);
    assertEq(_lastTimestamp(ALICE), _now);

    // An older email can no longer be honored.
    EmailProof memory _old = _proof(ALICE, bobWallet, _now - 100);
    bytes memory _oldSig = _sign(aliceKey, _old.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.StaleEmail.selector, _now - 100, _now)
    );
    registry.setController(_old, bobWallet, _oldSig);

    // The same second is fine.
    EmailProof memory _same = _proof(ALICE, bobWallet, _now);
    registry.setController(
      _same, bobWallet, _sign(aliceKey, _same.emailNullifier)
    );
    assertEq(_lastTimestamp(ALICE), _now);

    // A zero timestamp is simply the oldest possible email.
    EmailProof memory _zero = _proof(ALICE, aliceWallet, 0);
    bytes memory _zeroSig = _sign(bobKey, _zero.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.StaleEmail.selector, 0, _now)
    );
    registry.setController(_zero, aliceWallet, _zeroSig);

    // A later email advances the clock.
    EmailProof memory _later = _proof(ALICE, bobWallet, _now + 5);
    registry.setController(
      _later, bobWallet, _sign(bobKey, _later.emailNullifier)
    );
    assertEq(_lastTimestamp(ALICE), _now + 5);
    assertEq(_controllerOf(ALICE), bobWallet);
  }

  /// A proof the verifier rejects does nothing, and spends nothing.
  function test_email_revertsOnInvalidProof () public {
    EmailProof memory _p = _email(ALICE, aliceWallet);
    _p.proof = "forged";
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    registry.register(_p, aliceWallet);
    assertFalse(registry.usedNullifiers(_p.emailNullifier));
    assertEq(registry.profileCount(), 0);

    // A forged rotation is rejected the same way, spending nothing.
    _register(ALICE, aliceWallet);
    EmailProof memory _q = _email(ALICE, bobWallet);
    _q.proof = "forged";
    bytes memory _sig = _sign(aliceKey, _q.emailNullifier);
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    registry.setController(_q, bobWallet, _sig);
    assertFalse(registry.usedNullifiers(_q.emailNullifier));
  }

  /// An inactive profile rejects every email, and honors none.
  function test_email_revertsWhenInactive () public {
    _register(ALICE, aliceWallet);
    vm.prank(management);
    registry.setActive(ALICE, false);
    EmailProof memory _p = _email(ALICE, bobWallet);
    bytes memory _sig = _sign(aliceKey, _p.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InactiveProfile.selector, ALICE)
    );
    registry.setController(_p, bobWallet, _sig);
    assertFalse(registry.usedNullifiers(_p.emailNullifier), "not spent");

    // The relayed signed record path is frozen too.
    bytes memory _textSig = _signText(aliceKey, ALICE, "avatar", "a");
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InactiveProfile.selector, ALICE)
    );
    registry.setTextSigned(ALICE, "avatar", "a", _textSig);

    // Reactivation restores email control, including the rejected email.
    vm.prank(management);
    registry.setActive(ALICE, true);
    registry.setController(_p, bobWallet, _sig);
    assertEq(_controllerOf(ALICE), bobWallet);
  }

  /**
    A relayed signature sets a record, clears it, and consumes a nonce each
    time.
  */
  function test_setTextSigned () public {
    _register(BOB, bobWallet);
    string memory _url = "https://example.org/bob.png";
    assertEq(registry.nonces(BOB), 0);
    vm.expectEmit(address(registry));
    emit Registry.TextChanged(BOB, "avatar", "avatar", _url);
    registry.setTextSigned(
      BOB, "avatar", _url, _signText(bobKey, BOB, "avatar", _url)
    );
    assertEq(registry.text(BOB, "avatar"), _url);
    assertEq(registry.text(BOB, "url"), "", "unset records are empty");
    assertEq(registry.nonces(BOB), 1);

    // An empty value clears, at the next nonce.
    registry.setTextSigned(
      BOB, "avatar", "", _signText(bobKey, BOB, "avatar", "")
    );
    assertEq(registry.text(BOB, "avatar"), "");
    assertEq(registry.nonces(BOB), 2);
  }

  /**
    A relayed signature is single-use and bound to its signer, profile, and
    content.
  */
  function test_setTextSigned_replayAndBinding () public {
    _register(ALICE, aliceWallet);
    _register(BOB, bobWallet);
    bytes memory _sig = _signText(aliceKey, ALICE, "avatar", "a");
    registry.setTextSigned(ALICE, "avatar", "a", _sig);

    // The consumed nonce retires the signature.
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextSigned(ALICE, "avatar", "a", _sig);

    // A stranger's signature is refused.
    bytes memory _strangerSig = _signText(bobKey, ALICE, "url", "x");
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextSigned(ALICE, "url", "x", _strangerSig);

    // A signature for one profile says nothing about another.
    bytes memory _crossSig = _signText(aliceKey, ALICE, "url", "x");
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextSigned(BOB, "url", "x", _crossSig);

    // A signature covers exactly its key and value.
    bytes memory _valueSig = _signText(aliceKey, ALICE, "url", "x");
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextSigned(ALICE, "url", "y", _valueSig);
  }

  /// Relayed signatures act only on registered profiles and usable keys.
  function test_setTextSigned_validation () public {
    vm.expectRevert(
      abi.encodeWithSelector(Registry.UnknownProfile.selector, BOB)
    );
    registry.setTextSigned(BOB, "avatar", "a", "");
    _register(ALICE, aliceWallet);
    vm.expectRevert(abi.encodeWithSelector(Registry.InvalidKey.selector, ""));
    registry.setTextSigned(ALICE, "", "a", "");
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidKey.selector, "my avatar")
    );
    registry.setTextSigned(ALICE, "my avatar", "a", "");
  }

  /// The relayed-write digest is exactly the documented EIP-712 digest.
  function test_setTextDigest () public {
    _register(ALICE, aliceWallet);
    bytes32 _domainTypehash =
      keccak256(
        abi.encodePacked(
          "EIP712Domain(string name,string version,uint256 chainId,",
          "address verifyingContract)"
        )
      );
    bytes32 _domainSeparator =
      keccak256(
        abi.encode(
          _domainTypehash, keccak256(bytes("Registry")), keccak256(bytes("1")),
          block.chainid, address(registry)
        )
      );
    bytes32 _structHash =
      keccak256(
        abi.encode(
          registry.SET_TEXT_TYPEHASH(), ALICE, keccak256("avatar"),
          keccak256("a"), registry.nonces(ALICE)
        )
      );
    assertEq(
      registry.setTextDigest(ALICE, "avatar", "a"),
      keccak256(abi.encodePacked(hex"1901", _domainSeparator, _structHash))
    );
  }

  /**
    One relayed signature writes a batch in order, a later write to a key
    overriding an earlier one, and consumes one nonce.
  */
  function test_setTextsSigned () public {
    _register(BOB, bobWallet);
    string[] memory _keys = _list("avatar", "url");
    string[] memory _values = _list("a", "https://bob.example");
    vm.expectEmit(address(registry));
    emit Registry.TextChanged(BOB, "avatar", "avatar", "a");
    vm.expectEmit(address(registry));
    emit Registry.TextChanged(BOB, "url", "url", "https://bob.example");
    registry.setTextsSigned(
      BOB, _keys, _values, _signTexts(bobKey, BOB, _keys, _values)
    );
    assertEq(registry.text(BOB, "avatar"), "a");
    assertEq(registry.text(BOB, "url"), "https://bob.example");
    assertEq(registry.nonces(BOB), 1);

    // Clearing and overriding in one batch, at the next nonce.
    _keys = _list("url", "avatar", "url");
    _values = _list("x", "", "y");
    registry.setTextsSigned(
      BOB, _keys, _values, _signTexts(bobKey, BOB, _keys, _values)
    );
    assertEq(registry.text(BOB, "url"), "y", "the later write wins");
    assertEq(registry.text(BOB, "avatar"), "", "an empty value clears");
    assertEq(registry.nonces(BOB), 2);
  }

  /**
    A batch signature is single-use and bound to its signer, profile, keys,
    values, and their order; a single-record signature never passes for one.
  */
  function test_setTextsSigned_replayAndBinding () public {
    _register(ALICE, aliceWallet);
    _register(BOB, bobWallet);
    string[] memory _keys = _list("avatar", "url");
    string[] memory _values = _list("a", "b");
    bytes memory _sig = _signTexts(aliceKey, ALICE, _keys, _values);
    registry.setTextsSigned(ALICE, _keys, _values, _sig);

    // The consumed nonce retires the signature.
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextsSigned(ALICE, _keys, _values, _sig);

    /*
      A stranger's signature is refused, and a controller's signature for one
      profile says nothing about another.
    */
    bytes memory _strangerSig = _signTexts(bobKey, ALICE, _keys, _values);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextsSigned(ALICE, _keys, _values, _strangerSig);
    bytes memory _crossSig = _signTexts(bobKey, ALICE, _keys, _values);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextsSigned(BOB, _keys, _values, _crossSig);

    // A signature covers exactly its values, its keys, and their order.
    bytes memory _fresh = _signTexts(aliceKey, ALICE, _keys, _values);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextsSigned(ALICE, _keys, _list("a", "c"), _fresh);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextsSigned(
      ALICE, _list("url", "avatar"), _list("b", "a"), _fresh
    );

    // A single-record signature does not stand in for a batch of one.
    bytes memory _single = _signText(aliceKey, ALICE, "avatar", "a");
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextsSigned(ALICE, _list("avatar"), _list("a"), _single);
    registry.setTextsSigned(ALICE, _keys, _values, _fresh);
    assertEq(registry.nonces(ALICE), 2);
  }

  /// Batches act only on registered profiles, paired lists, and usable keys.
  function test_setTextsSigned_validation () public {
    vm.expectRevert(
      abi.encodeWithSelector(Registry.UnknownProfile.selector, BOB)
    );
    registry.setTextsSigned(BOB, _list("avatar"), _list("a"), "");
    _register(ALICE, aliceWallet);
    vm.expectRevert(Registry.LengthMismatch.selector);
    registry.setTextsSigned(ALICE, _list("avatar", "url"), _list("a"), "");
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidKey.selector, "my avatar")
    );
    registry.setTextsSigned(
      ALICE, _list("url", "my avatar"), _list("a", "b"), ""
    );
    vm.expectRevert(abi.encodeWithSelector(Registry.InvalidKey.selector, ""));
    registry.setTextsSigned(ALICE, _list(""), _list("a"), "");
  }

  /**
    An empty signed batch writes nothing and consumes the nonce, revoking every
    signed write handed out before it.
  */
  function test_setTextsSigned_emptyBatchRevokes () public {
    _register(ALICE, aliceWallet);
    bytes memory _pending = _signText(aliceKey, ALICE, "url", "x");
    bytes memory _pendingBatch =
      _signTexts(aliceKey, ALICE, _list("url"), _list("y"));
    registry.setTextsSigned(
      ALICE, _list(), _list(), _signTexts(aliceKey, ALICE, _list(), _list())
    );
    assertEq(registry.nonces(ALICE), 1);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextSigned(ALICE, "url", "x", _pending);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setTextsSigned(ALICE, _list("url"), _list("y"), _pendingBatch);
    assertEq(registry.text(ALICE, "url"), "");
  }

  /**
    The relayed-batch digest is exactly the documented EIP-712 digest, each list
    encoded as the hash of its elements' hashes.
  */
  function test_setTextsDigest () public {
    _register(ALICE, aliceWallet);
    assertEq(
      registry.SET_TEXTS_TYPEHASH(),
      keccak256(
        "SetTexts(bytes32 profileId,string[] keys,string[] values,uint256 nonce)"
      )
    );
    bytes32 _structHash =
      keccak256(
        abi.encode(
          registry.SET_TEXTS_TYPEHASH(), ALICE,
          keccak256(abi.encodePacked(keccak256("avatar"), keccak256("url"))),
          keccak256(abi.encodePacked(keccak256("a"), keccak256(""))),
          registry.nonces(ALICE)
        )
      );
    assertEq(
      registry.setTextsDigest(ALICE, _list("avatar", "url"), _list("a", "")),
      keccak256(abi.encodePacked(hex"1901", _domainSeparator(), _structHash))
    );

    // An empty list encodes as the hash of nothing.
    bytes32 _emptyHash =
      keccak256(
        abi.encode(
          registry.SET_TEXTS_TYPEHASH(), ALICE, keccak256(""), keccak256(""),
          registry.nonces(ALICE)
        )
      );
    assertEq(
      registry.setTextsDigest(ALICE, _list(), _list()),
      keccak256(abi.encodePacked(hex"1901", _domainSeparator(), _emptyHash))
    );
  }

  /**
    Only the controller writes batches by transaction, in order, consuming no
    nonce; a refused batch writes nothing.
  */
  function test_setTexts_controllerOnly () public {
    _register(ALICE, aliceWallet);
    vm.prank(aliceWallet);
    vm.expectEmit(address(registry));
    emit Registry.TextChanged(ALICE, "url", "url", "https://alice.example");
    vm.expectEmit(address(registry));
    emit Registry.TextChanged(ALICE, "com.github", "com.github", "alice");
    registry.setTexts(
      ALICE, _list("url", "com.github"), _list(
        "https://alice.example", "alice"
      )
    );
    assertEq(registry.text(ALICE, "url"), "https://alice.example");
    assertEq(registry.text(ALICE, "com.github"), "alice");
    assertEq(registry.nonces(ALICE), 0, "direct writes consume no nonce");

    // Strangers and management have no editing power.
    vm.prank(bobWallet);
    vm.expectRevert(Registry.NotController.selector);
    registry.setTexts(ALICE, _list("url"), _list("x"));
    vm.prank(management);
    vm.expectRevert(Registry.NotController.selector);
    registry.setTexts(ALICE, _list("url"), _list("x"));

    // Unknown profiles, uneven lists, and bad keys are rejected whole.
    vm.prank(aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.UnknownProfile.selector, BOB)
    );
    registry.setTexts(BOB, _list("url"), _list("x"));
    vm.prank(aliceWallet);
    vm.expectRevert(Registry.LengthMismatch.selector);
    registry.setTexts(ALICE, _list("url"), _list("x", "y"));
    vm.prank(aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidKey.selector, "com github")
    );
    registry.setTexts(ALICE, _list("url", "com github"), _list("x", "y"));
    assertEq(registry.text(ALICE, "url"), "https://alice.example");

    // Clearing and overriding, in order.
    vm.prank(aliceWallet);
    registry.setTexts(
      ALICE, _list("com.github", "url", "url"), _list("", "x", "y")
    );
    assertEq(registry.text(ALICE, "com.github"), "");
    assertEq(registry.text(ALICE, "url"), "y");
  }

  /// Only the controller edits records by transaction; empty values clear.
  function test_setText_controllerOnly () public {
    _register(ALICE, aliceWallet);
    vm.prank(aliceWallet);
    vm.expectEmit(address(registry));
    emit Registry.TextChanged(ALICE, "com.github", "com.github", "alice");
    registry.setText(ALICE, "com.github", "alice");
    assertEq(registry.text(ALICE, "com.github"), "alice");
    vm.prank(bobWallet);
    vm.expectRevert(Registry.NotController.selector);
    registry.setText(ALICE, "com.github", "bob");

    // Management has no editing power whatsoever.
    vm.prank(management);
    vm.expectRevert(Registry.NotController.selector);
    registry.setText(ALICE, "com.github", "mgmt");

    // Unknown profiles and bad keys are rejected.
    vm.prank(aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.UnknownProfile.selector, BOB)
    );
    registry.setText(BOB, "com.github", "alice");
    vm.prank(aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidKey.selector, "com github")
    );
    registry.setText(ALICE, "com github", "alice");

    // An empty value clears.
    vm.prank(aliceWallet);
    registry.setText(ALICE, "com.github", "");
    assertEq(registry.text(ALICE, "com.github"), "");
  }

  /// An inactive profile is read-only for its controller too.
  function test_setText_inactiveIsReadOnly () public {
    _register(ALICE, aliceWallet);
    vm.prank(aliceWallet);
    registry.setText(ALICE, "url", "https://alice.example");
    vm.prank(management);
    registry.setActive(ALICE, false);
    vm.prank(aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InactiveProfile.selector, ALICE)
    );
    registry.setText(ALICE, "url", "https://elsewhere.example");
    vm.prank(aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InactiveProfile.selector, ALICE)
    );
    registry.setTexts(ALICE, _list("url"), _list("https://elsewhere.example"));
    bytes memory _batchSig =
      _signTexts(aliceKey, ALICE, _list("url"), _list("x"));
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InactiveProfile.selector, ALICE)
    );
    registry.setTextsSigned(ALICE, _list("url"), _list("x"), _batchSig);

    // The records stay exactly where they were.
    assertEq(registry.text(ALICE, "url"), "https://alice.example");
    assertEq(_controllerOf(ALICE), aliceWallet);
    vm.prank(management);
    registry.setActive(ALICE, true);
    vm.prank(aliceWallet);
    registry.setText(ALICE, "url", "https://elsewhere.example");
    assertEq(registry.text(ALICE, "url"), "https://elsewhere.example");
  }

  /// Only management flags profiles, and only profiles that exist.
  function test_setActive_managementControlsStandingProfiles () public {
    _register(ALICE, aliceWallet);

    // Before the lapse, nobody but management moves the flag, either way.
    vm.prank(aliceWallet);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.setActive(ALICE, false);
    vm.prank(relayer);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.setActive(ALICE, true);
    vm.warp(block.timestamp + 90 days - 1);
    vm.prank(relayer);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.setActive(ALICE, false);
    vm.prank(relayer);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.UnknownProfile.selector, BOB)
    );
    registry.setActive(BOB, false);
    vm.prank(management);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.UnknownProfile.selector, BOB)
    );
    registry.setActive(BOB, false);
    vm.prank(management);
    vm.expectEmit(address(registry));
    emit Registry.ActiveSet(ALICE, false);
    registry.setActive(ALICE, false);
    (, bool _active, , ) = _profile(ALICE);
    assertFalse(_active);
    vm.prank(management);
    registry.setActive(ALICE, true);
    (, _active, , ) = _profile(ALICE);
    assertTrue(_active);
  }

  /// Management moves only via the two-step handover.
  function test_management_twoStep () public {
    address _next = makeAddr("nextManagement");
    vm.prank(aliceWallet);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.transferManagement(_next);
    vm.prank(management);
    registry.transferManagement(_next);

    // Still the old management until accepted.
    assertEq(registry.management(), management);
    assertEq(registry.pendingManagement(), _next);
    vm.prank(aliceWallet);
    vm.expectRevert(Registry.NotPendingManagement.selector);
    registry.acceptManagement();
    vm.prank(_next);
    registry.acceptManagement();
    assertEq(registry.management(), _next);
    assertEq(registry.pendingManagement(), address(0));

    // The old management has lost control; the new one has it.
    _register(ALICE, aliceWallet);
    vm.prank(management);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.setActive(ALICE, false);
    vm.prank(_next);
    registry.setActive(ALICE, false);

    // A pending handover may be canceled with the zero address.
    vm.prank(_next);
    registry.transferManagement(management);
    vm.prank(_next);
    registry.transferManagement(address(0));
    vm.prank(management);
    vm.expectRevert(Registry.NotPendingManagement.selector);
    registry.acceptManagement();
  }

  /**
    A profile lapses `RENEWAL_PERIOD` after its latest email, goes read-only,
    and comes back with a fresh email.
  */
  function test_profile_lapsesAndRenews () public {
    uint256 _t = block.timestamp;
    _register(ALICE, aliceWallet);
    assertTrue(registry.isActive(ALICE));
    assertEq(registry.expiresAt(ALICE), _t + 90 days);
    assertEq(registry.expiresAt(BOB), 0, "unregistered");
    assertFalse(registry.isActive(BOB));

    // One second before the lapse, records still move.
    vm.warp(_t + 90 days - 1);
    vm.prank(aliceWallet);
    registry.setText(ALICE, "url", "https://alice.example");

    // At the lapse, both record paths freeze.
    vm.warp(_t + 90 days);
    assertFalse(registry.isActive(ALICE));
    vm.prank(aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.LapsedProfile.selector, ALICE)
    );
    registry.setText(ALICE, "url", "https://elsewhere.example");
    bytes memory _textSig = _signText(aliceKey, ALICE, "url", "x");
    vm.expectRevert(
      abi.encodeWithSelector(Registry.LapsedProfile.selector, ALICE)
    );
    registry.setTextSigned(ALICE, "url", "x", _textSig);
    vm.prank(aliceWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.LapsedProfile.selector, ALICE)
    );
    registry.setTexts(ALICE, _list("url"), _list("x"));
    bytes memory _batchSig =
      _signTexts(aliceKey, ALICE, _list("url"), _list("x"));
    vm.expectRevert(
      abi.encodeWithSelector(Registry.LapsedProfile.selector, ALICE)
    );
    registry.setTextsSigned(ALICE, _list("url"), _list("x"), _batchSig);
    assertEq(registry.text(ALICE, "url"), "https://alice.example", "kept");

    // A fresh email authorizing the same controller renews it.
    EmailProof memory _p = _email(ALICE, aliceWallet);
    registry.setController(_p, aliceWallet, _sign(aliceKey, _p.emailNullifier));
    assertTrue(registry.isActive(ALICE));
    assertEq(registry.expiresAt(ALICE), block.timestamp + 90 days);
    assertEq(_controllerOf(ALICE), aliceWallet);
    vm.prank(aliceWallet);
    registry.setText(ALICE, "url", "https://elsewhere.example");
  }

  /// An email is usable for `EMAIL_LIFETIME` after its timestamp, and no more.
  function test_email_expiresAfterLifetime () public {
    uint256 _t = block.timestamp;
    EmailProof memory _p = _proof(ALICE, aliceWallet, _t - 5 weeks - 1);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.ExpiredEmail.selector, _t - 5 weeks - 1)
    );
    registry.register(_p, aliceWallet);
    _p = _proof(ALICE, aliceWallet, _t - 5 weeks);
    registry.register(_p, aliceWallet);
    assertEq(registry.expiresAt(ALICE), _t - 5 weeks + 90 days);

    // An old email cannot renew either.
    EmailProof memory _q = _proof(ALICE, aliceWallet, _t - 5 weeks);
    vm.warp(_t + 1);
    bytes memory _sig = _sign(aliceKey, _q.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.ExpiredEmail.selector, _t - 5 weeks)
    );
    registry.setController(_q, aliceWallet, _sig);
  }

  /**
    Once a profile lapses, anyone may flag it inactive, and nobody but
    management may restore it. Flagged, it can no longer renew; restored, it
    renews again with a fresh email.
  */
  function test_setActive_anyoneMayRetireALapsedProfile () public {
    uint256 _t = block.timestamp;
    _register(ALICE, aliceWallet);
    vm.warp(_t + 90 days);
    assertFalse(registry.isActive(ALICE), "lapsed");

    // Anyone may retire it; nobody but management may bring it back.
    vm.prank(relayer);
    vm.expectEmit(address(registry));
    emit Registry.ActiveSet(ALICE, false);
    registry.setActive(ALICE, false);
    (, bool _active, , ) = _profile(ALICE);
    assertFalse(_active);
    vm.prank(relayer);
    registry.setActive(ALICE, false);
    vm.prank(aliceWallet);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.setActive(ALICE, true);

    // Retired, it cannot renew, even with a fresh email and its controller.
    EmailProof memory _p = _email(ALICE, aliceWallet);
    bytes memory _sig = _sign(aliceKey, _p.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InactiveProfile.selector, ALICE)
    );
    registry.setController(_p, aliceWallet, _sig);

    // Restored by management, it renews.
    vm.prank(management);
    registry.setActive(ALICE, true);
    assertFalse(registry.isActive(ALICE), "still lapsed until renewed");
    registry.setController(_p, aliceWallet, _sig);
    assertTrue(registry.isActive(ALICE));
    assertEq(registry.expiresAt(ALICE), block.timestamp + 90 days);

    // Renewed, it stands again, and is management's alone to flag.
    vm.prank(relayer);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.setActive(ALICE, false);
  }

  /**
    A profile flagged inactive cannot renew, even once lapsed, and restoring it
    does not extend its expiry.
  */
  function test_inactiveProfile_cannotRenew () public {
    uint256 _t = block.timestamp;
    _register(ALICE, aliceWallet);
    vm.prank(management);
    registry.setActive(ALICE, false);
    assertFalse(registry.isActive(ALICE));
    EmailProof memory _p = _email(ALICE, aliceWallet);
    bytes memory _sig = _sign(aliceKey, _p.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InactiveProfile.selector, ALICE)
    );
    registry.setController(_p, aliceWallet, _sig);

    // Restored after its lapse, it stays lapsed until a fresh email.
    vm.warp(_t + 90 days);
    vm.prank(management);
    registry.setActive(ALICE, true);
    assertFalse(registry.isActive(ALICE));
    assertEq(registry.expiresAt(ALICE), _t + 90 days);
  }

  /**
    Whatever the time, a stranger may flag a profile inactive exactly when it
    has lapsed, and may never flag it active.

    @param _elapsed The fuzzed time since registration.
    @param _stranger The fuzzed caller.
  */
  function testFuzz_setActive_strangerOnlyRetiresLapsed (
    uint256 _elapsed,
    address _stranger
  ) public {
    vm.assume(_stranger != management);
    _elapsed = bound(_elapsed, 0, 365 days);
    uint256 _t = block.timestamp;
    _register(ALICE, aliceWallet);
    vm.warp(_t + _elapsed);
    vm.prank(_stranger);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.setActive(ALICE, true);
    if (_elapsed < 90 days) {
      vm.prank(_stranger);
      vm.expectRevert(Registry.NotManagement.selector);
      registry.setActive(ALICE, false);
      assertTrue(registry.isActive(ALICE));
      return;
    }
    vm.prank(_stranger);
    registry.setActive(ALICE, false);
    (, bool _active, , ) = _profile(ALICE);
    assertFalse(_active);
  }

  /// Profiles enumerate in registration order, once each.
  function test_profileEnumeration () public {
    _register(ALICE, aliceWallet);
    _register(BOB, bobWallet);
    _register(CAROL, bobWallet);
    EmailProof memory _p = _email(ALICE, bobWallet);
    registry.setController(_p, bobWallet, _sign(aliceKey, _p.emailNullifier));
    assertEq(registry.profileCount(), 3);
    assertEq(registry.profileIds(0), ALICE);
    assertEq(registry.profileIds(1), BOB);
    assertEq(registry.profileIds(2), CAROL);
  }

  /**
    Any nonzero address at all can be bound as a controller, and can then edit
    records directly.

    @param _wallet The fuzzed controller.
  */
  function testFuzz_register_anyController (
    address _wallet
  ) public {
    vm.assume(_wallet != address(0));
    _register(ALICE, _wallet);
    assertEq(_controllerOf(ALICE), _wallet);
    vm.prank(_wallet);
    registry.setText(ALICE, "url", "https://x.example");
    assertEq(registry.text(ALICE, "url"), "https://x.example");
  }

  /**
    Whatever the identity, key, and value, a relayed signed record write reads
    back exactly, and clears by the controller exactly.

    @param _sender The fuzzed identity.
    @param _keySeed The fuzzed seed of the record key.
    @param _value The fuzzed record value.
  */
  function testFuzz_textRoundTrip (
    bytes32 _sender,
    bytes32 _keySeed,
    string memory _value
  ) public {
    _register(_sender, aliceWallet);

    // A hex key never contains a space.
    string memory _key = uint256(_keySeed).toHexString();
    registry.setTextSigned(
      _sender, _key, _value, _signText(aliceKey, _sender, _key, _value)
    );
    assertEq(registry.text(_sender, _key), _value);
    assertEq(registry.nonces(_sender), 1);
    vm.prank(aliceWallet);
    registry.setText(_sender, _key, "");
    assertEq(registry.text(_sender, _key), "");
    assertEq(registry.profileCount(), 1);
  }

  /**
    Whatever the nullifier, an email spends it once.

    @param _nullifier The fuzzed nullifier.
  */
  function testFuzz_nullifierIsSingleUse (
    bytes32 _nullifier
  ) public {
    EmailProof memory _p = _email(ALICE, aliceWallet);
    _p.emailNullifier = _nullifier;
    registry.register(_p, aliceWallet);
    assertTrue(registry.usedNullifiers(_nullifier));
    EmailProof memory _q = _email(ALICE, bobWallet);
    _q.emailNullifier = _nullifier;
    bytes memory _sig = _sign(aliceKey, _nullifier);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.EmailAlreadyUsed.selector, _nullifier)
    );
    registry.setController(_q, bobWallet, _sig);
  }

  /**
    A controller signature authorizes exactly one email: any other nullifier's
    digest is a different message.

    @param _other The fuzzed foreign nullifier.
  */
  function testFuzz_signatureBindsToEmail (
    bytes32 _other
  ) public {
    _register(ALICE, aliceWallet);
    EmailProof memory _p = _email(ALICE, bobWallet);
    vm.assume(_other != _p.emailNullifier);
    bytes memory _sig = _sign(aliceKey, _other);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setController(_p, bobWallet, _sig);
  }

  /**
    Whatever two usable DKIM timestamps an identity's emails carry, the second
    is honored exactly when it does not precede the first.

    @param _t1 The fuzzed timestamp of the first email.
    @param _t2 The fuzzed timestamp of the second email.
  */
  function testFuzz_timestampsNeverRunBackwards (
    uint256 _t1,
    uint256 _t2
  ) public {
    _t1 = bound(_t1, block.timestamp - 5 weeks, block.timestamp);
    _t2 = bound(_t2, block.timestamp - 5 weeks, block.timestamp);
    registry.register(_proof(ALICE, aliceWallet, _t1), aliceWallet);
    EmailProof memory _p = _proof(ALICE, bobWallet, _t2);
    bytes memory _sig = _sign(aliceKey, _p.emailNullifier);
    if (_t2 < _t1) {
      vm.expectRevert(
        abi.encodeWithSelector(Registry.StaleEmail.selector, _t2, _t1)
      );
      registry.setController(_p, bobWallet, _sig);
      assertEq(_lastTimestamp(ALICE), _t1);
      return;
    }
    registry.setController(_p, bobWallet, _sig);
    assertEq(_lastTimestamp(ALICE), _t2);
  }
}

