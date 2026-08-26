// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
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
  exactly the proofs a test marks valid, so every policy check the registry
  performs itself (domain, key hashes, nullifier, timestamp, command, binding,
  account code, controller signature, nonce, active flag) is exercised in
  isolation from the circuit.

  @custom:date August 25th, 2026.
*/
contract RegistryTest is
  Test {

  using LibString for address;

  using LibString for uint256;

  /// The pinned email domain.
  string internal constant DOMAIN = "ethereum.org";

  /// A DKIM key hash management honors for the domain.
  bytes32 internal constant KEY_HASH = keccak256("ethereum.org dkim key");

  /// Alice's identity: her account salt.
  bytes32 internal constant ALICE = keccak256("alice@ethereum.org|code");

  /// Bob's identity: his account salt.
  bytes32 internal constant BOB = keccak256("bob@ethereum.org|code");

  /// Carol's identity: her account salt.
  bytes32 internal constant CAROL = keccak256("carol@ethereum.org|code");

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
    Build an email proof the mock verifier accepts, with a fresh nullifier.

    @param _salt The sender's account salt.
    @param _command The command the email carries.
    @param _timestamp The DKIM timestamp of the email.
    @param _code Whether the email carries the account code.

    @return _ The email proof.
  */
  function _proof (
    bytes32 _salt,
    string memory _command,
    uint256 _timestamp,
    bool _code
  ) internal returns (EmailProof memory) {
    return EmailProof({
      domainName: DOMAIN,
      publicKeyHash: KEY_HASH,
      timestamp: _timestamp,
      maskedCommand: _command,
      emailNullifier: keccak256(abi.encode("email", ++emailsSent)),
      accountSalt: _salt,
      isCodeExist: _code,
      proof: "valid"
    });
  }

  /**
    Build a first email from an identity: current, carrying the account code.

    @param _salt The sender's account salt.
    @param _command The command the email carries.

    @return _ The email proof.
  */
  function _firstEmail (
    bytes32 _salt,
    string memory _command
  ) internal returns (EmailProof memory) {
    return _proof(_salt, _command, block.timestamp, true);
  }

  /**
    Build a later email from an identity: current, without the account code.

    @param _salt The sender's account salt.
    @param _command The command the email carries.

    @return _ The email proof.
  */
  function _email (
    bytes32 _salt,
    string memory _command
  ) internal returns (EmailProof memory) {
    return _proof(_salt, _command, block.timestamp, false);
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
    Build the binding tag of the registry under test, independently of the
    registry's own rendering.

    @return _ The binding tag.
  */
  function _binding () internal view returns (string memory) {
    return string.concat(
      block.chainid.toString(), ":", address(registry).toHexStringChecksummed()
    );
  }

  /**
    Build the controller command exactly as an EFer's frontend would.

    @param _controller The controller to name.

    @return _ The command.
  */
  function _setControllerCommand (
    address _controller
  ) internal view returns (string memory) {
    return string.concat(
      "Set controller to ", _controller.toHexStringChecksummed(), " ",
      _binding()
    );
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
    Register a profile by email, binding a controller.

    @param _salt The sender's account salt.
    @param _controller The controller to bind.
  */
  function _register (
    bytes32 _salt,
    address _controller
  ) internal {
    registry.register(
      _firstEmail(_salt, _setControllerCommand(_controller)), _controller
    );
  }

  /**
    Retrieve a profile.

    @param _salt The profile ID.

    @return _ The profile's controller, active flag, registration time, and last
      honored DKIM timestamp.
  */
  function _profile (
    bytes32 _salt
  ) internal view returns (address, bool, uint256, uint256) {
    return registry.profiles(_salt);
  }

  /**
    Retrieve a profile's controller.

    @param _salt The profile ID.

    @return _ The profile's controller.
  */
  function _controllerOf (
    bytes32 _salt
  ) internal view returns (address) {
    (address _c, , , ) = registry.profiles(_salt);
    return _c;
  }

  /**
    Retrieve a profile's last honored DKIM timestamp.

    @param _salt The profile ID.

    @return _ The profile's last honored DKIM timestamp.
  */
  function _lastTimestamp (
    bytes32 _salt
  ) internal view returns (uint256) {
    (, , , uint256 _t) = registry.profiles(_salt);
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
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(aliceWallet));
    vm.expectEmit(address(registry));
    emit Registry.EmailAuthorized(
      ALICE, _p.emailNullifier, block.timestamp, _p.maskedCommand
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
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(aliceWallet));
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
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(address(0)));
    vm.expectRevert(Registry.ZeroAddress.selector);
    registry.register(_p, address(0));
  }

  /// An identity registers exactly once.
  function test_register_once () public {
    _register(ALICE, aliceWallet);
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(bobWallet));
    vm.expectRevert(
      abi.encodeWithSelector(Registry.AlreadyRegistered.selector, ALICE)
    );
    registry.register(_p, bobWallet);
    assertEq(_controllerOf(ALICE), aliceWallet, "controller unmoved");
  }

  /**
    The registering email must carry the account code; later emails need only
    the controller's signature.
  */
  function test_register_requiresAccountCode () public {
    EmailProof memory _p = _email(ALICE, _setControllerCommand(aliceWallet));
    vm.expectRevert(Registry.MissingAccountCode.selector);
    registry.register(_p, aliceWallet);
    assertEq(registry.profileCount(), 0);
    _register(ALICE, aliceWallet);
    EmailProof memory _q = _email(ALICE, _setControllerCommand(bobWallet));
    registry.setController(_q, bobWallet, _sign(aliceKey, _q.emailNullifier));
    assertEq(_controllerOf(ALICE), bobWallet);
  }

  /// A registration email whose signature carries no timestamp records none.
  function test_register_zeroTimestamp () public {
    registry.register(
      _proof(ALICE, _setControllerCommand(aliceWallet), 0, true), aliceWallet
    );
    assertEq(_lastTimestamp(ALICE), 0);
    assertEq(_controllerOf(ALICE), aliceWallet);
  }

  /// The controller address is accepted checksummed, lowercase, or uppercase.
  function test_register_acceptsAnyAddressCasing () public {
    _register(ALICE, aliceWallet);
    string memory _lower =
      string.concat(
        "Set controller to ", bobWallet.toHexString(), " ", _binding()
      );
    registry.register(_firstEmail(BOB, _lower), bobWallet);
    assertEq(_controllerOf(BOB), bobWallet);
    string memory _upper =
      string.concat(
        "Set controller to 0x",
        LibString.upper(bobWallet.toHexStringNoPrefix()), " ", _binding()
      );
    registry.register(_firstEmail(CAROL, _upper), bobWallet);
    assertEq(_controllerOf(CAROL), bobWallet);

    // An uppercase `0X` prefix is not one of the three forms.
    string memory _bad =
      string.concat(
        "Set controller to ", LibString.upper(bobWallet.toHexString()), " ",
        _binding()
      );
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidCommand.selector, _bad)
    );
    registry.register(_firstEmail(BOB, _bad), bobWallet);
  }

  /// The call must claim exactly what the email says.
  function test_register_revertsOnWrongCommand () public {

    // The email names bob's wallet; the call claims alice's.
    string memory _cmd = _setControllerCommand(bobWallet);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidCommand.selector, _cmd)
    );
    registry.register(_firstEmail(ALICE, _cmd), aliceWallet);

    // Not a controller command at all.
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidCommand.selector, "hello")
    );
    registry.register(_firstEmail(ALICE, "hello"), aliceWallet);

    // Trailing garbage after a perfect command is still a different command.
    string memory _trailing =
      string.concat(_setControllerCommand(aliceWallet), " x");
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidCommand.selector, _trailing)
    );
    registry.register(_firstEmail(ALICE, _trailing), aliceWallet);
    assertEq(registry.profileCount(), 0, "nothing registered");
  }

  /// Rotation needs email and the current controller's signature together.
  function test_setController_requiresControllerSignature () public {
    _register(ALICE, aliceWallet);
    EmailProof memory _p = _email(ALICE, _setControllerCommand(bobWallet));

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
    _p = _email(ALICE, _setControllerCommand(aliceWallet));
    bytes memory _staleSig = _sign(aliceKey, _p.emailNullifier);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setController(_p, aliceWallet, _staleSig);
    registry.setController(_p, aliceWallet, _sign(bobKey, _p.emailNullifier));
    assertEq(_controllerOf(ALICE), aliceWallet);
    assertEq(registry.profileCount(), 1, "no re-registration");
  }

  /// Rotation matches the command exactly, just as registration does.
  function test_setController_revertsOnWrongCommand () public {
    _register(ALICE, aliceWallet);

    // The email names bob's wallet; the call claims alice's.
    string memory _cmd = _setControllerCommand(bobWallet);
    EmailProof memory _p = _email(ALICE, _cmd);
    bytes memory _sig = _sign(aliceKey, _p.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidCommand.selector, _cmd)
    );
    registry.setController(_p, aliceWallet, _sig);
    assertEq(_controllerOf(ALICE), aliceWallet, "controller unmoved");
  }

  /// Rotation never unbinds: the two-of-two is permanent.
  function test_setController_rejectsZero () public {
    _register(ALICE, aliceWallet);
    EmailProof memory _p = _email(ALICE, _setControllerCommand(address(0)));
    bytes memory _sig = _sign(aliceKey, _p.emailNullifier);
    vm.expectRevert(Registry.ZeroAddress.selector);
    registry.setController(_p, address(0), _sig);
  }

  /// Rotation acts only on registered profiles; nothing auto-registers.
  function test_setController_requiresRegistration () public {
    EmailProof memory _p = _firstEmail(BOB, _setControllerCommand(bobWallet));
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
    EmailProof memory _p = _email(ALICE, _setControllerCommand(bobWallet));
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
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(aliceWallet));
    _p.domainName = "ethereum.com";
    vm.expectRevert(
      abi.encodeWithSelector(Registry.WrongDomain.selector, "ethereum.com")
    );
    registry.register(_p, aliceWallet);
  }

  /// Emails signed with a key management does not honor are rejected.
  function test_email_revertsOnUnknownDKIMKey () public {
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(aliceWallet));
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
    _p = _firstEmail(ALICE, _setControllerCommand(aliceWallet));
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
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(aliceWallet));
    vm.expectRevert(
      abi.encodeWithSelector(
        Registry.InvalidDKIMPublicKeyHash.selector, KEY_HASH
      )
    );
    registry.register(_p, aliceWallet);
    _p = _firstEmail(ALICE, _setControllerCommand(aliceWallet));
    _p.publicKeyHash = _newKey;
    registry.register(_p, aliceWallet);
    assertEq(_controllerOf(ALICE), aliceWallet);
  }

  /// Every email is single-use, whatever it is resubmitted as.
  function test_email_isSingleUse () public {
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(aliceWallet));
    registry.register(_p, aliceWallet);

    // The registration email cannot register anyone else.
    EmailProof memory _r = _firstEmail(BOB, _setControllerCommand(bobWallet));
    _r.emailNullifier = _p.emailNullifier;
    vm.expectRevert(
      abi.encodeWithSelector(
        Registry.EmailAlreadyUsed.selector, _p.emailNullifier
      )
    );
    registry.register(_r, bobWallet);

    // Nor can it be re-spent as an authorized rotation.
    EmailProof memory _q = _email(ALICE, _setControllerCommand(bobWallet));
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
    EmailProof memory _old =
      _proof(ALICE, _setControllerCommand(bobWallet), _now - 100, false);
    bytes memory _oldSig = _sign(aliceKey, _old.emailNullifier);
    vm.expectRevert(
      abi.encodeWithSelector(Registry.StaleEmail.selector, _now - 100, _now)
    );
    registry.setController(_old, bobWallet, _oldSig);

    // The same second is fine.
    EmailProof memory _same =
      _proof(ALICE, _setControllerCommand(bobWallet), _now, false);
    registry.setController(
      _same, bobWallet, _sign(aliceKey, _same.emailNullifier)
    );
    assertEq(_lastTimestamp(ALICE), _now);

    // A signature without a timestamp skips the check and moves nothing.
    EmailProof memory _zero =
      _proof(ALICE, _setControllerCommand(aliceWallet), 0, false);
    registry.setController(
      _zero, aliceWallet, _sign(bobKey, _zero.emailNullifier)
    );
    assertEq(_lastTimestamp(ALICE), _now, "zero timestamps leave no trace");

    // A later email advances the clock.
    EmailProof memory _later =
      _proof(ALICE, _setControllerCommand(bobWallet), _now + 5, false);
    registry.setController(
      _later, bobWallet, _sign(aliceKey, _later.emailNullifier)
    );
    assertEq(_lastTimestamp(ALICE), _now + 5);
    assertEq(_controllerOf(ALICE), bobWallet);
  }

  /// A proof the verifier rejects does nothing, and spends nothing.
  function test_email_revertsOnInvalidProof () public {
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(aliceWallet));
    _p.proof = "forged";
    vm.expectRevert(Registry.InvalidEmailProof.selector);
    registry.register(_p, aliceWallet);
    assertFalse(registry.usedNullifiers(_p.emailNullifier));
    assertEq(registry.profileCount(), 0);

    // A forged rotation is rejected the same way, spending nothing.
    _register(ALICE, aliceWallet);
    EmailProof memory _q = _email(ALICE, _setControllerCommand(bobWallet));
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
    EmailProof memory _p = _email(ALICE, _setControllerCommand(bobWallet));
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

    // Reactivation restores email control, including the rejected command.
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
  function test_setActive_onlyManagement () public {
    _register(ALICE, aliceWallet);
    vm.prank(aliceWallet);
    vm.expectRevert(Registry.NotManagement.selector);
    registry.setActive(ALICE, false);
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

  /// The command helpers render exactly what an email must say.
  function test_commandHelpers () public view {
    assertEq(
      registry.commandBinding(),
      string.concat("31337:", address(registry).toHexStringChecksummed())
    );
    assertEq(
      registry.setControllerCommand(aliceWallet),
      _setControllerCommand(aliceWallet)
    );
  }

  /// A command bound to any other deployment is rejected.
  function test_commandBinding_rejectsForeignBindings () public {
    string memory _action =
      string.concat("Set controller to ", aliceWallet.toHexStringChecksummed());

    // No binding at all.
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidCommand.selector, _action)
    );
    registry.register(_firstEmail(ALICE, _action), aliceWallet);

    // The right registry on the wrong chain.
    string memory _wrongChain =
      string.concat(
        _action, " 999:", address(registry).toHexStringChecksummed()
      );
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidCommand.selector, _wrongChain)
    );
    registry.register(_firstEmail(ALICE, _wrongChain), aliceWallet);

    // The right chain on the wrong registry.
    string memory _wrongRegistry =
      string.concat(_action, " 31337:", bobWallet.toHexStringChecksummed());
    vm.expectRevert(
      abi.encodeWithSelector(Registry.InvalidCommand.selector, _wrongRegistry)
    );
    registry.register(_firstEmail(ALICE, _wrongRegistry), aliceWallet);
    assertEq(registry.profileCount(), 0, "nothing registered");
  }

  /// Profiles enumerate in registration order, once each.
  function test_profileEnumeration () public {
    _register(ALICE, aliceWallet);
    _register(BOB, bobWallet);
    _register(CAROL, bobWallet);
    EmailProof memory _p = _email(ALICE, _setControllerCommand(bobWallet));
    registry.setController(_p, bobWallet, _sign(aliceKey, _p.emailNullifier));
    assertEq(registry.profileCount(), 3);
    assertEq(registry.profileIds(0), ALICE);
    assertEq(registry.profileIds(1), BOB);
    assertEq(registry.profileIds(2), CAROL);
  }

  /**
    Any nonzero address at all can be bound as a controller through the
    checksummed command, and can then edit records directly.

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

    @param _salt The fuzzed identity.
    @param _keySeed The fuzzed seed of the record key.
    @param _value The fuzzed record value.
  */
  function testFuzz_textRoundTrip (
    bytes32 _salt,
    bytes32 _keySeed,
    string memory _value
  ) public {
    _register(_salt, aliceWallet);

    // A hex key never contains a space.
    string memory _key = uint256(_keySeed).toHexString();
    registry.setTextSigned(
      _salt, _key, _value, _signText(aliceKey, _salt, _key, _value)
    );
    assertEq(registry.text(_salt, _key), _value);
    assertEq(registry.nonces(_salt), 1);
    vm.prank(aliceWallet);
    registry.setText(_salt, _key, "");
    assertEq(registry.text(_salt, _key), "");
    assertEq(registry.profileCount(), 1);
  }

  /**
    Whatever the nullifier, an email spends it once.

    @param _nullifier The fuzzed nullifier.
  */
  function testFuzz_nullifierIsSingleUse (
    bytes32 _nullifier
  ) public {
    EmailProof memory _p =
      _firstEmail(ALICE, _setControllerCommand(aliceWallet));
    _p.emailNullifier = _nullifier;
    registry.register(_p, aliceWallet);
    assertTrue(registry.usedNullifiers(_nullifier));
    EmailProof memory _q = _email(ALICE, _setControllerCommand(bobWallet));
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
    EmailProof memory _p = _email(ALICE, _setControllerCommand(bobWallet));
    vm.assume(_other != _p.emailNullifier);
    bytes memory _sig = _sign(aliceKey, _other);
    vm.expectRevert(Registry.InvalidControllerSignature.selector);
    registry.setController(_p, bobWallet, _sig);
  }

  /**
    Whatever two DKIM timestamps an identity's emails carry, the second is
    honored exactly when it does not precede the first (or carries none).

    @param _t1 The fuzzed timestamp of the first email.
    @param _t2 The fuzzed timestamp of the second email.
  */
  function testFuzz_timestampsNeverRunBackwards (
    uint64 _t1,
    uint64 _t2
  ) public {
    vm.assume(_t1 != 0);
    registry.register(
      _proof(ALICE, _setControllerCommand(aliceWallet), _t1, true), aliceWallet
    );
    EmailProof memory _p =
      _proof(ALICE, _setControllerCommand(bobWallet), _t2, false);
    bytes memory _sig = _sign(aliceKey, _p.emailNullifier);
    if (_t2 != 0 && _t2 < _t1) {
      vm.expectRevert(
        abi.encodeWithSelector(Registry.StaleEmail.selector, _t2, _t1)
      );
      registry.setController(_p, bobWallet, _sig);
      assertEq(_lastTimestamp(ALICE), _t1);
      return;
    }
    registry.setController(_p, bobWallet, _sig);
    assertEq(_lastTimestamp(ALICE), _t2 == 0 ? _t1 : _t2);
  }
}

