// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { EmailProof } from "../src/interfaces/IVerifier.sol";
import { Registry } from "../src/Registry.sol";
import { MockVerifier } from "./mocks/MockVerifier.sol";
import { Test } from "forge-std/Test.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RegistryInvariantTest
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The Registry invariant campaign: it deploys the mock verifier, the
  registry, a cast
  of identities, controllers, managements, keys, and values, and the handler,
  then declares the laws that must hold in every reachable state: the profile
  list is exactly the set of registered identities, once each and never
  shrinking; every email the handler sent is spent; no profile's clock runs
  ahead of the emails it has seen; management is always who the handover made
  it; every registered profile always has a nonzero controller; each
  profile's nonce counts exactly its relayed signed writes; and an inactive
  profile's records and controller are frozen where the flag found them.

  @custom:date August 21st, 2026.
*/
contract RegistryInvariantTest is
  Test {

  /// A DKIM key hash management honors for the domain.
  bytes32 internal constant KEY_HASH = keccak256("ethereum.org dkim key");

  /// The mock proof verifier.
  MockVerifier internal verifier;

  /// The registry under test.
  Registry internal registry;

  /// The choreographer the fuzzer drives.
  RegistryHandler internal handler;

  /// The initial management.
  address internal management = makeAddr("management");

  /// Deploy the mock verifier, the registry, and the handler.
  function setUp () public {
    verifier = new MockVerifier();
    registry = new Registry(address(verifier), "ethereum.org", management);
    vm.prank(management);
    registry.setDKIMPublicKeyHash(KEY_HASH, true);
    handler = new RegistryHandler(registry, management, KEY_HASH);
    targetContract(address(handler));
  }

  /// The profile list counts exactly the identities the handler registered.
  function invariant_profileCount () public view {
    assertEq(
      registry.profileCount(), handler.ghostRegisteredCount(),
      "profile count diverged"
    );
  }

  /// Every listed profile is registered, known to the handler, and unique.
  function invariant_profileIdsUniqueAndRegistered () public view {
    uint256 _count = registry.profileCount();
    for (uint256 i = 0; i < _count; ++i) {
      bytes32 _id = registry.profileIds(i);
      (, , uint256 _registeredAt, ) = registry.profiles(_id);
      assertGt(_registeredAt, 0, "a listed profile is not registered");
      assertTrue(handler.ghostRegistered(_id), "a listed profile is unknown");
      for (uint256 j = 0; j < i; ++j) {
        assertTrue(registry.profileIds(j) != _id, "a profile is listed twice");
      }
    }
  }

  /// Every identity the handler registered is still registered, as flagged.
  function invariant_registrationsPersist () public view {
    for (uint256 i = 0; i < handler.saltCount(); ++i) {
      bytes32 _salt = handler.saltAt(i);
      (, bool _active, uint256 _registeredAt, ) = registry.profiles(_salt);
      if (!handler.ghostRegistered(_salt)) {
        assertEq(_registeredAt, 0, "an unregistered identity has a profile");
        continue;
      }
      assertGt(_registeredAt, 0, "a registered profile vanished");
      assertEq(_active, handler.ghostActive(_salt), "active flag diverged");
    }
  }

  /// Every email the handler sent has been spent.
  function invariant_emailsSpent () public view {
    for (uint256 i = 0; i < handler.ghostNullifierCount(); ++i) {
      assertTrue(
        registry.usedNullifiers(handler.ghostNullifiers(i)),
        "a sent email was not spent"
      );
    }
  }

  /// No profile's clock runs ahead of the emails the handler has sent.
  function invariant_timestampsBoundedByClock () public view {
    for (uint256 i = 0; i < handler.saltCount(); ++i) {
      (, , , uint256 _lastTimestamp) = registry.profiles(handler.saltAt(i));
      assertLe(_lastTimestamp, handler.clock(), "a profile clock ran ahead");
    }
  }

  /// Management is always exactly who the last handover made it.
  function invariant_management () public view {
    assertEq(
      registry.management(), handler.management(), "management diverged"
    );
    assertEq(registry.pendingManagement(), address(0), "a handover dangles");
  }

  /// Every registered profile is a two-of-two: its controller is never zero.
  function invariant_controllersAlwaysBound () public view {
    for (uint256 i = 0; i < handler.saltCount(); ++i) {
      bytes32 _salt = handler.saltAt(i);
      (address _controller, , uint256 _registeredAt, ) = registry.profiles(
        _salt
      );
      if (_registeredAt == 0) {
        continue;
      }
      assertTrue(_controller != address(0), "a profile lost its controller");
    }
  }

  /// Each profile's nonce counts exactly its relayed signed writes.
  function invariant_noncesCountSignedWrites () public view {
    for (uint256 i = 0; i < handler.saltCount(); ++i) {
      bytes32 _salt = handler.saltAt(i);
      assertEq(
        registry.nonces(_salt), handler.ghostSignedWrites(_salt),
        "a profile nonce diverged"
      );
    }
  }

  /// An inactive profile's records and controller are frozen where flagged.
  function invariant_inactiveProfilesFrozen () public view {
    for (uint256 i = 0; i < handler.saltCount(); ++i) {
      bytes32 _salt = handler.saltAt(i);
      (address _controller, bool _active, uint256 _registeredAt, ) =
      registry.profiles(
        _salt
      );
      if (_registeredAt == 0 || _active) {
        continue;
      }
      assertEq(
        _controller, handler.frozenController(_salt),
        "an inactive profile's controller moved"
      );
      for (uint256 j = 0; j < handler.keyCount(); ++j) {
        string memory _key = handler.keyAt(j);
        assertEq(
          registry.text(_salt, _key), handler.frozenText(_salt, _key),
          "an inactive profile's record moved"
        );
      }
    }
  }
}

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title RegistryHandler
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The choreographer for the Registry invariant campaign. Every action
  translates fuzzer entropy into a valid-by-construction registry interaction
  over a fixed cast of identities, controllers (with their signing keys),
  managements, keys, and values, so no call ever reverts and the campaign runs
  with `fail_on_revert` enabled. Controller rotations are co-signed by the
  current controller, as the root two-of-two demands, and relayed record
  writes carry the controller's signature at the profile's current nonce.
  Emails are stamped from a monotone clock with fresh nullifiers, and ghost
  state records the facts the invariants need: who is registered and flagged
  how, which emails were sent, who management is, and what an inactive
  profile looked like the moment it was frozen.

  @custom:date August 21st, 2026.
*/
contract RegistryHandler is
  Test {

  /// The registry under test.
  Registry internal registry;

  /// The DKIM key hash the handler's emails are signed with.
  bytes32 internal immutable keyHash;

  /// The current management, tracked through every handover.
  address public management;

  /// The fixed cast of identities.
  bytes32[] internal saltList;

  /// The fixed cast of controllers.
  address[] internal controllerList;

  /**
    The signing key behind each controller in the cast.

    @custom:param _controller The controller.
    @custom:return _key The signing key behind it.
  */
  mapping (
    address _controller => uint256 _key
  ) internal controllerKeys;

  /// The fixed cast of candidate managements.
  address[] internal managementList;

  /// The fixed cast of record keys.
  string[] internal keyList;

  /// The fixed cast of record values.
  string[] internal valueList;

  /// The DKIM clock: every email is stamped later than the last.
  uint256 public clock;

  /// The number of identities registered so far.
  uint256 public ghostRegisteredCount;

  /// The nullifier of every email sent so far.
  bytes32[] public ghostNullifiers;

  /**
    Whether an identity has been registered.

    @custom:param _salt The identity.
    @custom:return _ Whether it has been registered.
  */
  mapping (
    bytes32 _salt => bool _registered
  ) public ghostRegistered;

  /**
    Whether a registered identity is flagged active.

    @custom:param _salt The identity.
    @custom:return _ Whether it is flagged active.
  */
  mapping (
    bytes32 _salt => bool _active
  ) public ghostActive;

  /**
    The number of relayed signed writes made for an identity.

    @custom:param _salt The identity.
    @custom:return _ The number of relayed signed writes made.
  */
  mapping (
    bytes32 _salt => uint256 _count
  ) public ghostSignedWrites;

  /**
    The controller an identity had the moment it was last flagged inactive.

    @custom:param _salt The identity.
    @custom:return _ The frozen controller.
  */
  mapping (
    bytes32 _salt => address _controller
  ) public frozenController;

  /**
    The records an identity had the moment it was last flagged inactive.

    @custom:param _salt The identity.
    @custom:param _key The record key.
    @custom:return _ The frozen record value.
  */
  mapping (
    bytes32 _salt => mapping (
      string _key => string _value
    )
  ) internal frozenTexts;

  /**
    Construct the handler.

    @param _registry The registry under test.
    @param _management The initial management.
    @param _keyHash The DKIM key hash the handler's emails are signed with.
  */
  constructor (
    Registry _registry,
    address _management,
    bytes32 _keyHash
  ) {
    registry = _registry;
    management = _management;
    keyHash = _keyHash;
    saltList.push(keccak256("alice@ethereum.org|code"));
    saltList.push(keccak256("bob@ethereum.org|code"));
    saltList.push(keccak256("carol@ethereum.org|code"));
    saltList.push(keccak256("dave@ethereum.org|code"));
    _addController("walletA");
    _addController("walletB");
    _addController("walletC");
    managementList.push(_management);
    managementList.push(makeAddr("managementB"));
    managementList.push(makeAddr("managementC"));
    keyList.push("avatar");
    keyList.push("url");
    keyList.push("com.github");
    valueList.push("a");
    valueList.push("https://example.org/a-longer-value");
    valueList.push("moved from Berlin to Lisbon");
  }

  /**
    Retrieve the size of the identity cast.

    @return _ The number of identities.
  */
  function saltCount () external view returns (uint256) {
    return saltList.length;
  }

  /**
    Retrieve an identity from the cast.

    @param _index The index of the identity.

    @return _ The identity.
  */
  function saltAt (
    uint256 _index
  ) external view returns (bytes32) {
    return saltList[_index];
  }

  /**
    Retrieve the size of the key cast.

    @return _ The number of keys.
  */
  function keyCount () external view returns (uint256) {
    return keyList.length;
  }

  /**
    Retrieve a key from the cast.

    @param _index The index of the key.

    @return _ The key.
  */
  function keyAt (
    uint256 _index
  ) external view returns (string memory) {
    return keyList[_index];
  }

  /**
    Retrieve the number of emails sent so far.

    @return _ The number of emails sent.
  */
  function ghostNullifierCount () external view returns (uint256) {
    return ghostNullifiers.length;
  }

  /**
    Retrieve a frozen record.

    @param _salt The identity.
    @param _key The record key.

    @return _ The record value the identity had when last flagged inactive.
  */
  function frozenText (
    bytes32 _salt,
    string calldata _key
  ) external view returns (string memory) {
    return frozenTexts[_salt][_key];
  }

  /**
    Pick an identity from the cast.

    @param _seed The fuzzer-supplied selection seed.

    @return _ The chosen identity.
  */
  function _pickSalt (
    uint256 _seed
  ) internal view returns (bytes32) {
    return saltList[_seed % saltList.length];
  }

  /**
    Pick a key from the cast.

    @param _seed The fuzzer-supplied selection seed.

    @return _ The chosen key.
  */
  function _pickKey (
    uint256 _seed
  ) internal view returns (string memory) {
    return keyList[_seed % keyList.length];
  }

  /**
    Pick a value from the cast.

    @param _seed The fuzzer-supplied selection seed.

    @return _ The chosen value.
  */
  function _pickValue (
    uint256 _seed
  ) internal view returns (string memory) {
    return valueList[_seed % valueList.length];
  }

  /**
    Create a controller with a known signing key and add it to the cast.

    @param _name The label of the controller.
  */
  function _addController (
    string memory _name
  ) internal {
    (address _wallet, uint256 _key) = makeAddrAndKey(_name);
    controllerList.push(_wallet);
    controllerKeys[_wallet] = _key;
  }

  /**
    Sign the current controller's authorization of one email.

    @param _salt The identity whose controller signs.
    @param _emailNullifier The nullifier of the email to authorize.

    @return _ The signature.
  */
  function _sign (
    bytes32 _salt,
    bytes32 _emailNullifier
  ) internal view returns (bytes memory) {
    (address _controller, , , ) = registry.profiles(_salt);
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      controllerKeys[_controller], registry.authorizationDigest(
        _emailNullifier
      )
    );
    return abi.encodePacked(_r, _s, _v);
  }

  /**
    Build the next email from an identity: stamped later than every email before
    it, with a fresh nullifier, carrying the account code.

    @param _salt The sender's identity.
    @param _command The command the email carries.

    @return _ The email proof.
  */
  function _emailFrom (
    bytes32 _salt,
    string memory _command
  ) internal returns (EmailProof memory) {
    clock += 1;
    bytes32 _nullifier =
      keccak256(abi.encode("email", ghostNullifiers.length + 1));
    ghostNullifiers.push(_nullifier);
    return EmailProof({
      domainName: "ethereum.org",
      publicKeyHash: keyHash,
      timestamp: clock,
      maskedCommand: _command,
      emailNullifier: _nullifier,
      accountSalt: _salt,
      isCodeExist: true,
      proof: "valid"
    });
  }

  /**
    Note that an identity is registered, if it was not already.

    @param _salt The identity.
  */
  function _noteRegistered (
    bytes32 _salt
  ) internal {
    if (ghostRegistered[_salt]) {
      return;
    }
    ghostRegistered[_salt] = true;
    ghostActive[_salt] = true;
    ghostRegisteredCount += 1;
  }

  /**
    Register an identity by email, or rotate its controller with the current
    controller's signature.

    @param _saltSeed The identity selection seed.
    @param _controllerSeed The controller selection seed.
  */
  function setController (
    uint256 _saltSeed,
    uint256 _controllerSeed
  ) external {
    bytes32 _salt = _pickSalt(_saltSeed);
    address _controller =
      controllerList[_controllerSeed % controllerList.length];
    if (!ghostRegistered[_salt]) {
      registry.register(
        _emailFrom(_salt, registry.setControllerCommand(_controller)),
        _controller
      );
      _noteRegistered(_salt);
      return;
    }

    if (!ghostActive[_salt]) {
      return;
    }
    EmailProof memory _proof =
      _emailFrom(_salt, registry.setControllerCommand(_controller));
    registry.setController(
      _proof, _controller, _sign(_salt, _proof.emailNullifier)
    );
  }

  /**
    Set or clear a registered identity's record by the controller's relayed
    signature at the current nonce.

    @param _saltSeed The identity selection seed.
    @param _keySeed The key selection seed.
    @param _valueSeed The value selection seed.
    @param _clear Whether to clear the record instead of setting it.
  */
  function setTextSigned (
    uint256 _saltSeed,
    uint256 _keySeed,
    uint256 _valueSeed,
    bool _clear
  ) external {
    bytes32 _salt = _pickSalt(_saltSeed);
    if (!ghostRegistered[_salt] || !ghostActive[_salt]) {
      return;
    }
    string memory _key = _pickKey(_keySeed);
    string memory _value = _clear ? "" : _pickValue(_valueSeed);
    (address _controller, , , ) = registry.profiles(_salt);
    (uint8 _v, bytes32 _r, bytes32 _s) = vm.sign(
      controllerKeys[_controller], registry.setTextDigest(_salt, _key, _value)
    );
    registry.setTextSigned(_salt, _key, _value, abi.encodePacked(_r, _s, _v));
    ghostSignedWrites[_salt] += 1;
  }

  /**
    Set or clear a registered identity's record as its controller.

    @param _saltSeed The identity selection seed.
    @param _keySeed The key selection seed.
    @param _valueSeed The value selection seed.
    @param _clear Whether to clear the record instead of setting it.
  */
  function setText (
    uint256 _saltSeed,
    uint256 _keySeed,
    uint256 _valueSeed,
    bool _clear
  ) external {
    bytes32 _salt = _pickSalt(_saltSeed);
    if (!ghostRegistered[_salt] || !ghostActive[_salt]) {
      return;
    }
    (address _controller, , , ) = registry.profiles(_salt);
    string memory _key = _pickKey(_keySeed);
    string memory _value = _clear ? "" : _pickValue(_valueSeed);
    vm.prank(_controller);
    registry.setText(_salt, _key, _value);
  }

  /**
    Flag a registered identity active or inactive as management, freezing a
    snapshot of it when it goes inactive.

    @param _saltSeed The identity selection seed.
    @param _active The new active flag.
  */
  function setActive (
    uint256 _saltSeed,
    bool _active
  ) external {
    bytes32 _salt = _pickSalt(_saltSeed);
    if (!ghostRegistered[_salt]) {
      return;
    }
    vm.prank(management);
    registry.setActive(_salt, _active);
    ghostActive[_salt] = _active;
    if (_active) {
      return;
    }
    (address _controller, , , ) = registry.profiles(_salt);
    frozenController[_salt] = _controller;
    for (uint256 i = 0; i < keyList.length; ++i) {
      frozenTexts[_salt][keyList[i]] = registry.text(_salt, keyList[i]);
    }
  }

  /**
    Hand management over in two steps to a candidate from the cast.

    @param _seed The candidate selection seed.
  */
  function rotateManagement (
    uint256 _seed
  ) external {
    address _next = managementList[_seed % managementList.length];
    vm.prank(management);
    registry.transferManagement(_next);
    vm.prank(_next);
    registry.acceptManagement();
    management = _next;
  }
}

