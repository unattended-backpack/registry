// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only
pragma solidity 0.8.36;

import { EmailProof, IVerifier } from "./interfaces/IVerifier.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Foundation Registry
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "You're not supposed to do accounting in a temple."

  An onchain directory of Ethereum Foundation personnel in which every profile
  is private. Each profile is a key-value store of text records mapping cleanly
  onto `.gwei` and other less-immutable naming systems. A profile's ID is
  `sha256(salt || lowercased email address)`, where the salt is a secret only
  the profile's owner holds, so nobody else can tell whose profile is whose.

  A profile comes into being only through a zero-knowledge proof that a
  DKIM-signed email from an address at the pinned domain carried, as its whole
  subject, a commitment authorizing a controller on this registry on this
  chain (see `circuits/`). The proof reveals neither the address nor the
  subject, and it reveals the email's time only to the week.

  A profile stays active for `RENEWAL_PERIOD` after its latest email, and its
  owner renews it with a fresh email that authorizes the same controller
  again. Someone who leaves the Foundation loses the mailbox, cannot renew, and
  lapses on their own. The sole administrative role is `management`: it
  maintains the set of DKIM public key hashes honored for the domain, and it
  may flag any profile inactive ("former EF"). Once a profile lapses, anyone
  may flag it inactive too.

  @custom:date October 1st, 2026.
*/
contract Registry is
  EIP712 {

  /**
    A profile in the directory.

    @param controller The account that edits the profile's records with ordinary
      transactions and co-signs its email operations; never zero.
    @param active Whether the profile is standing. A profile flagged inactive
      (by management at any time, or by anyone once it lapses) is read-only and
      cannot renew.
    @param registeredAt The block timestamp of the profile's creation; zero
      means no profile.
    @param lastTimestamp The week-rounded DKIM timestamp of the latest email
      honored for the profile. The profile lapses `RENEWAL_PERIOD` after it, and
      later emails may not precede it.
  */
  struct Profile {
    address controller;
    bool active;
    uint256 registeredAt;
    uint256 lastTimestamp;
  }

  /// An address was the zero address where a real address is required.
  error ZeroAddress ();

  /// The domain was empty.
  error EmptyDomain ();

  /// The caller is not management.
  error NotManagement ();

  /// The caller is not the pending management.
  error NotPendingManagement ();

  /// The caller is not the controller of the profile.
  error NotController ();

  /**
    A profile ID does not correspond to any registered profile.

    @param profileId The unknown profile ID.
  */
  error UnknownProfile (
    bytes32 profileId
  );

  /**
    An identity attempted to register a second time.

    @param profileId The already-registered profile ID.
  */
  error AlreadyRegistered (
    bytes32 profileId
  );

  /**
    A profile has been flagged inactive and is therefore read-only.

    @param profileId The inactive profile ID.
  */
  error InactiveProfile (
    bytes32 profileId
  );

  /**
    A profile has gone `RENEWAL_PERIOD` without a fresh email and is read-only
    until renewed.

    @param profileId The lapsed profile ID.
  */
  error LapsedProfile (
    bytes32 profileId
  );

  /**
    An email came from a domain other than the pinned one.

    @param domainName The offending domain.
  */
  error WrongDomain (
    string domainName
  );

  /**
    An email was signed with a DKIM key management does not honor.

    @param publicKeyHash The offending DKIM public key hash.
  */
  error InvalidDKIMPublicKeyHash (
    bytes32 publicKeyHash
  );

  /**
    An email has already been used.

    @param emailNullifier The nullifier of the used email.
  */
  error EmailAlreadyUsed (
    bytes32 emailNullifier
  );

  /**
    An email predates the last email honored for its profile.

    @param timestamp The week-rounded DKIM timestamp of the email.
    @param lastTimestamp The week-rounded DKIM timestamp of the last honored
      email.
  */
  error StaleEmail (
    uint256 timestamp,
    uint256 lastTimestamp
  );

  /**
    An email is older than `EMAIL_LIFETIME` allows.

    @param timestamp The week-rounded DKIM timestamp of the email.
  */
  error ExpiredEmail (
    uint256 timestamp
  );

  /// The email proof did not verify.
  error InvalidEmailProof ();

  /// The profile's controller did not sign off on the operation.
  error InvalidControllerSignature ();

  /**
    A record key is empty or contains a space.

    @param key The offending key.
  */
  error InvalidKey (
    string key
  );

  /// A batch of records pairs its keys and values unevenly.
  error LengthMismatch ();

  /**
    Emitted when a profile is registered.

    @param profileId The ID of the new profile.
  */
  event Registered (
    bytes32 indexed profileId
  );

  /**
    Emitted when an email is verified and consumed. The key hash lets anyone
    audit which DKIM key authorized each profile against the keys the domain
    publishes in DNS.

    @param profileId The ID of the profile the email acted on.
    @param emailNullifier The nullifier of the consumed email.
    @param publicKeyHash The hash of the DKIM key that signed the email.
    @param timestamp The week-rounded DKIM timestamp of the email.
  */
  event EmailAuthorized (
    bytes32 indexed profileId,
    bytes32 indexed emailNullifier,
    bytes32 indexed publicKeyHash,
    uint256 timestamp
  );

  /**
    Emitted when a profile's controller is set.

    @param profileId The ID of the profile.
    @param controller The new controller.
  */
  event ControllerSet (
    bytes32 indexed profileId,
    address indexed controller
  );

  /**
    Emitted when a text record changes, in the shape of the ENS resolver event.

    @param profileId The ID of the profile.
    @param indexedKey The record key, indexed.
    @param key The record key.
    @param value The new record value; empty means cleared.
  */
  event TextChanged (
    bytes32 indexed profileId,
    string indexed indexedKey,
    string key,
    string value
  );

  /**
    Emitted when a profile is flagged inactive, or restored.

    @param profileId The ID of the profile.
    @param active The new active flag.
  */
  event ActiveSet (
    bytes32 indexed profileId,
    bool active
  );

  /**
    Emitted when management honors or revokes a DKIM public key hash for the
    domain.

    @param publicKeyHash The DKIM public key hash.
    @param valid Whether the key hash is now honored.
  */
  event DKIMPublicKeyHashSet (
    bytes32 indexed publicKeyHash,
    bool valid
  );

  /**
    Emitted when a two-step management handover is started or canceled.

    @param management The current management.
    @param pendingManagement The proposed next management, or the zero address
      on cancellation.
  */
  event ManagementTransferStarted (
    address indexed management,
    address indexed pendingManagement
  );

  /**
    Emitted when a management handover completes.

    @param previousManagement The previous management.
    @param newManagement The new management.
  */
  event ManagementTransferred (
    address indexed previousManagement,
    address indexed newManagement
  );

  /**
    How long a profile stays active after the DKIM timestamp of its latest
    email. Timestamps are rounded down to the week, so the effective window is
    83 to 90 days after the email is sent.
  */
  uint256 public constant RENEWAL_PERIOD = 90 days;

  /**
    How long after its week-rounded DKIM timestamp an email remains usable:
    every email is usable for at least four weeks after it is sent, and at most
    five. The slack lets its sender wait before submitting, so the submission's
    time says little about the email's.
  */
  uint256 public constant EMAIL_LIFETIME = 5 weeks;

  /// The EIP-712 typehash of a controller's authorization of one email.
  bytes32 public constant EMAIL_AUTHORIZATION_TYPEHASH =
    keccak256("EmailAuthorization(bytes32 emailNullifier)");

  /// The EIP-712 typehash of a controller's relayed text-record write.
  bytes32 public constant SET_TEXT_TYPEHASH =
    keccak256(
      "SetText(bytes32 profileId,string key,string value,uint256 nonce)"
    );

  /// The EIP-712 typehash of a controller's relayed batch of text-record
  /// writes.
  bytes32 public constant SET_TEXTS_TYPEHASH =
    keccak256(
      "SetTexts(bytes32 profileId,string[] keys,string[] values,uint256 nonce)"
    );

  /// The email proof verifier.
  IVerifier public immutable verifier;

  /// The email domain whose senders may hold profiles, e.g. `ethereum.org`.
  string public domain;

  /// The multisig that maintains DKIM keys and may flag profiles inactive.
  address public management;

  /// The next management in a pending two-step handover.
  address public pendingManagement;

  /// The IDs of every registered profile, in order of registration.
  bytes32[] public profileIds;

  /**
    A mapping of registered profiles.

    @custom:param _profileId The ID of the profile: the SHA-256 of its owner's
      secret salt followed by their lowercased email address.
    @custom:return _profile The profile.
  */
  mapping (
    bytes32 _profileId => Profile _profile
  ) public profiles;

  /**
    A mapping of profile text records.

    @custom:param _profileId The ID of the profile.
    @custom:param _key The record key.
    @custom:return _value The record value; empty if unset.
  */
  mapping (
    bytes32 _profileId => mapping (
      string _key => string _value
    )
  ) internal texts;

  /**
    A mapping of the DKIM public key hashes honored for the domain,
    maintained by management as the domain's mail infrastructure rotates its
    keys.

    @custom:param _publicKeyHash The Pedersen hash of a DKIM public key's
      modulus limbs (see `circuits/dkim_key_hash`).
    @custom:return _valid Whether the key hash is currently honored.
  */
  mapping (
    bytes32 _publicKeyHash => bool _valid
  ) public dkimPublicKeyHashes;

  /**
    A mapping of consumed email nullifiers.

    @custom:param _emailNullifier The nullifier of an email.
    @custom:return _used Whether the email has been used.
  */
  mapping (
    bytes32 _emailNullifier => bool _used
  ) public usedNullifiers;

  /**
    A mapping of profile nonces consumed by relayed signed operations
    (`setTextSigned` and `setTextsSigned`), so each such signature is single-use
    and ordered.

    @custom:param _profileId The ID of the profile.
    @custom:return _nonce The next nonce a signed operation must carry.
  */
  mapping (
    bytes32 _profileId => uint256 _nonce
  ) public nonces;

  /**
    Construct the registry against an email proof verifier.

    @param _verifier The email proof verifier.
    @param _domain The email domain whose senders may hold profiles.
    @param _management The initial management, which must then honor the
      domain's current DKIM public key hashes before any email can act.
  */
  constructor (
    address _verifier,
    string memory _domain,
    address _management
  ) {
    if (_verifier == address(0) || _management == address(0)) {
      revert ZeroAddress();
    }

    if (bytes(_domain).length == 0) {
      revert EmptyDomain();
    }
    verifier = IVerifier(_verifier);
    domain = _domain;
    management = _management;
    emit ManagementTransferred(address(0), _management);
  }

  /**
    Name and version this contract's EIP-712 signing domain.

    @return _ The name of the signing domain.
    @return _ The version of the signing domain.
  */
  function _domainNameAndVersion () internal pure override returns (
    string memory, string memory
  ) {
    return ("Registry", "1");
  }

  /**
    Revert unless a record key is usable: non-empty and free of spaces. Keys are
    identifiers in the shape of ENS text-record keys, and keeping spaces out of
    them keeps them mirrorable onto the name registries.

    @param _key The record key to check.
  */
  function _requireKey (
    string calldata _key
  ) internal pure {
    bytes calldata _bytes = bytes(_key);
    if (_bytes.length == 0) {
      revert InvalidKey(_key);
    }
    for (uint256 i = 0; i < _bytes.length; ++i) {
      if (_bytes[i] == 0x20) {
        revert InvalidKey(_key);
      }
    }
  }

  /**
    Verify an email proof against this registry's email policy and consume it:
    the sender's domain must be the pinned domain, the DKIM key hash must be one
    management honors, the email must be unused and within `EMAIL_LIFETIME`, and
    the proof must verify for `_controller` on this registry on this chain. The
    nullifier is spent and the email announced.

    @param _proof The email proof to verify and consume.
    @param _controller The controller the email's subject must authorize.
  */
  function _verifyEmail (
    EmailProof calldata _proof,
    address _controller
  ) internal {
    if (keccak256(bytes(_proof.domainName)) != keccak256(bytes(domain))) {
      revert WrongDomain(_proof.domainName);
    }

    if (!dkimPublicKeyHashes[_proof.publicKeyHash]) {
      revert InvalidDKIMPublicKeyHash(_proof.publicKeyHash);
    }

    if (usedNullifiers[_proof.emailNullifier]) {
      revert EmailAlreadyUsed(_proof.emailNullifier);
    }

    if (_proof.timestamp + EMAIL_LIFETIME < block.timestamp) {
      revert ExpiredEmail(_proof.timestamp);
    }

    if (!verifier.verifyEmailProof(_proof, _controller)) {
      revert InvalidEmailProof();
    }
    usedNullifiers[_proof.emailNullifier] = true;
    emit EmailAuthorized(
      _proof.profileId, _proof.emailNullifier, _proof.publicKeyHash,
      _proof.timestamp
    );
  }

  /**
    Authorize an email operation on an existing profile: management must not be
    flagged inactive, the email must not predate the last email honored for it,
    the profile's controller must have signed off on this exact email, and the
    email itself must verify and be consumed. This is the two-of-two: neither
    the email nor the controller alone moves an existing profile. A lapsed
    profile may still be renewed this way.

    @param _proof The email proof to verify and consume.
    @param _controller The controller the email's subject must authorize.
    @param _signature The controller's signature over `authorizationDigest` of
      the email's nullifier.

    @return _ The profile the email acts on.
  */
  function _authorize (
    EmailProof calldata _proof,
    address _controller,
    bytes calldata _signature
  ) internal returns (Profile storage) {
    bytes32 _profileId = _proof.profileId;
    Profile storage p = profiles[_profileId];
    if (p.registeredAt == 0) {
      revert UnknownProfile(_profileId);
    }

    if (!p.active) {
      revert InactiveProfile(_profileId);
    }

    if (_proof.timestamp < p.lastTimestamp) {
      revert StaleEmail(_proof.timestamp, p.lastTimestamp);
    }

    if (
      !SignatureCheckerLib.isValidSignatureNowCalldata(
        p.controller, authorizationDigest(_proof.emailNullifier), _signature
      )
    ) {
      revert InvalidControllerSignature();
    }
    _verifyEmail(_proof, _controller);
    p.lastTimestamp = _proof.timestamp;
    return p;
  }

  /**
    Revert unless a profile's records may be written: it exists, management has
    not been flagged inactive, and it has not lapsed.

    @param _profileId The ID of the profile.

    @return _ The profile.
  */
  function _writable (
    bytes32 _profileId
  ) internal view returns (Profile storage) {
    Profile storage p = profiles[_profileId];
    if (p.registeredAt == 0) {
      revert UnknownProfile(_profileId);
    }

    if (!p.active) {
      revert InactiveProfile(_profileId);
    }

    if (block.timestamp >= p.lastTimestamp + RENEWAL_PERIOD) {
      revert LapsedProfile(_profileId);
    }
    return p;
  }

  /**
    Revert unless a batch of records is well formed: as many values as keys, and
    every key usable.

    @param _keys The record keys.
    @param _values The record values, paired with the keys by position.
  */
  function _requireRecords (
    string[] calldata _keys,
    string[] calldata _values
  ) internal pure {
    if (_keys.length != _values.length) {
      revert LengthMismatch();
    }
    for (uint256 i = 0; i < _keys.length; ++i) {
      _requireKey(_keys[i]);
    }
  }

  /**
    Hash an array of strings as EIP-712 encodes a `string[]` member: the hash of
    the concatenated hashes of its elements.

    @param _strings The strings to hash.

    @return _ The EIP-712 encoding of the array.
  */
  function _hashStrings (
    string[] calldata _strings
  ) internal pure returns (bytes32) {
    bytes32[] memory _hashes = new bytes32[](_strings.length);
    for (uint256 i = 0; i < _strings.length; ++i) {
      _hashes[i] = keccak256(bytes(_strings[i]));
    }
    return keccak256(abi.encodePacked(_hashes));
  }

  /**
    Write a batch of text records in order, so a later write to a key overrides
    an earlier one, announcing each.

    @param _profileId The ID of the profile.
    @param _keys The record keys.
    @param _values The record values, paired with the keys; empty clears.
  */
  function _setTexts (
    bytes32 _profileId,
    string[] calldata _keys,
    string[] calldata _values
  ) internal {
    for (uint256 i = 0; i < _keys.length; ++i) {
      _setText(_profileId, _keys[i], _values[i]);
    }
  }

  /**
    Write a text record and announce it.

    @param _profileId The ID of the profile.
    @param _key The record key.
    @param _value The new record value; empty clears it.
  */
  function _setText (
    bytes32 _profileId,
    string calldata _key,
    string memory _value
  ) internal {
    texts[_profileId][_key] = _value;
    emit TextChanged(_profileId, _key, _key, _value);
  }

  /**
    Retrieve the number of registered profiles.

    @return _ The number of registered profiles.
  */
  function profileCount () external view returns (uint256) {
    return profileIds.length;
  }

  /**
    Retrieve a profile's text record, in the shape of an ENS text resolver.

    @param _profileId The ID of the profile.
    @param _key The record key, e.g. `avatar`, `url`, `com.github`.

    @return _ The record value; empty if unset.
  */
  function text (
    bytes32 _profileId,
    string calldata _key
  ) external view returns (string memory) {
    return texts[_profileId][_key];
  }

  /**
    Check whether a profile is active: registered, not flagged inactive, and
    renewed within `RENEWAL_PERIOD`. A gate that admits current EF personnel
    checks this.

    @param _profileId The ID of the profile.

    @return _ Whether the profile is active.
  */
  function isActive (
    bytes32 _profileId
  ) external view returns (bool) {
    Profile storage p = profiles[_profileId];
    return p.registeredAt != 0 && p.active
    && block.timestamp < p.lastTimestamp + RENEWAL_PERIOD;
  }

  /**
    Retrieve when a profile lapses unless renewed.

    @param _profileId The ID of the profile.

    @return _ The timestamp at which the profile lapses; zero if unregistered.
  */
  function expiresAt (
    bytes32 _profileId
  ) external view returns (uint256) {
    Profile storage p = profiles[_profileId];
    if (p.registeredAt == 0) {
      return 0;
    }
    return p.lastTimestamp + RENEWAL_PERIOD;
  }

  /**
    Retrieve the EIP-712 digest a profile's controller signs to authorize one
    email operation. The digest binds the email's nullifier to this exact
    registry on this exact chain, so a signature is single-use precisely when
    the email is.

    @param _emailNullifier The nullifier of the email to authorize.

    @return _ The digest for the controller to sign.
  */
  function authorizationDigest (
    bytes32 _emailNullifier
  ) public view returns (bytes32) {
    return _hashTypedData(
      keccak256(abi.encode(EMAIL_AUTHORIZATION_TYPEHASH, _emailNullifier))
    );
  }

  /**
    Retrieve the EIP-712 digest a profile's controller signs to authorize one
    relayed text-record write at the profile's current nonce. The digest binds
    the profile, the key, the value, and the nonce to this exact registry on
    this exact chain, so each signature writes one record once.

    @param _profileId The ID of the profile.
    @param _key The record key.
    @param _value The record value; empty clears it.

    @return _ The digest for the controller to sign.
  */
  function setTextDigest (
    bytes32 _profileId,
    string calldata _key,
    string calldata _value
  ) public view returns (bytes32) {
    return _hashTypedData(
      keccak256(
        abi.encode(
          SET_TEXT_TYPEHASH, _profileId, keccak256(bytes(_key)),
          keccak256(bytes(_value)), nonces[_profileId]
        )
      )
    );
  }

  /**
    Return the EIP-712 digest a profile's controller signs to authorize one
    relayed batch of text-record writes at the profile's current nonce. The
    digest binds the profile, every key and value in order, and the nonce to
    this exact registry on this exact chain, so each signature writes one batch
    once.

    @param _profileId The ID of the profile.
    @param _keys The record keys.
    @param _values The record values, paired with the keys; empty clears.

    @return _ The digest for the controller to sign.
  */
  function setTextsDigest (
    bytes32 _profileId,
    string[] calldata _keys,
    string[] calldata _values
  ) public view returns (bytes32) {
    return _hashTypedData(
      keccak256(
        abi.encode(
          SET_TEXTS_TYPEHASH, _profileId, _hashStrings(_keys),
          _hashStrings(_values), nonces[_profileId]
        )
      )
    );
  }

  /**
    Register a profile by email, binding its controller. The email's subject
    must commit to `_controller`, this registry, this chain, and the profile's
    salt, and the controller may not be zero: every profile is a two-of-two from
    birth. Registration is the one email operation needing no controller
    signature. Anyone may submit the proof. One person may hold several
    profiles, one per salt; a profile whose controller key or salt is lost
    simply lapses, and its owner registers a fresh one.

    @param _proof The email proof.
    @param _controller The controller the email authorizes.
  */
  function register (
    EmailProof calldata _proof,
    address _controller
  ) external {
    if (_controller == address(0)) {
      revert ZeroAddress();
    }
    bytes32 _profileId = _proof.profileId;
    Profile storage p = profiles[_profileId];
    if (p.registeredAt != 0) {
      revert AlreadyRegistered(_profileId);
    }
    _verifyEmail(_proof, _controller);
    p.lastTimestamp = _proof.timestamp;
    p.active = true;
    p.registeredAt = block.timestamp;
    p.controller = _controller;
    profileIds.push(_profileId);
    emit Registered(_profileId);
    emit ControllerSet(_profileId, _controller);
  }

  /**
    Renew a profile, or rotate its controller: a fresh email plus the current
    controller's signature. The email's subject must commit to `_controller`,
    this registry, this chain, and the profile's salt, and the new controller
    may not be zero. Renewal is a rotation to the current controller. Every call
    restarts the profile's `RENEWAL_PERIOD`, including on a lapsed profile.
    Anyone may submit the proof.

    @param _proof The email proof.
    @param _controller The controller the email authorizes.
    @param _signature The current controller's signature over
      `authorizationDigest` of the email's nullifier.
  */
  function setController (
    EmailProof calldata _proof,
    address _controller,
    bytes calldata _signature
  ) external {
    if (_controller == address(0)) {
      revert ZeroAddress();
    }
    Profile storage p = _authorize(_proof, _controller, _signature);
    p.controller = _controller;
    emit ControllerSet(_proof.profileId, _controller);
  }

  /**
    Set a profile's text record as its controller. An empty value clears the
    record. Inactive and lapsed profiles are read-only.

    @param _profileId The ID of the profile.
    @param _key The record key; it may not contain spaces.
    @param _value The new record value, or empty to clear.
  */
  function setText (
    bytes32 _profileId,
    string calldata _key,
    string calldata _value
  ) external {
    Profile storage p = _writable(_profileId);
    if (msg.sender != p.controller) {
      revert NotController();
    }
    _requireKey(_key);
    _setText(_profileId, _key, _value);
  }

  /**
    Set a profile's text record by the controller's relayed signature, so a
    controller that can sign but cannot transact wields full control and anyone
    may carry the transaction. The signature covers `setTextDigest` at the
    profile's current nonce, which this call consumes. An empty value clears the
    record. Inactive and lapsed profiles are read-only.

    @param _profileId The ID of the profile.
    @param _key The record key; it may not contain spaces.
    @param _value The new record value, or empty to clear.
    @param _signature The controller's signature over `setTextDigest`.
  */
  function setTextSigned (
    bytes32 _profileId,
    string calldata _key,
    string calldata _value,
    bytes calldata _signature
  ) external {
    Profile storage p = _writable(_profileId);
    _requireKey(_key);
    if (
      !SignatureCheckerLib.isValidSignatureNowCalldata(
        p.controller, setTextDigest(_profileId, _key, _value), _signature
      )
    ) {
      revert InvalidControllerSignature();
    }
    nonces[_profileId] += 1;
    _setText(_profileId, _key, _value);
  }

  /**
    Set several of a profile's text records at once as its controller, in order,
    so a later write to a key overrides an earlier one. An empty value clears
    its record. Inactive and lapsed profiles are read-only.

    @param _profileId The ID of the profile.
    @param _keys The record keys; none may contain spaces.
    @param _values The new record values, paired with the keys by position.
  */
  function setTexts (
    bytes32 _profileId,
    string[] calldata _keys,
    string[] calldata _values
  ) external {
    Profile storage p = _writable(_profileId);
    if (msg.sender != p.controller) {
      revert NotController();
    }
    _requireRecords(_keys, _values);
    _setTexts(_profileId, _keys, _values);
  }

  /**
    Set several of a profile's text records at once by one relayed signature of
    its controller, in order, so a later write to a key overrides an earlier
    one. The signature covers `setTextsDigest` at the profile's current nonce,
    which this call consumes. An empty value clears its record. An empty batch
    writes nothing but still consumes the nonce, which lets a controller revoke
    every signed write it has handed out and not yet seen broadcast. Inactive
    and lapsed profiles are read-only.

    @param _profileId The ID of the profile.
    @param _keys The record keys; none may contain spaces.
    @param _values The new record values, paired with the keys by position.
    @param _signature The controller's signature over `setTextsDigest`.
  */
  function setTextsSigned (
    bytes32 _profileId,
    string[] calldata _keys,
    string[] calldata _values,
    bytes calldata _signature
  ) external {
    Profile storage p = _writable(_profileId);
    _requireRecords(_keys, _values);
    if (
      !SignatureCheckerLib.isValidSignatureNowCalldata(
        p.controller, setTextsDigest(_profileId, _keys, _values), _signature
      )
    ) {
      revert InvalidControllerSignature();
    }
    nonces[_profileId] += 1;
    _setTexts(_profileId, _keys, _values);
  }

  /**
    Flag a profile inactive ("former EF"), or restore it. Management may do
    either to any profile, though it can only recognize a profile for some
    reason beyond its ID, since IDs reveal no owner. Anyone may flag a lapsed
    profile inactive: its owner stopped proving membership, so saying so needs
    no special power. Only management may restore a profile, or touch one that
    has not lapsed. An inactive profile is read-only, with its records left in
    place, and cannot renew, so flagging a lapsed profile ends it for good
    unless management restores it; its owner may instead register a fresh
    profile under a new salt. Restoring a profile does not extend its expiry.

    @param _profileId The ID of the profile.
    @param _active The new active flag.
  */
  function setActive (
    bytes32 _profileId,
    bool _active
  ) external {
    Profile storage p = profiles[_profileId];
    if (p.registeredAt == 0) {
      revert UnknownProfile(_profileId);
    }

    if (msg.sender != management) {
      bool _lapsed = block.timestamp >= p.lastTimestamp + RENEWAL_PERIOD;
      if (_active || !_lapsed) {
        revert NotManagement();
      }
    }
    p.active = _active;
    emit ActiveSet(_profileId, _active);
  }

  /**
    Honor or revoke a DKIM public key hash for the domain. Only management may
    do this. The domain's mail infrastructure rotates its signing keys from time
    to time; management tracks that rotation here, and a revoked key stops every
    email signed with it at once.

    @param _publicKeyHash The Poseidon hash of the DKIM public key.
    @param _valid Whether the key hash is honored.
  */
  function setDKIMPublicKeyHash (
    bytes32 _publicKeyHash,
    bool _valid
  ) external {
    if (msg.sender != management) {
      revert NotManagement();
    }
    dkimPublicKeyHashes[_publicKeyHash] = _valid;
    emit DKIMPublicKeyHashSet(_publicKeyHash, _valid);
  }

  /**
    Start a two-step management handover. Only management may do this. Pass the
    zero address to cancel a pending handover.

    @param _newManagement The proposed next management.
  */
  function transferManagement (
    address _newManagement
  ) external {
    if (msg.sender != management) {
      revert NotManagement();
    }
    pendingManagement = _newManagement;
    emit ManagementTransferStarted(management, _newManagement);
  }

  /// Complete a two-step management handover. Only the pending management may.
  function acceptManagement () external {
    if (msg.sender != pendingManagement) {
      revert NotPendingManagement();
    }
    emit ManagementTransferred(management, msg.sender);
    management = msg.sender;
    pendingManagement = address(0);
  }
}

