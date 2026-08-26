// SPDX-License-Identifier: LicenseRef-(SEPPUKU WITH VPL) WITH AGPL-3.0-only 
import { EmailProof, IVerifier } from "./interfaces/IVerifier.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { LibString } from "solady/utils/LibString.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Foundation Registry
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "You're not supposed to do accounting in a temple."

  An onchain directory of Ethereum Foundation personnel. Each profile is a
  key-value store of text records mapping cleanly onto onto `.gwei` and other
  less-immutable naming systems. Profiles are identified by a ZK Email account
  salt. A profile comes into being only through a ZK Email proof that a
  DKIM-signed message from an address at the pinned domain carried the body:

  `Set controller to {address} {binding}`

  The sole administrative role is `management`: it flags a profile inactive
  ("former EF") and back and it maintains the set of DKIM public key hashes
  honored for the domain.

  @custom:date August 25th, 2026.
*/
contract Registry is
  EIP712 {
  using LibString for address;
  using LibString for string;
  using LibString for uint256;

  /**
    A profile in the directory.

    @param controller The account that edits the profile's records with ordinary
      transactions and co-signs its email operations; never zero.
    @param active Whether the profile is current EF personnel. Inactive profiles
      are read-only.
    @param registeredAt The block timestamp of the profile's creation; zero
      means no profile.
    @param lastTimestamp The DKIM timestamp of the last email honored for the
      profile; later emails may not precede it.
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
    A profile is inactive and therefore read-only.

    @param profileId The inactive profile ID.
  */
  error InactiveProfile (
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

  /// The email registering a profile did not carry its account code.
  error MissingAccountCode ();

  /**
    An email predates the last email honored for its profile.

    @param timestamp The DKIM timestamp of the email.
    @param lastTimestamp The DKIM timestamp of the last honored email.
  */
  error StaleEmail (
    uint256 timestamp,
    uint256 lastTimestamp
  );

  /**
    An email's command does not say what the call claims it says.

    @param maskedCommand The command the email actually carried.
  */
  error InvalidCommand (
    string maskedCommand
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

  /**
    Emitted when a profile is registered.

    @param profileId The ID of the new profile.
  */
  event Registered (
    bytes32 indexed profileId
  );

  /**
    Emitted when an email is verified and consumed.

    @param profileId The ID of the profile the email acted on.
    @param emailNullifier The nullifier of the consumed email.
    @param timestamp The DKIM timestamp of the email.
    @param command The command the email carried.
  */
  event EmailAuthorized (
    bytes32 indexed profileId,
    bytes32 indexed emailNullifier,
    uint256 timestamp,
    string command
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
    Emitted when management flags a profile active or inactive.

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

  /// The command prefix that sets a profile's controller.
  string internal constant SET_CONTROLLER_PREFIX = "Set controller to ";

  /// The EIP-712 typehash of a controller's authorization of one email.
  bytes32 public constant EMAIL_AUTHORIZATION_TYPEHASH =
    keccak256("EmailAuthorization(bytes32 emailNullifier)");

  /// The EIP-712 typehash of a controller's relayed text-record write.
  bytes32 public constant SET_TEXT_TYPEHASH =
    keccak256(
      "SetText(bytes32 profileId,string key,string value,uint256 nonce)"
    );

  /// The ZK Email proof verifier.
  IVerifier public immutable verifier;

  /// The email domain whose senders may hold profiles, e.g. `ethereum.org`.
  string public domain;

  /// The multisig that flags profiles active or inactive.
  address public management;

  /// The next management in a pending two-step handover.
  address public pendingManagement;

  /// The IDs of every registered profile, in order of registration.
  bytes32[] public profileIds;

  /**
    A mapping of registered profiles.

    @custom:param _profileId The ID of the profile: its account salt.
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

    @custom:param _publicKeyHash The Poseidon hash of a DKIM public key.
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
    (`setTextSigned`), so each such signature is single-use and ordered.

    @custom:param _profileId The ID of the profile.
    @custom:return _nonce The next nonce a signed operation must carry.
  */
  mapping (
    bytes32 _profileId => uint256 _nonce
  ) public nonces;

  /**
    Construct the registry against a ZK Email proof verifier.

    @param _verifier The ZK Email proof verifier.
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
    Check whether an email's masked command is exactly an expected command.

    @param _maskedCommand The command the email carried.
    @param _expected The command the call claims it carried.

    @return _ Whether the two are identical.
  */
  function _commandIs (
    string calldata _maskedCommand,
    string memory _expected
  ) internal pure returns (bool) {
    return keccak256(bytes(_maskedCommand)) == keccak256(bytes(_expected));
  }

  /**
    Check whether an email's masked command sets the controller to a particular
    address, accepting the address in checksummed, lowercase, or uppercase hex:
    the same three forms ZK Email's own `CommandUtils` accepts. The binding tag
    must follow in every form.

    @param _maskedCommand The command the email carried.
    @param _controller The controller the call claims it names.

    @return _ Whether the command sets the controller to `_controller`.
  */
  function _isSetControllerCommand (
    string calldata _maskedCommand,
    address _controller
  ) internal view returns (bool) {
    if (_commandIs(_maskedCommand, setControllerCommand(_controller))) {
      return true;
    }
    string memory _binding = commandBinding();
    if (
      _commandIs(
        _maskedCommand,
        string.concat(
          SET_CONTROLLER_PREFIX, _controller.toHexString(), " ", _binding
        )
      )
    ) {
      return true;
    }
    return _commandIs(
      _maskedCommand,
      string.concat(
        SET_CONTROLLER_PREFIX, "0x", _controller.toHexStringNoPrefix().upper(),
        " ", _binding
      )
    );
  }

  /**
    Verify an email proof against this registry's email policy and consume it:
    the sender's domain must be the pinned domain, the DKIM key hash must be one
    management honors, the email must be unused, and the proof must verify. The
    nullifier is spent and the email announced.

    @param _proof The ZK Email proof to verify and consume.
  */
  function _verifyEmail (
    EmailProof calldata _proof
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

    if (!verifier.verifyEmailProof(_proof)) {
      revert InvalidEmailProof();
    }
    usedNullifiers[_proof.emailNullifier] = true;
    emit EmailAuthorized(
      _proof.accountSalt, _proof.emailNullifier, _proof.timestamp,
      _proof.maskedCommand
    );
  }

  /**
    Authorize an email operation on an existing profile: the profile must be
    active, the email must not predate the last email honored for it, the
    profile's controller must have signed off on this exact email, and the email
    itself must verify and be consumed. This is the two-of-two: neither the
    email nor the controller alone moves an existing profile.

    @param _proof The ZK Email proof to verify and consume.
    @param _signature The controller's signature over `authorizationDigest` of
      the email's nullifier.

    @return _ The profile the email acts on.
  */
  function _authorize (
    EmailProof calldata _proof,
    bytes calldata _signature
  ) internal returns (Profile storage) {
    bytes32 _profileId = _proof.accountSalt;
    Profile storage p = profiles[_profileId];
    if (p.registeredAt == 0) {
      revert UnknownProfile(_profileId);
    }

    if (!p.active) {
      revert InactiveProfile(_profileId);
    }

    if (_proof.timestamp != 0 && _proof.timestamp < p.lastTimestamp) {
      revert StaleEmail(_proof.timestamp, p.lastTimestamp);
    }

    if (
      !SignatureCheckerLib.isValidSignatureNowCalldata(
        p.controller, authorizationDigest(_proof.emailNullifier), _signature
      )
    ) {
      revert InvalidControllerSignature();
    }
    _verifyEmail(_proof);
    if (_proof.timestamp != 0) {
      p.lastTimestamp = _proof.timestamp;
    }
    return p;
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
    Retrieve the binding tag every command ends with: `{chainid}:{registry}` for
    this exact deployment. A command bound this way can never be honored by any
    other registry on any other chain.

    @return _ The binding tag.
  */
  function commandBinding () public view returns (string memory) {
    return string.concat(
      block.chainid.toString(), ":", address(this).toHexStringChecksummed()
    );
  }

  /**
    Build the command an email must carry to set a controller. The address is
    rendered checksummed; lowercase and uppercase hex are also accepted.

    @param _controller The controller to set.

    @return _ The command.
  */
  function setControllerCommand (
    address _controller
  ) public view returns (string memory) {
    return string.concat(
      SET_CONTROLLER_PREFIX, _controller.toHexStringChecksummed(), " ",
      commandBinding()
    );
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
    Register a profile by email, binding its controller. The email's command
    must read `Set controller to {address} {binding}` (see
    `setControllerCommand`), it must carry the identity's account code, and the
    controller may not be zero: every profile is a two-of-two from birth.
    Registration is the one email operation needing no controller signature.
    Anyone may submit the proof.

    @param _proof The ZK Email proof of the command email.
    @param _controller The controller the command names.
  */
  function register (
    EmailProof calldata _proof,
    address _controller
  ) external {
    if (!_isSetControllerCommand(_proof.maskedCommand, _controller)) {
      revert InvalidCommand(_proof.maskedCommand);
    }

    if (_controller == address(0)) {
      revert ZeroAddress();
    }
    bytes32 _profileId = _proof.accountSalt;
    Profile storage p = profiles[_profileId];
    if (p.registeredAt != 0) {
      revert AlreadyRegistered(_profileId);
    }

    if (!_proof.isCodeExist) {
      revert MissingAccountCode();
    }
    _verifyEmail(_proof);
    if (_proof.timestamp != 0) {
      p.lastTimestamp = _proof.timestamp;
    }
    p.active = true;
    p.registeredAt = block.timestamp;
    p.controller = _controller;
    profileIds.push(_profileId);
    emit Registered(_profileId);
    emit ControllerSet(_profileId, _controller);
  }

  /**
    Rotate a profile's controller: email plus the current controller's
    signature. The email's command must read `Set controller to {address}
    {binding}` (see `setControllerCommand`), and the new controller may not be
    zero. Anyone may submit the proof.

    @param _proof The ZK Email proof of the command email.
    @param _controller The controller the command names.
    @param _signature The current controller's signature over
      `authorizationDigest` of the email's nullifier.
  */
  function setController (
    EmailProof calldata _proof,
    address _controller,
    bytes calldata _signature
  ) external {
    if (!_isSetControllerCommand(_proof.maskedCommand, _controller)) {
      revert InvalidCommand(_proof.maskedCommand);
    }

    if (_controller == address(0)) {
      revert ZeroAddress();
    }
    Profile storage p = _authorize(_proof, _signature);
    p.controller = _controller;
    emit ControllerSet(_proof.accountSalt, _controller);
  }

  /**
    Set a profile's text record as its controller. An empty value clears the
    record. Inactive profiles are read-only.

    @param _profileId The ID of the profile.
    @param _key The record key; it may not contain spaces.
    @param _value The new record value, or empty to clear.
  */
  function setText (
    bytes32 _profileId,
    string calldata _key,
    string calldata _value
  ) external {
    Profile storage p = profiles[_profileId];
    if (p.registeredAt == 0) {
      revert UnknownProfile(_profileId);
    }

    if (msg.sender != p.controller) {
      revert NotController();
    }

    if (!p.active) {
      revert InactiveProfile(_profileId);
    }
    _requireKey(_key);
    _setText(_profileId, _key, _value);
  }

  /**
    Set a profile's text record by the controller's relayed signature, so a
    controller that can sign but cannot transact wields full control and anyone
    may carry the transaction. The signature covers `setTextDigest` at the
    profile's current nonce, which this call consumes. An empty value clears the
    record. Inactive profiles are read-only.

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
    Profile storage p = profiles[_profileId];
    if (p.registeredAt == 0) {
      revert UnknownProfile(_profileId);
    }

    if (!p.active) {
      revert InactiveProfile(_profileId);
    }
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
    Flag a profile active or inactive. Only management may do this. An inactive
    profile is "former EF": read-only, with its records left in place.

    @param _profileId The ID of the profile.
    @param _active The new active flag.
  */
  function setActive (
    bytes32 _profileId,
    bool _active
  ) external {
    if (msg.sender != management) {
      revert NotManagement();
    }
    Profile storage p = profiles[_profileId];
    if (p.registeredAt == 0) {
      revert UnknownProfile(_profileId);
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

