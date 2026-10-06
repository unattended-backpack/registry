// The Registry ABI, in ethers human-readable form, and the EIP-712 types the
// controller signs. Only the functions this frontend calls are listed, but
// every custom error is, so any revert can be explained.

window.REGISTRY_ABI = [

  // Reads.
  "function domain() view returns (string)",
  "function management() view returns (address)",
  "function verifier() view returns (address)",
  "function profileCount() view returns (uint256)",
  "function profileIds(uint256) view returns (bytes32)",
  "function profiles(bytes32) view returns (address controller, bool active, uint256 registeredAt, uint256 lastTimestamp)",
  "function text(bytes32 profileId, string key) view returns (string)",
  "function nonces(bytes32) view returns (uint256)",
  "function usedNullifiers(bytes32) view returns (bool)",
  "function dkimPublicKeyHashes(bytes32) view returns (bool)",
  "function isActive(bytes32 profileId) view returns (bool)",
  "function expiresAt(bytes32 profileId) view returns (uint256)",
  "function RENEWAL_PERIOD() view returns (uint256)",
  "function EMAIL_LIFETIME() view returns (uint256)",
  "function authorizationDigest(bytes32 emailNullifier) view returns (bytes32)",
  "function setTextDigest(bytes32 profileId, string key, string value) view returns (bytes32)",
  "function setTextsDigest(bytes32 profileId, string[] keys, string[] values) view returns (bytes32)",

  // Writes. The EmailProof tuple mirrors the on-chain struct field for field.
  "function register((string domainName, bytes32 publicKeyHash, uint256 timestamp, bytes32 emailNullifier, bytes32 profileId, bytes proof) proof, address controller)",
  "function setController((string domainName, bytes32 publicKeyHash, uint256 timestamp, bytes32 emailNullifier, bytes32 profileId, bytes proof) proof, address controller, bytes signature)",
  "function setText(bytes32 profileId, string key, string value)",
  "function setTextSigned(bytes32 profileId, string key, string value, bytes signature)",
  "function setTexts(bytes32 profileId, string[] keys, string[] values)",
  "function setTextsSigned(bytes32 profileId, string[] keys, string[] values, bytes signature)",

  // Every custom error the Registry can revert with.
  "error ZeroAddress()",
  "error EmptyDomain()",
  "error NotManagement()",
  "error NotPendingManagement()",
  "error NotController()",
  "error UnknownProfile(bytes32 profileId)",
  "error AlreadyRegistered(bytes32 profileId)",
  "error InactiveProfile(bytes32 profileId)",
  "error LapsedProfile(bytes32 profileId)",
  "error WrongDomain(string domainName)",
  "error InvalidDKIMPublicKeyHash(bytes32 publicKeyHash)",
  "error EmailAlreadyUsed(bytes32 emailNullifier)",
  "error StaleEmail(uint256 timestamp, uint256 lastTimestamp)",
  "error ExpiredEmail(uint256 timestamp)",
  "error InvalidEmailProof()",
  "error InvalidControllerSignature()",
  "error InvalidKey(string key)",
  "error LengthMismatch()",

  // Events, for surfacing results.
  "event Registered(bytes32 indexed profileId)",
  "event ControllerSet(bytes32 indexed profileId, address indexed controller)",
  "event TextChanged(bytes32 indexed profileId, string indexed indexedKey, string key, string value)"
];

// The EIP-712 types. The domain is built at runtime from the chain id and the
// Registry address, matching the contract's own signing domain ("Registry",
// version "1").
window.REGISTRY_EIP712 = {
  emailAuthorization: {
    EmailAuthorization: [
      { name: "emailNullifier", type: "bytes32" }
    ]
  },
  setText: {
    SetText: [
      { name: "profileId", type: "bytes32" },
      { name: "key", type: "string" },
      { name: "value", type: "string" },
      { name: "nonce", type: "uint256" }
    ]
  },
  setTexts: {
    SetTexts: [
      { name: "profileId", type: "bytes32" },
      { name: "keys", type: "string[]" },
      { name: "values", type: "string[]" },
      { name: "nonce", type: "uint256" }
    ]
  }
};

// The common text-record keys. Records are an open key-value space: these
// come first when a profile's records are listed, Manage suggests them for
// new records, and they are the keys read when a node will not serve the
// logs that name every key.
window.REGISTRY_DEFAULT_KEYS = [
  "name", "url", "avatar", "description", "email",
  "com.github", "com.twitter", "org.telegram", "role"
];
