// The Registry ABI, in ethers human-readable form, and the EIP-712 types the
// controller signs. Only the functions this frontend calls are listed.

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
  "function commandBinding() view returns (string)",
  "function setControllerCommand(address) view returns (string)",
  "function authorizationDigest(bytes32 emailNullifier) view returns (bytes32)",
  "function setTextDigest(bytes32 profileId, string key, string value) view returns (bytes32)",

  // Writes. The EmailProof tuple mirrors the on-chain struct field for field.
  "function register((string domainName, bytes32 publicKeyHash, uint256 timestamp, string maskedCommand, bytes32 emailNullifier, bytes32 accountSalt, bool isCodeExist, bytes proof) proof, address controller)",
  "function setController((string domainName, bytes32 publicKeyHash, uint256 timestamp, string maskedCommand, bytes32 emailNullifier, bytes32 accountSalt, bool isCodeExist, bytes proof) proof, address controller, bytes signature)",
  "function setText(bytes32 profileId, string key, string value)",
  "function setTextSigned(bytes32 profileId, string key, string value, bytes signature)",

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
  }
};

// The text-record keys the browser shows by default when resolving a profile.
// Records are an open key-value space; this is only the set fetched eagerly.
window.REGISTRY_DEFAULT_KEYS = [
  "name", "url", "avatar", "description", "email",
  "com.github", "com.twitter", "org.telegram", "role"
];
