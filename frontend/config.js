// Registry frontend configuration.
//
// This file is the deployment the site serves. It ships as plain data with no
// build step, so it can be changed in place before pinning the directory to
// IPFS or any static host. Nothing here can be changed from the page: a
// visitor only supplies the RPC endpoint they read through, which stays in
// their browser.

window.REGISTRY_CONFIG = {

  // The chain the Registry is deployed on: Sepolia. The page refuses an RPC
  // that serves any other chain.
  chainId: 11155111,

  // The Registry contract address, verified on Etherscan. Replace it,
  // `chainId`, and `deployBlock` with the mainnet deployment once it exists.
  registryAddress: "0xB3aBD4C3D27B071641A963a5539C48B2cA167778",

  // The block the Registry was deployed in. Browsing reads every record key
  // from the Registry's logs from this block onward, so a later block misses
  // records and an earlier one only costs time.
  deployBlock: 11853053,

  // The email domain the Registry gates on.
  domain: "ethereum.org",

  // The domain's DKIM public keys, by selector, exactly as published in DNS at
  // <selector>._domainkey.<domain>. The prover reads the key from here rather
  // than from DNS, so proving touches no network. Keep this current as the
  // domain rotates keys (`dig TXT gmail._domainkey.ethereum.org`): an email
  // signed under a selector missing here cannot be proven on this site. The
  // key only has to be right for the proof to verify; the Registry itself
  // decides which keys it honors.
  dkimKeys: {
    gmail: "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiNR/XTAsSgOco2TO6oCjG8RNQS4duadA9fkqPeEVdeu58BGNJjMi90TxVh16vi5PLjRN+pHVvUornY8SXLJH3ntd/ItctOKmhmJmYcKB5EVNpA79Uxc1QVX8/FTGHlB31znv/26Ns80VkkmhJoZG4InbiyBj8oW2H9DyE1q77V8qthq+CUbkmQbQt8PA+EqAd5aK2LGVICIrYbrepq5tORFkUgO+S8L2+K5bPeWfCQhZ/TQgcggym5JxkNXDC1V/Zdr1e5KRsY77ki0sB+18P332gl/qieN0ojZ+7sTQVezk0zXwI2/IpCx70gwTE3AkiSGic69dSzmpvj43ZehwLwIDAQAB"
  }
};
