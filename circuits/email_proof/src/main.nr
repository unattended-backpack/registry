// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Email Proof
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The Registry's email circuit. Its public inputs are the controller, the chain
  id, and the registry address, in that order, followed by the public outputs
  `registry_email::PUBLIC_OUTPUTS` documents; the on-chain `Verifier` rebuilds
  them in that same order, taking the registry from its caller and the chain
  id from the chain. Everything else, the salt above all, is private.

  @custom:date September 25th, 2026.
*/

use registry_email::{KEY_LIMBS, MAX_HEADER_LENGTH, PUBLIC_OUTPUTS, prove_email, Sequence};

fn main(
    controller: pub Field,
    chain_id: pub Field,
    registry: pub Field,
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    modulus: [u128; KEY_LIMBS],
    redc: [u128; KEY_LIMBS],
    signature: [u128; KEY_LIMBS],
    salt: Field,
    from: Sequence,
    address: Sequence,
    at: u32,
    subject: Sequence,
    dkim: Sequence,
    timestamp_index: u32,
) -> pub [Field; PUBLIC_OUTPUTS] {
    prove_email(
        controller,
        chain_id,
        registry,
        header,
        modulus,
        redc,
        signature,
        salt,
        from,
        address,
        at,
        subject,
        dkim,
        timestamp_index,
    )
}
