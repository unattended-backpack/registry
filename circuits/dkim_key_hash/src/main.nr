// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title DKIM Key Hash
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  Compute the hash management honors in the Registry for a DKIM key. This is
  never proven; it is executed, so the value management submits comes from the
  very function the email circuit runs, with no second implementation to
  drift from it.

  @custom:date September 25th, 2026.
*/

use registry_email::{dkim_key_hash, KEY_LIMBS};

fn main(modulus: [u128; KEY_LIMBS]) -> pub Field {
    dkim_key_hash(modulus)
}
