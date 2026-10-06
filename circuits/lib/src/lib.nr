// SPDX-License-Identifier: LicenseRef-VPL WITH AGPL-3.0-only

/**
  @custom:benediction DEVS BENEDICAT ET PROTEGAT CONTRACTVM MEVM
  @title Registry Email
  @author Tim Clancy <tim-clancy.gwei>
  @custom:terry "Is this too much voodoo for the next ten centuries?"

  The constraints behind a Registry email proof. A proof attests that a DKIM
  key signed an email header from an address at some domain, and that the
  email's subject authorizes a controller for a private profile. It reveals
  the domain, the key's hash, a nullifier, the week the email was signed, and
  the profile id; the address, the subject, and the exact time stay hidden.
  The body is never read, so the circuit hashes only the signed header.

  A private profile is bound to its owner's address and a secret salt only its
  owner holds. The profile id is `sha256(salt || lowercased address)`, which no
  outsider can reverse. The subject must be exactly `Set controller to 0x`
  followed by the lowercase hex of `sha256(tag || controller || chain id ||
  registry || salt)`, a commitment only the salt's holder can open, and the
  circuit checks it without revealing it. The nullifier hashes the DKIM
  signature together with the salt, so nobody holding the email can compute
  it. Because one salt feeds the commitment, the id, and the nullifier, an
  email authorizes exactly one profile.

  The header this circuit consumes is the DKIM signing input: the signed
  header fields in relaxed canonical form, each `name:value` followed by CRLF,
  ending with the DKIM-Signature field itself with its `b=` value emptied and
  no trailing CRLF. Relaxed canonicalization lowercases every field name and
  unfolds every value, so each CRLF in this input ends exactly one field; the
  parsing below leans on that fact throughout.

  @custom:date September 25th, 2026.
*/

use bignum::{params::BigNumParams, RuntimeBigNum};
use noir_rsa::pkcs1v15::verify_sha256_pkcs1v15;
use sha256::sha256_var;
use std::hash::pedersen_hash;

/// The longest signed header the circuit accepts, in bytes.
pub global MAX_HEADER_LENGTH: u32 = 1024;

/// The number of 120-bit limbs in a 2048-bit RSA number.
pub global KEY_LIMBS: u32 = 18;

/// The RSA modulus size in bits. Only 2048-bit DKIM keys are accepted.
pub global KEY_BITS: u32 = 2048;

/// The RSA public exponent every DKIM key in practice uses.
pub global RSA_EXPONENT: u32 = 65537;

/// The longest From field value, display name included, in bytes.
pub global MAX_FROM_LENGTH: u32 = 256;

/// The longest sender address, in bytes.
pub global MAX_ADDRESS_LENGTH: u32 = 128;

/// The longest sender domain, in bytes: three 31-byte fields.
pub global MAX_DOMAIN_LENGTH: u32 = 93;

/// The number of field elements the domain packs into.
pub global DOMAIN_FIELDS: u32 = 3;

/// The subject every email carries: `SUBJECT_PREFIX` and 64 hex characters.
pub global SUBJECT_PREFIX: [u8; 20] = [
    83, 101, 116, 32, 99, 111, 110, 116, 114, 111, 108, 108, 101, 114, 32, 116, 111, 32, 48, 120,
];

/// The subject's exact length in bytes.
pub global SUBJECT_LENGTH: u32 = 84;

/// The domain separation tag of the subject commitment,
/// `registry.set-controller.v1`.
pub global COMMITMENT_TAG: [u8; 26] = [
    114, 101, 103, 105, 115, 116, 114, 121, 46, 115, 101, 116, 45, 99, 111, 110, 116, 114, 111,
    108, 108, 101, 114, 46, 118, 49,
];

/// The length of the commitment preimage: the tag, the controller (20), the
/// chain id (32), the registry (20), and the salt (32).
global COMMITMENT_PREIMAGE_LENGTH: u32 = 26 + 20 + 32 + 20 + 32;

/// The granularity of the revealed timestamp: one week, in seconds. The
/// circuit reveals the DKIM timestamp rounded down to a multiple of it.
pub global WEEK: u64 = 604800;

/// The longest DKIM-Signature field value, in bytes, with `b=` emptied.
pub global MAX_DKIM_LENGTH: u32 = 512;

/// The number of decimal digits in a DKIM `t=` timestamp. Ten digits cover
/// every second from September 2001 to November 2286.
pub global TIMESTAMP_DIGITS: u32 = 10;

/// The number of public outputs, in order: the domain (3), the DKIM key hash
/// (1), the salted email nullifier (1), the week-rounded timestamp (1), and
/// the profile id as high and low 128-bit halves (2). They follow the three
/// public inputs: the controller, the chain id, and the registry.
pub global PUBLIC_OUTPUTS: u32 = 8;

global CR: u8 = 13;
global LF: u8 = 10;
global SPACE: u8 = 32;
global COLON: u8 = 58;
global SEMICOLON: u8 = 59;
global LESS_THAN: u8 = 60;
global EQUALS: u8 = 61;
global GREATER_THAN: u8 = 62;
global AT: u8 = 64;

/// A run of bytes in the header: where it starts and how long it is.
pub struct Sequence {
    pub index: u32,
    pub length: u32,
}

impl Sequence {
    /// The index one past the run's last byte.
    pub fn end(self) -> u32 {
        self.index + self.length
    }
}

/**
  Hash a DKIM public key: the Pedersen hash of its modulus limbs. This is the
  value management honors in the Registry for a domain's current key.

  Only the modulus is hashed. The Barrett reduction parameter the circuit also
  takes is a witness-generation aid: in this bignum version an incorrect value
  only derails unconstrained witness computation, and cannot make a false
  signature verify. Do not add it to the hash.

  The modulus is validated to be exactly 2048 bits, limb by limb.
*/
pub fn dkim_key_hash(modulus: [u128; KEY_LIMBS]) -> Field {
    let _params: BigNumParams<KEY_LIMBS, KEY_BITS> =
        BigNumParams::new(false, modulus, [0; KEY_LIMBS]);
    pedersen_hash(modulus.map(|limb: u128| limb as Field))
}

/**
  Constrain `field` to be one whole header field named `name`: it starts a
  line, it ends a line (or the header), its name matches, a colon follows the
  name, and its value holds no CR. Returns the index of the value's first byte.
*/
fn constrain_field<let NAME_LENGTH: u32, let MAX_VALUE_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    field: Sequence,
    name: [u8; NAME_LENGTH],
) -> u32 {
    let end = field.end();
    assert(end <= header.len(), "Field extends past the header");

    // The field starts the header or follows a CRLF.
    if field.index != 0 {
        assert(header.get_unchecked(field.index - 2) == CR, "Field must follow CRLF");
        assert(header.get_unchecked(field.index - 1) == LF, "Field must follow CRLF");
    }

    // The field ends the header or precedes a CRLF inside the header.
    if end != header.len() {
        assert(end + 2 <= header.len(), "Field must precede CRLF");
        assert(header.get_unchecked(end) == CR, "Field must precede CRLF");
        assert(header.get_unchecked(end + 1) == LF, "Field must precede CRLF");
    }

    // The name matches exactly and a colon follows it.
    for i in 0..NAME_LENGTH {
        assert(header.get_unchecked(field.index + i) == name[i], "Field name mismatch");
    }
    assert(header.get_unchecked(field.index + NAME_LENGTH) == COLON, "Field name needs a colon");

    // The value is one unbroken line.
    let value_start = field.index + NAME_LENGTH + 1;
    let value_length = field.length - (NAME_LENGTH + 1);
    assert(value_length <= MAX_VALUE_LENGTH, "Field value too long");
    for i in 0..MAX_VALUE_LENGTH {
        if i < value_length {
            assert(header.get_unchecked(value_start + i) != CR, "Field value holds a CR");
        }
    }
    value_start
}

/// Whether a lowercased byte may appear in a sender address.
fn is_address_byte(b: u8) -> bool {
    let lower = (b >= 97) & (b <= 122);
    let digit = (b >= 48) & (b <= 57);
    let punctuation = (b == 46) | (b == 45) | (b == 95) | (b == 43) | (b == 39);
    lower | digit | punctuation | (b == AT)
}

/**
  Extract the sender address from the From field, lowercased. The address is
  either the whole field value, or, when the value holds a `<`, exactly the
  run between the last `<` and a `>` that ends the value. The address holds
  exactly one `@`, at `at` (an offset into the address), with at least one
  byte on each side.

  Returns the lowercased address and the offset of its `@`.
*/
fn sender_address(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    from: Sequence,
    address: Sequence,
    at: u32,
) -> (BoundedVec<u8, MAX_ADDRESS_LENGTH>, u32) {
    let from_name: [u8; 4] = comptime { "from".as_bytes() };
    let value_start = constrain_field::<4, MAX_FROM_LENGTH>(header, from, from_name);
    let value_length = from.length - 5;

    // Find the last `<` in the value, if any.
    let mut has_bracket = false;
    let mut last_bracket: u32 = 0;
    for i in 0..MAX_FROM_LENGTH {
        if i < value_length {
            if header.get_unchecked(value_start + i) == LESS_THAN {
                has_bracket = true;
                last_bracket = value_start + i;
            }
        }
    }

    // Pin the address to the bracket, or to the whole value.
    if has_bracket {
        assert(address.index == last_bracket + 1, "Address must follow the last '<'");
        assert(address.end() + 1 == from.end(), "Address must end the field before '>'");
        assert(header.get_unchecked(address.end()) == GREATER_THAN, "Address must close with '>'");
    } else {
        assert(address.index == value_start, "Address must be the whole field value");
        assert(address.end() == from.end(), "Address must be the whole field value");
    }
    assert(address.length <= MAX_ADDRESS_LENGTH, "Address too long");

    // Copy and lowercase the address, checking every byte and counting `@`.
    let mut storage: [u8; MAX_ADDRESS_LENGTH] = [0; MAX_ADDRESS_LENGTH];
    let mut at_count: u32 = 0;
    for i in 0..MAX_ADDRESS_LENGTH {
        if i < address.length {
            let b = header.get_unchecked(address.index + i);
            let lowered = if (b >= 65) & (b <= 90) { b + 32 } else { b };
            assert(is_address_byte(lowered), "Address holds a disallowed byte");
            if lowered == AT {
                at_count += 1;
            }
            storage[i] = lowered;
        }
    }
    assert(at_count == 1, "Address must hold exactly one '@'");
    assert(at >= 1, "Address needs a local part");
    assert(at + 1 < address.length, "Address needs a domain");
    assert(storage[at] == AT, "Address '@' is not at the claimed offset");

    (BoundedVec::from_parts_unchecked(storage, address.length), at)
}

/**
  Read the DKIM `t=` timestamp from the DKIM-Signature field. The field must
  end the header, which makes it the verified signature's own field. The tag
  must open at a tag boundary (after `;` or `; `), hold exactly ten digits,
  and close with `;`.
*/
fn dkim_timestamp(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    dkim: Sequence,
    timestamp_index: u32,
) -> Field {
    let dkim_name: [u8; 14] = comptime { "dkim-signature".as_bytes() };
    let value_start = constrain_field::<14, MAX_DKIM_LENGTH>(header, dkim, dkim_name);
    assert(dkim.end() == header.len(), "DKIM-Signature must end the header");

    // The tag opens at a tag boundary.
    assert(timestamp_index >= value_start + 3, "Timestamp tag out of the field");
    assert(header.get_unchecked(timestamp_index - 1) == EQUALS, "Timestamp tag must be 't='");
    assert(header.get_unchecked(timestamp_index - 2) == 116, "Timestamp tag must be 't='");
    let before = header.get_unchecked(timestamp_index - 3);
    let adjacent = before == SEMICOLON;
    let spaced = (before == SPACE) & (header.get_unchecked(timestamp_index - 4) == SEMICOLON);
    assert(adjacent | spaced, "Timestamp tag must open after ';'");

    // Exactly ten digits, then `;`, all inside the field.
    assert(timestamp_index + TIMESTAMP_DIGITS < dkim.end(), "Timestamp runs past the field");
    let mut timestamp: Field = 0;
    for i in 0..TIMESTAMP_DIGITS {
        let digit = header.get_unchecked(timestamp_index + i);
        assert((digit >= 48) & (digit <= 57), "Timestamp must be decimal digits");
        timestamp = timestamp * 10 + (digit - 48) as Field;
    }
    assert(
        header.get_unchecked(timestamp_index + TIMESTAMP_DIGITS) == SEMICOLON,
        "Timestamp must close with ';'",
    );
    timestamp
}

/// Pack bytes into big-endian 31-byte field elements.
fn pack<let N: u32, let FIELDS: u32>(bytes: [u8; N]) -> [Field; FIELDS] {
    assert(N == FIELDS * 31, "Packing needs whole 31-byte fields");
    let mut out: [Field; FIELDS] = [0; FIELDS];
    for i in 0..FIELDS {
        let mut acc: Field = 0;
        for j in 0..31 {
            acc = acc * 256 + bytes[i * 31 + j] as Field;
        }
        out[i] = acc;
    }
    out
}

/// Split 32 big-endian bytes into high and low 128-bit field elements.
fn split_hash(hash: [u8; 32]) -> (Field, Field) {
    let mut high: Field = 0;
    let mut low: Field = 0;
    for i in 0..16 {
        high = high * 256 + hash[i] as Field;
        low = low * 256 + hash[16 + i] as Field;
    }
    (high, low)
}

/// Render 32 bytes as 64 lowercase hex characters.
fn to_hex(bytes: [u8; 32]) -> [u8; 64] {
    let mut out: [u8; 64] = [0; 64];
    for i in 0..32 {
        let high = bytes[i] >> 4;
        let low = bytes[i] & 15;
        out[2 * i] = if high < 10 { high + 48 } else { high + 87 };
        out[2 * i + 1] = if low < 10 { low + 48 } else { low + 87 };
    }
    out
}

/**
  The subject commitment: the SHA-256 of the tag, the controller, the chain
  id, the registry, and the salt. `to_be_bytes::<20>` also constrains the
  controller and the registry to be 160-bit addresses.
*/
pub fn subject_commitment(controller: Field, chain_id: Field, registry: Field, salt: Field) -> [u8; 32] {
    let controller_bytes: [u8; 20] = controller.to_be_bytes();
    let chain_bytes: [u8; 32] = chain_id.to_be_bytes();
    let registry_bytes: [u8; 20] = registry.to_be_bytes();
    let salt_bytes: [u8; 32] = salt.to_be_bytes();
    let mut preimage: [u8; COMMITMENT_PREIMAGE_LENGTH] = [0; COMMITMENT_PREIMAGE_LENGTH];
    for i in 0..26 {
        preimage[i] = COMMITMENT_TAG[i];
    }
    for i in 0..20 {
        preimage[26 + i] = controller_bytes[i];
        preimage[78 + i] = registry_bytes[i];
    }
    for i in 0..32 {
        preimage[46 + i] = chain_bytes[i];
        preimage[98 + i] = salt_bytes[i];
    }
    sha256::digest(preimage)
}

/**
  Constrain the subject field to be exactly the subject authorizing
  `commitment`: the prefix, then the commitment in lowercase hex, and nothing
  else. A reply or a forward prefixes the subject and fails.
*/
fn constrain_subject(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    subject: Sequence,
    commitment: [u8; 32],
) {
    let subject_name: [u8; 7] = comptime { "subject".as_bytes() };
    let start = constrain_field::<7, SUBJECT_LENGTH>(header, subject, subject_name);
    assert(subject.length == 8 + SUBJECT_LENGTH, "Subject is not a controller authorization");
    let hex = to_hex(commitment);
    for i in 0..20 {
        assert(header.get_unchecked(start + i) == SUBJECT_PREFIX[i], "Subject prefix mismatch");
    }
    for i in 0..64 {
        assert(header.get_unchecked(start + 20 + i) == hex[i], "Subject commitment mismatch");
    }
}

/**
  The private profile id: the SHA-256 of the salt (32 bytes, big-endian)
  followed by the lowercased sender address.
*/
fn profile_id(sender: BoundedVec<u8, MAX_ADDRESS_LENGTH>, salt: Field) -> [u8; 32] {
    let salt_bytes: [u8; 32] = salt.to_be_bytes();
    let mut preimage: [u8; 32 + MAX_ADDRESS_LENGTH] = [0; 32 + MAX_ADDRESS_LENGTH];
    for i in 0..32 {
        preimage[i] = salt_bytes[i];
    }
    for i in 0..MAX_ADDRESS_LENGTH {
        if i < sender.len() {
            preimage[32 + i] = sender.get_unchecked(i);
        }
    }
    sha256_var(preimage, 32 + sender.len())
}

/**
  Prove a Registry email. Verifies the DKIM signature over the signed header,
  checks that the subject authorizes `controller` on `registry` at `chain_id`
  for the profile `salt` defines, and returns the public outputs in the order
  `PUBLIC_OUTPUTS` documents:

  - the sender's domain, lowercased, packed into three fields;
  - the Pedersen hash of the DKIM key modulus (see `dkim_key_hash`);
  - the email nullifier, the Pedersen hash of the signature limbs and the salt;
  - the DKIM `t=` timestamp, rounded down to a multiple of `WEEK`;
  - the profile id, as high and low 128-bit halves.

  The domain packing is nonzero inside its length and zero after it, so it is
  never ambiguous about where the domain ends.
*/
pub fn prove_email(
    controller: Field,
    chain_id: Field,
    registry: Field,
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
) -> [Field; PUBLIC_OUTPUTS] {
    // Verify the DKIM signature over the signed header. The signature must be
    // below the modulus, or `s` and `s + n` would verify alike and yield two
    // nullifiers for one email.
    let header_hash = sha256_var(header.storage(), header.len());
    let params: BigNumParams<KEY_LIMBS, KEY_BITS> = BigNumParams::new(false, modulus, redc);
    let sig: RuntimeBigNum<KEY_LIMBS, KEY_BITS> = RuntimeBigNum::from_array(params, signature);
    sig.validate_in_field();
    assert(verify_sha256_pkcs1v15(header_hash, sig, RSA_EXPONENT), "DKIM signature invalid");

    // The subject authorizes this controller, here, for this profile.
    constrain_subject(header, subject, subject_commitment(controller, chain_id, registry, salt));

    // The sender and its domain.
    let (sender, at_offset) = sender_address(header, from, address, at);
    let domain_length = sender.len() - at_offset - 1;
    assert(domain_length <= MAX_DOMAIN_LENGTH, "Domain too long");
    let mut domain: [u8; MAX_DOMAIN_LENGTH] = [0; MAX_DOMAIN_LENGTH];
    for i in 0..MAX_DOMAIN_LENGTH {
        if i < domain_length {
            domain[i] = sender.get_unchecked(at_offset + 1 + i);
        }
    }

    // The week-rounded timestamp, the key hash, the salted nullifier, and the
    // profile id.
    let timestamp = dkim_timestamp(header, dkim, timestamp_index);
    let week = ((timestamp as u64) / WEEK) * WEEK;
    let key_hash = dkim_key_hash(modulus);
    let mut nullifier_preimage: [Field; KEY_LIMBS + 1] = [0; KEY_LIMBS + 1];
    for i in 0..KEY_LIMBS {
        nullifier_preimage[i] = signature[i] as Field;
    }
    nullifier_preimage[KEY_LIMBS] = salt;
    let nullifier = pedersen_hash(nullifier_preimage);
    let (id_high, id_low) = split_hash(profile_id(sender, salt));

    let domain_fields: [Field; DOMAIN_FIELDS] = pack(domain);
    let mut out: [Field; PUBLIC_OUTPUTS] = [0; PUBLIC_OUTPUTS];
    for i in 0..DOMAIN_FIELDS {
        out[i] = domain_fields[i];
    }
    out[3] = key_hash;
    out[4] = nullifier;
    out[5] = week as Field;
    out[6] = id_high;
    out[7] = id_low;
    out
}
