# 015 — Snapshot envelope, primitives and signed bytes

Status: accepted, 2026-10-31. The cryptographic half of ADR 014. Amended by DOT-V02 in three
byte-level places, each marked: the format identifier, the genesis parent, and the commitment input.

## Context

Naming a suite is not a specification. "XChaCha20-Poly1305 and Ed25519" leaves out nonce sizes, key
derivation, associated data, canonical encoding, key commitment, signer selection and how a wrap binds its
recipient. Two implementations of that sentence disagree.

An earlier draft bound the associated data to the snapshot record CID, but that record contains the blob
reference, so its CID depends on the ciphertext, which would have depended on the CID.

XChaCha20-Poly1305 is not key-committing, and this design wraps one content key per recipient. A malicious
publisher could otherwise emit a single ciphertext that authenticates under two different keys and shows
different plaintext to different recipients.

## Decision

Every section below is normative. The primitive list comes first because the envelope depends on it.

## Primitives

A closed list. Anything outside it needs its own decision record.

| Purpose | Construction |
| --- | --- |
| Content encryption | `golang.org/x/crypto/chacha20poly1305` (not the standard library), AEAD constructed by `chacha20poly1305.NewX`, 192-bit random nonce per message |
| Content signature | `crypto/ed25519` with `ed25519.Options{Context: …}` (Ed25519ctx) and `VerifyWithOptions` |
| Recipient wrapping | `crypto/ecdh` X25519 with `ecdh.X25519()`, ephemeral sender key, then HKDF-SHA256 |
| Hashing and commitment | `crypto/sha256` |
| Key derivation | `crypto/hkdf` with SHA-256, distinct `info` per purpose |
| Randomness | `crypto/rand` only |

Two API facts matter, and an earlier draft got them backwards. The standard library **does** support a
signature context: `ed25519.Options.Context` selects Ed25519ctx, so domain separation uses the library
rather than a hand-built prefix. And `crypto/ecdh` **does** reject low-order X25519 inputs, returning an
error rather than a zero secret; the deprecated `ScalarMult` helper is what does not, so it is not used and
its error path is not something an implementation has to add.

No custom construction, no additional mode, no hand-rolled KDF. Compression is absent; a future decoder
owes a streaming byte cap.

## Envelope

Fields in this order. Unknown fields are rejected.

| Field | Type | Meaning |
| --- | --- | --- |
| `magic` | 3 bytes | `0x44 0x54 0x45` (`DTE`). **Amended by DOT-V02** from a bare uint8 `v`. |
| `version` | uint8 | format version, currently `1` |
| `kind` | uint8 | 1 envelope, 2 policy, 3 control, 4 certificate, 5 checkpoint, 6 attestation. Required because an envelope's `purpose` and an object's `kind` would otherwise occupy one byte and be ambiguous. |
| `purpose` | uint8 | `1` snapshot, `2` policy, `3` control, `4` certificate, `5` checkpoint, `6` attestation. Present only when `kind` is 1. |
| `vault` | 32 bytes | vault identifier |
| `publication_id` | 16 bytes | random, allocated before encryption |
| `epoch_seq` | uint64 big-endian | epoch owning the content key |
| `policy_digest` | 32 bytes | digest of the policy the content is valid under |
| `parent` | uint16 length + full CID bytes; length 0 means genesis. **Amended by DOT-V02** from a one-byte sentinel, because a zero-length field is unambiguous and needs no reserved value. |
| `signer` | `{device_id, key_id}` | the publishing device, inside the signed preimage |
| `commit` | 32 bytes | `SHA-256("dottie/v1/commit" ‖ K ‖ vault ‖ epoch_seq)`. **Amended by DOT-V02**: binding the vault and epoch stops a key being accepted as a commitment answer in a different context. |
| `recipients` | array, ≤ 64 | `{key_id, ephemeral_pub 32, wrap_nonce 24, wrapped_key}`, sorted by `key_id` |
| `nonce` | 24 bytes | content nonce |
| `ciphertext`, `tag` | bytes | content encryption output |
| `signature` | 64 bytes | Ed25519 over the preimages below |

`publication_id` is what breaks the cycle: it exists before encryption, so nothing authenticated depends on
the ciphertext. `signer` is present because a verifier cannot otherwise decide which certificate to check;
`recipients[].key_id` names recipients, not the author.

## Encodings

- Integers are big-endian, fixed width as shown. No variable-length integer may appear in a signed
  preimage.
- Identifiers (`vault`, `publication_id`, digests, CIDs) are their raw binary form, never text.
- Arrays are `uint16 count` followed by elements; elements are concatenated, not tagged.
- `recipients` are sorted ascending by `key_id`, and duplicate `key_id` values are rejected.
- No trailing bytes: a preimage whose length exceeds its declared fields is rejected.

## Preimages

Four distinct preimages, none of which includes its own output:

- **Content associated data**: `"dottie/v1/ad"` ‖ `magic` ‖ `version` ‖ `kind` ‖ `purpose` ‖ `vault` ‖
  `publication_id` ‖ `epoch_seq` ‖ `policy_digest` ‖ `parent` ‖ `commit`. It excludes `nonce`, `ciphertext`, `tag` and
  `signature`, because the tag would otherwise authenticate itself.
- **Signature, every object**: `"dottie/v1/sig"` ‖ the serialized object from its first byte through the last
  byte before the signature. The signature occupies the final 64 bytes of every object, so the preimage is a
  byte range and no field list can omit a field by enumeration error.
- **Policy digest**: `SHA-256("dottie/v1/policy" ‖ deterministic encoding of the policy object)`.
- **Wrap associated data**: `"dottie/v1/wrapad"` ‖ `vault` ‖ `key_id` ‖ `epoch_seq` ‖ `purpose` ‖
  recipient public key ‖ ephemeral public key.

Names are ASCII without a terminator; each preimage begins with its own label, so a signature over one
context cannot be replayed in another even if the encodings collide.

## Key commitment

`commit` appears inside the content associated data. A recipient whose unwrapped key does not hash to the
committed value fails authentication instead of accepting a plaintext chosen for someone else. One SHA-256
per envelope.

## Wrapping

Per recipient and per epoch, an ephemeral X25519 key pair is generated for that recipient alone. The shared
secret is rejected on error, including a low-order input, and the content key is wrapped with a key from
HKDF-SHA256 with `info` = `"dottie/v1/wrap" ‖ vault ‖ key_id ‖ epoch_seq ‖ purpose` and a zero salt.

The wrap AEAD binds the associated data above, so a wrap cannot be moved between recipients, vaults, epochs
or purposes, and cannot be re-pointed at a different ephemeral key.

The recipient's X25519 public key comes from the root-signed certificate. A key read from a provider record
is never used, which is what ADR 003 means when it says an uploaded key is not approval.

## Snapshot record and record-to-blob binding

The envelope is sealed before the record exists, so the binding runs the other way: the record names the
blob, and the record is signed.

The snapshot record carries `v`, `vault`, `publication_id`, `epoch_seq`, `policy_digest`, `parent`,
`blob_cid`, `blob_bytes`, `signer` and the envelope's `signature` digest. Its own signature is Ed25519ctx
over `"dottie/v1/recordsig"` ‖ that field list, using the same device key as the envelope.

Verification is: the record is present in a verified revision, its signature checks against the certificate
for its `signer`, `publication_id`, `epoch_seq` and `policy_digest` match the envelope, and `blob_cid`
resolves to bytes whose envelope signature verifies. The two signatures together bind author, content and
location; neither alone does.

## What is inside the ciphertext

Everything describing the user's configuration: paths, values, hashes, entry counts and the plaintext
digest the existing snapshot payload carries. No plaintext-derived value appears in public metadata. The
only provider-visible fields are those in the envelope table above, each of which is structural or already
public.

## Byte-level contract, deferred to DOT-V02

The field order, the four preimages and their exclusions are normative here. The byte-level details are
not, and this record says so instead of pretending otherwise: exact widths for `device_id` and `key_id`,
the concrete Ed25519ctx `Context` strings, the wrap AEAD choice with its key, output and tag lengths,
nonce generation and entropy-failure behaviour, and the deterministic encoding of the policy object.

Those belong with the code that implements them, because prose cannot validate them. DOT-V02 delivers the
encodings **together with test vectors** for every signed object and every digest, and review of that
task checks the vectors rather than the sentences. A specification that pins bytes without vectors is a
claim nobody can check.

CIDs are full CIDv1 DAG-CBOR SHA-256 values with their version, codec and multihash framing, which vary
in length. No field in this envelope is a bare 32-byte digest except the ones that are digests.

## Bounds

Each limit is separate because they fail for different reasons.

| Limit | Value | Enforcement |
| --- | --- | --- |
| Encrypted blob length | provider ceiling and local cap, whichever is smaller | before the upload request, on the final serialized length (ADR 004) |
| Entry plaintext | 256 MiB, the existing `MaxTotalBytes` default | while decoding |
| Decrypted container | 256 MiB plus manifest, tar headers and padding, computed by DOT-V02 | while decoding |
| Encrypted blob | the decrypted container plus envelope overhead, checked against the provider ceiling | before upload |
| Recipients | 64 | before allocation |
| Certificate chain | 3 links | before allocation |
| Lineage depth per check | 4096 records | before allocation |
| Envelope header | 64 KiB | before allocation |
| Decompressed bytes | n/a until compression exists | streaming cap when it does |

Repository proofs are a separate budget and are often confused with this one. A repository CAR carries
records and blob references, not blob payloads, so an envelope that exceeds the 8 MiB CAR or 4096-record
membership budget is not made unverifiable by its own size; it is the record and membership counts that
matter there, and those are DOT-P03's defaults to revisit.

## Consequences

An unknown `v` is rejected. A downgrade test replays a v0 envelope under a v1 label and expects refusal.

Random 192-bit nonces make reuse vanishingly unlikely, which is a probability rather than an impossibility;
the specification states the probability.

Key material lives in memory or in the Secret Service envelope. Error paths must not render keys, and
zeroization is best-effort because the garbage collector may copy.

## Alternatives

A committing AEAD was considered and rejected for now: the commitment field costs one hash and keeps the
primitive list to standard-library parts, while a less common construction would need its own review.

Binding ciphertext to the future record CID was rejected: the record contains the blob, so the CID cannot
exist before the ciphertext.

Sharing one recipient private key across devices was rejected: removing a device would then require
re-encrypting existing content, and no wrap would bind to a specific device. The content key itself is
shared by design and wrapped separately for each recipient, which is what limits re-encryption to the
head rather than to history.
