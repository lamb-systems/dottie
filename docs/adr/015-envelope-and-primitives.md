# 015 — Snapshot envelope, primitives and signed bytes

Status: accepted, 2026-10-31. The cryptographic half of ADR 014. Amended by the envelope implementation in three
byte-level places, each marked: the format identifier, the genesis parent, and the commitment input.

## Context

A suite name is not a specification. "XChaCha20-Poly1305 and Ed25519" omits nonce sizes, key derivation,
associated data, canonical encoding, key commitment, signer selection and how a wrap binds its
recipient. Two implementations based on that sentence disagree.

An earlier draft bound the associated data to the snapshot record CID. The record contains the blob
reference, creating a cycle: the CID depends on the ciphertext, which would depend on the CID.

XChaCha20-Poly1305 is not key-committing, and this design wraps one content key per recipient. A malicious
publisher could otherwise emit a single ciphertext that authenticates under two different keys and shows
different plaintext to different recipients.

## Decision

Every section below is normative. The primitive list precedes the envelope that depends on it.

## Primitives

This list is closed. Any other primitive requires its own decision record.

| Purpose | Construction |
| --- | --- |
| Content encryption | `golang.org/x/crypto/chacha20poly1305` (not the standard library), AEAD constructed by `chacha20poly1305.NewX`, 192-bit random nonce per message |
| Content signature | `crypto/ed25519` with `ed25519.Options{Context: …}` (Ed25519ctx) and `VerifyWithOptions` |
| Recipient wrapping | `crypto/ecdh` X25519 with `ecdh.X25519()`, ephemeral sender key, then HKDF-SHA256 |
| Hashing and commitment | `crypto/sha256` |
| Key derivation | `crypto/hkdf` with SHA-256, distinct `info` per purpose |
| Randomness | `crypto/rand` only |

An earlier draft reversed two API facts. The standard library **does** support a signature context:
`ed25519.Options.Context` selects Ed25519ctx, so domain separation uses the library rather than a
hand-built prefix. `crypto/ecdh` **does** reject low-order X25519 inputs with an error instead of a zero
secret. The deprecated `ScalarMult` helper does not; it is not used, so an implementation does not
have to add its error path.

Custom constructions, additional modes and hand-rolled KDFs are prohibited. Compression is absent;
a future decoder must enforce a streaming byte cap.

## Envelope

Fields must appear in this order. Reject unknown fields.

| Field | Type | Meaning |
| --- | --- | --- |
| `magic` | 3 bytes | `0x44 0x54 0x45` (`DTE`). **Amended by the envelope implementation** from a bare uint8 `v`. |
| `version` | uint8 | format version, currently `1` |
| `kind` | uint8 | 1 envelope, 2 policy, 3 control, 4 certificate, 5 checkpoint, 6 attestation. Required because an envelope's `purpose` and an object's `kind` would otherwise occupy one byte and be ambiguous. |
| `purpose` | uint8 | `1` snapshot, `2` policy, `3` control, `4` certificate, `5` checkpoint, `6` attestation. Present only when `kind` is 1. |
| `vault` | 32 bytes | vault identifier |
| `publication_id` | 16 bytes | random, allocated before encryption |
| `epoch_seq` | uint64 big-endian | epoch owning the content key |
| `policy_digest` | 32 bytes | digest of the policy the content is valid under |
| `parent` | uint16 length + full CID bytes; length 0 means genesis. **Amended by the envelope implementation** from a one-byte sentinel, because a zero-length field is unambiguous and needs no reserved value. |
| `signer` | `{device_id, key_id}` | the publishing device, inside the signed preimage |
| `commit` | 32 bytes | `SHA-256("dottie/v1/commit" ‖ K ‖ vault ‖ epoch_seq)`. **Amended by the envelope implementation**: binding the vault and epoch stops a key being accepted as a commitment answer in a different context. |
| `recipients` | array, ≤ 64 | `{key_id, ephemeral_pub 32, wrap_nonce 24, wrapped_key}`, sorted by `key_id` |
| `nonce` | 24 bytes | content nonce |
| `ciphertext`, `tag` | bytes | content encryption output |
| `signature` | 64 bytes | Ed25519 over the preimages below |

`publication_id` breaks the cycle by existing before encryption, so nothing authenticated depends on
the ciphertext. The verifier uses `signer` to select the certificate to check; `recipients[].key_id`
names recipients, not the author.

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

Names use ASCII without a terminator. Each preimage starts with its own label, preventing a signature
over one context from being replayed in another even if the encodings collide.

## Key commitment

`commit` appears inside the content associated data. If a recipient's unwrapped key does not hash to
the committed value, authentication fails rather than accepting plaintext chosen for someone else.
The cost is one SHA-256 per envelope.

## Wrapping

For each recipient in each epoch, generate an ephemeral X25519 key pair for that recipient alone.
Reject the shared secret on error, including a low-order input. Wrap the content key with a key derived
by HKDF-SHA256 with `info` = `"dottie/v1/wrap" ‖ vault ‖ key_id ‖ epoch_seq ‖ purpose` and a zero salt.

The wrap AEAD binds the associated data above. A wrap cannot move between recipients, vaults, epochs
or purposes, or be re-pointed at a different ephemeral key.

The recipient's X25519 public key comes from the root-signed certificate, never from a provider
record. This is the constraint in ADR 003: an uploaded key is not approval.

## Snapshot record and record-to-blob binding

The envelope is sealed before the record exists. Binding therefore runs from the signed record to
the blob it names.

The snapshot record carries `v`, `vault`, `publication_id`, `epoch_seq`, `policy_digest`, `parent`,
`blob_cid`, `blob_bytes`, `signer` and the envelope's `signature` digest. Its own signature is Ed25519ctx
over `"dottie/v1/recordsig"` ‖ that field list, using the same device key as the envelope.

Verification requires the record to be present in a verified revision and its signature to verify
against the certificate for its `signer`. Its `publication_id`, `epoch_seq` and `policy_digest` must
match the envelope, and `blob_cid` must resolve to bytes whose envelope signature verifies. Together,
the two signatures bind author, content and location; neither does so alone.

## What is inside the ciphertext

The ciphertext contains everything describing the user's configuration: paths, values, hashes, entry
counts and the plaintext digest carried by the existing snapshot payload. No plaintext-derived value
appears in public metadata. The provider sees only the fields in the envelope table above, each
structural or already public.

## Byte-level contract, deferred to the envelope implementation

The field order, the four preimages and their exclusions are normative here. These byte-level details
are not: exact widths for `device_id` and `key_id`, the concrete Ed25519ctx `Context` strings, the wrap
AEAD choice with its key, output and tag lengths, nonce generation and entropy-failure behaviour, and
the deterministic encoding of the policy object.

Those details belong with their implementation; prose cannot validate them. The envelope
implementation delivers the encodings **together with test vectors** for every signed object and
every digest. Review checks the vectors, not the sentences. Byte specifications without vectors
leave claims that nobody can check.

CIDs for Dottie vault objects—envelopes, policies, controls, certificates, checkpoints, attestations
and heads—are full CIDv1 values using the raw codec and a SHA-256 multihash over the canonical encoded
object bytes, including the CID version, codec and multihash framing; their lengths vary. The CID
addresses those canonical bytes directly: their encoding is already pinned by the canonical-form rules
above, and DAG-CBOR framing would add a second encoding layer without verification value. AT Protocol
repository records are a different object family and remain DAG-CBOR records with DAG-CBOR CIDs. No
field in this envelope is a bare 32-byte digest except the ones that are digests.

## Bounds

The limits remain separate because each fails for a different reason.

| Limit | Value | Enforcement |
| --- | --- | --- |
| Encrypted blob length | provider ceiling and local cap, whichever is smaller | before the upload request, on the final serialized length (ADR 004) |
| Entry plaintext | 256 MiB, the existing `MaxTotalBytes` default | while decoding |
| Decrypted container | 256 MiB plus manifest, tar headers and padding, computed by the envelope implementation | while decoding |
| Encrypted blob | the decrypted container plus envelope overhead, checked against the provider ceiling | before upload |
| Recipients | 64 | before allocation |
| Certificate chain | 3 links | before allocation |
| Lineage depth per check | 4096 records | before allocation |
| Envelope header | 64 KiB | before allocation |
| Decompressed bytes | n/a until compression exists | streaming cap when it does |

Repository proofs have a separate, often-confused budget. A repository CAR carries records and blob
references, not blob payloads. An envelope exceeding the 8 MiB CAR or 4096-record membership budget is
not unverifiable because of its own size; record and membership counts matter there. Those defaults
remain for the read path to revisit.

## Attestation body schema versioning amendment (2026-11-06)

The DTE header version remains the single global wire version `1` for every object kind. The
retention attestation alone has a body schema version because its v2 form adds an ordered list
without changing legacy v1 bytes. V1 attestation bodies retain their existing exact layout and
count-only meaning. A v2 body begins with a big-endian uint16 schema version `2` after the DTE
header, then carries the common attestation fields, the recovery-point count and ordered
`{epoch u64, snapshot_cid uint16+bytes}` entries before control CID and signer. The existing
retained-recovery-point count must equal the v2 list length. The object signature covers the
body discriminator and every v2 field.

Attestation decoding first accepts only a complete exact v1 layout, then attempts the v2 layout;
unknown body versions, malformed lengths, non-canonical point ordering and trailing bytes are
rejected. Re-encoding a decoded v1 attestation emits its original v1 layout, never an implicit
upgrade. This per-object schema version does not change `wireVersion`, the object kind, or any
other DTE encoding.

## Consequences

An unknown DTE `v` is rejected. A downgrade test replays a v0 envelope under a v1 label and expects refusal.

Random 192-bit nonces make reuse vanishingly unlikely, not impossible. The specification states the
probability.

Key material stays in memory or the Secret Service envelope. Error paths must not render keys.
Zeroization is best-effort because the garbage collector may copy.

## Alternatives

A committing AEAD was considered and rejected for now: the commitment field costs one hash and keeps the
primitive list to standard-library parts, while a less common construction would need its own review.

Binding ciphertext to the future record CID was rejected: the record contains the blob, so the CID cannot
exist before the ciphertext.

Sharing one recipient private key across devices was rejected. Removing a device would require
re-encrypting existing content, and no wrap would bind to a specific device. The content key is
intentionally shared but wrapped separately for each recipient, limiting re-encryption to the head
rather than history.
