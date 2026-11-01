# Bounded portable snapshots

`Pack` and `Unpack` encode complete `model.Snapshot` values in a deterministic, uncompressed
USTAR container. The manifest carries the snapshot version, codec (`none`), complete target
records and a lossless wire entry for each file or GSettings entry. Tar member names are
opaque six-digit ordinals: `000000` is the manifest and later ordinals identify entries in
canonical order. Logical paths and symlink targets remain in the manifest. All tar records
use a pinned regular-file header; PAX/GNU extensions, other record types, non-ordinal names
and trailing data are rejected.

`Pack` accepts an already-reconciled desired snapshot. Omitted paths stay omitted; packing
does not observe a filesystem or invent tombstones. Explicit deleted entries remain
tombstones. `Estimate` reports plaintext bytes by target in target-id order and identifies
relative symlink targets that lexically escape the selected root. `Unpack` returns only an
in-memory snapshot; this package has no extraction API and performs no symlink containment
check. DOT-L10 owns re-containment and fresh external-link consent at apply time.

Default bounds are aligned with filesystem capture where applicable:

| Bound | Default |
| --- | ---: |
| Entries | 20,000 |
| Relative nesting depth (`.` is depth 0) | 32 |
| One payload member | 8 MiB |
| Total payload bytes | 256 MiB |
| Manifest | 16 MiB |
| Path | 4,096 bytes |

`PackWithLimits`, `UnpackWithLimits` and `EstimateWithLimits` allow callers and tests to
apply a tighter `Limits` set. Any exceeded bound returns `*BoundError` with its kind, path,
limit and observed value; no partial snapshot is returned. Unpack rejects oversized tar
header declarations before allocating a body, reads each body through a size-limited reader,
and counts bytes actually read.

Per-entry SHA-256 values and the whole-container digest detect accidental corruption and
truncation. These digests are integrity-only, not authenticity. `Pack` returns plaintext;
DOT-V02 `Seal` encrypts and signs those bytes when a caller supplies the authorization
context and keys. This package does not publish remotely, reconcile, merge or apply data.

## DOT-V02 envelope and signed objects

Every integer is big-endian. `DTE` is the three-byte ASCII prefix `44 54 45`; version is
`01`. The kind byte is `01` envelope, `02` policy, `03` control, `04` certificate,
`05` checkpoint or `06` attestation. An unknown prefix or kind is `ErrFormat`; a DTE
prefix with an unsupported version is `ErrUnsupportedVersion`.

An envelope starts with `DTE | version | kind | purpose | vault[32]`. Purpose values are
`01` snapshot, `02` policy, `03` control, `04` certificate, `05` checkpoint and `06`
attestation. Its remaining byte layout is:

| Field | Encoding |
| --- | --- |
| publication_id | 16 bytes |
| epoch_seq | uint64 |
| policy_digest | 32 bytes |
| parent | uint16 length, bytes; zero length is genesis |
| device_id | uint16 UTF-8 byte length, bytes |
| signer key_id | uint16 length, bytes |
| commit | 32 bytes |
| recipients | uint16 count; each has key_id (uint16 length + bytes), ephemeral public key (32), wrap nonce (24), wrapped key (uint16 length + bytes) |
| content nonce | 24 bytes |
| ciphertext_len | uint32 |
| ciphertext | ciphertext_len bytes |
| tag | 16 bytes |
| signature | 64 bytes |

Recipient entries are strictly ascending by the raw key_id bytes; duplicates and out-of-order
entries are rejected. The envelope signature preimage ends at the final tag byte, so it covers
the ciphertext length and all preceding serialized fields. Trailing bytes are rejected.

Administrative objects start `DTE | version | kind | vault[32]`; each ends with signer
(device_id then key_id, each uint16 length plus bytes) and a 64-byte signature. Their field
order between the vault and signer is:

| Kind/object | Fields in order |
| --- | --- |
| 02 policy | epoch_seq u64; roles count u16 and `{device_id, role u8}`; recipients count u16 and `{device_id, key_id, x25519_pub[32]}`; policy_retention_floor u64; retained_recovery_points u16; max_publications u32; max_epoch_age u32; recovery_anchor[32]; prev_policy_digest[32] |
| 03 control | epoch_seq u64; policy_digest[32]; head_snapshot_cid (uint16 length + bytes); publication_count u64; revoked count u16 and `{device_id, cert_epoch u64}`; prev_control_cid (uint16 length + bytes) |
| 04 certificate | device_id; key_id; ed25519_pub[32]; x25519_pub[32]; role u8; cert_epoch u64; issuer device_id; revocation_ref (uint16 length + bytes) |
| 05 checkpoint | snapshot_cid (uint16 length + bytes); epoch_seq u64; policy_digest[32]; control_cid (uint16 length + bytes) |
| 06 attestation | device_id; policy_digest[32]; retention_floor u64; retained_recovery_points u16; control_cid (uint16 length + bytes) |

All variable byte fields use uint16 length prefixes; strings are UTF-8 bytes without a
terminator. Arrays use uint16 counts. Vault identifiers, digests and public keys are raw
bytes. Parent/CID fields are capped at 128 bytes and device_id/key_id at 255 bytes. Policy
and other administrative objects are capped at 64 KiB. Envelope decoding is capped at
384 MiB total, 320 MiB ciphertext and 64 recipients. Decoders first validate all lengths,
counts, order, version/kind and trailing-data conditions without allocating decoded fields,
then allocate and decode.

The only role values are `01` root, `02` publisher and `03` restore_only. Any other role is
rejected. Object encoding and decoding define bytes only; they do not authorize transitions.

### Preimages and contexts

| Purpose | Preimage or derivation |
| --- | --- |
| Envelope signature | `dottie/v1/sig || serialized envelope[0:end of tag]` |
| Administrative signature | `dottie/v1/sig || serialized object[0:before signature]` |
| Content AD | `dottie/v1/ad || DTE || version || envelope kind || purpose || vault || publication_id || epoch_seq || policy_digest || parent(uint16+bytes) || commit` |
| Wrap AD | `dottie/v1/wrapad || vault || key_id(uint16+bytes) || epoch_seq || purpose || recipient_pub[32] || ephemeral_pub[32]` |
| Commitment | `SHA-256(dottie/v1/commit || content_key || vault || epoch_seq)` |
| Wrap key | HKDF-SHA256, nil salt, 32 bytes; info is `dottie/v1/wrap || vault || key_id(uint16+bytes) || epoch_seq || purpose` |
| Policy digest | `SHA-256(dottie/v1/policy || final serialized policy object including its signature)` |

Ed25519ctx contexts are exact and include no terminator:

| Signed bytes | Context |
| --- | --- |
| Snapshot envelope | `dottie/v1/sig-snapshot` |
| Snapshot record | `dottie/v1/sig-record` |
| Policy | `dottie/v1/sig-policy` |
| Control | `dottie/v1/sig-control` |
| Certificate | `dottie/v1/sig-certificate` |
| Checkpoint | `dottie/v1/sig-checkpoint` |
| Attestation | `dottie/v1/sig-attestation` |

The envelope context follows its purpose, including for policy/control/certificate/checkpoint/
attestation envelopes. Changing purpose changes both associated data and signature context.
X25519 errors, including low-order peer keys, abort sealing or opening. XChaCha20-Poly1305
(NewX) protects content and wrapped content keys. `OpenRequest.TrustAnchor` is the
SHA-256 fingerprint of the trusted root certificate's Ed25519 public key. An empty
`OpenRequest.Control` skips the revocation check: the caller is asserting freshness and
revocation state out of band, and `Open` does not establish either.

### Open verification order

`Open` returns no plaintext unless all checks succeed, in this order:

1. Accept the envelope magic, kind and purpose; reject unknown values.
2. Validate every declared length, count, recipient ordering and total cap in a no-allocation
   pass; reject truncation and trailing bytes.
3. Require the caller-supplied policy. Decode it, require its vault to equal the caller's
   expected vault, and match its digest to the envelope. Resolve the policy signer through
   the caller-supplied certificate set and verify the policy-context signature. Resolve the
   envelope signer certificate by `(device_id, key_id)`, verify its certificate chain, then
   require the policy-assigned role to agree with the certificate and permit this purpose;
   the policy signer must be root. A valid chain with a mismatching policy, control or
   envelope signature returns `ErrSignature`. The chain is bounded to three certificates; each certificate's issuer resolves to exactly
   one certificate by device_id, each signature verifies under the issuer certificate, and
   the chain terminates at a self-signed root whose Ed25519 public-key SHA-256 equals
   `OpenRequest.TrustAnchor`. Missing, ambiguous, wrong-vault, invalid-signature or
   unanchored certificate chains are `ErrAuthorization`; the caller-supplied trust anchor is
   the one external trust value. If `OpenRequest.Control` is present, decode it; require
   matching vault and epoch, resolve its signer through the same chain to a root certificate,
   verify its control-context signature, and match its policy digest to the caller's expected
   digest. Only then check whether the envelope signer is revoked: an entry for the same
   device revokes the certificate when the entry's `cert_epoch` is greater than or equal to
   the certificate's `cert_epoch`. A later reissued certificate is not revoked by an older
   entry. Missing policy is `ErrPolicyRequired`; failed authorization is `ErrAuthorization`.
4. Require the envelope vault, epoch_seq and policy_digest to equal caller expectations.
5. Verify the envelope signature using the matched certificate key and purpose-specific
   Ed25519ctx context.
6. Find the caller's DeviceKeyID in recipients and require that key id and X25519 public key
   to match a policy recipient.
7. Perform X25519, derive the wrap key, and authenticate/decrypt the wrapped content key.
8. Recompute and compare the commitment before decrypting content.
9. Authenticate/decrypt content with XChaCha20-Poly1305 and the content associated data.

Failures return typed `ErrFormat`, `ErrUnsupportedVersion`, `ErrLimit`, `ErrRecipient`,
`ErrPolicyRequired`, `ErrAuthorization`, `ErrSignature`, `ErrCommitment` or
`ErrAuthentication` errors. Error text identifies a field, never secret material or an
identifier value.

### Sender obligations

A sender allocates publication_id before encryption, uses the exact caller-authorized vault,
epoch, policy digest, parent and purpose, and encrypts the complete `Pack` output. It supplies
one fresh ephemeral X25519 key and wrap nonce for every authorized recipient, rejects duplicate
key ids, and aborts the whole operation on any key or entropy failure rather than emitting an
envelope that some recipients cannot open. It uses a fresh content key and content nonce from
`crypto/rand`, commits to that key and context, and returns only a fully signed envelope.
Recipient keys must be the policy-authorized certificate keys; the signer must be authorized
for the selected purpose. `SealPrepared` has the same invariants and is intended for fixed-key
test vectors, not production entropy handling.

### Current-format test vectors

The lowercase-hex vectors in `testdata/` are current version-1 examples; they are not
historical fossils. `envelope-one-recipient-chain.hex` and
`envelope-many-recipients-chain.hex` are deterministic `SealPrepared` outputs with fixed
content, ephemeral, nonce and signing keys. They are verified with the separate
`certificate-root-self-signed.hex` and `certificate-publisher-root-issued-chain.hex` values:
the root signs its own certificate, issues the publisher certificate, and the publisher signs
the envelopes. `policy-root-signed-chain.hex` is the one-recipient policy;
`policy-many-recipients-root-signed-chain.hex` authorizes the two-recipient envelope.
`control-root-signed-chain.hex`,
`checkpoint-root-signed-chain.hex` and `attestation-root-signed-chain.hex` are fixed-key
signed-object examples. `kind-ambiguity.hex` is a structural negative vector that parses as
an envelope and, when the kind check is ignored, as a checkpoint body. The regeneration test
rebuilds each vector and compares exact bytes without overwriting existing files.

## Size measurements

Measurements use the canonical `codec = none` archive. The synthetic tree contains one
`config/` directory and the specified number of files, each with deterministic 256-byte
content; the large-file case contains one 4 MiB file and its parent directory. Packed sizes
include the manifest, tar headers and padding. The gzip column is a standard-library
measurement only; no compressed codec is implemented or emitted.

| Tree | Entries | Plaintext payload | Uncompressed blob | Gzip reference |
| --- | ---: | ---: | ---: | ---: |
| `tests/testdata/neovim` fixture | 8 | 388 B | 9,728 B | 984 B |
| Synthetic, 1,000 files | 1,001 | 256,000 B | 1,239,552 B | 23,281 B |
| Synthetic, one 4 MiB file | 2 | 4,194,304 B | 4,197,888 B | 8,683 B |

The committed golden fixture pins exact uncompressed archive bytes. The gzip comparison is
informational only; this lane adds no compression dependency and keeps the codec `none`.
