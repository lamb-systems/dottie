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
check. The journaled apply path owns re-containment and fresh external-link consent at apply time.

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
the envelope implementation `Seal` encrypts and signs those bytes when a caller supplies the authorization
context and keys. This package does not publish remotely, reconcile, merge or apply data.

## Envelope and signed objects

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
| 03 control | epoch_seq u64; policy_digest[32]; head_snapshot_cid (uint16 length + bytes); revoked count u16 and `{device_id, cert_epoch u64}`; prev_control_cid (uint16 length + bytes) |
| 04 certificate | device_id; key_id; ed25519_pub[32]; x25519_pub[32]; role u8; cert_epoch u64; issuer device_id; revocation_ref (uint16 length + bytes) |
| 05 checkpoint | snapshot_cid (uint16 length + bytes); epoch_seq u64; policy_digest[32]; anchor[32]; control_cid (uint16 length + bytes) |
| 06 attestation | device_id; policy_digest[32]; retention_floor u64; retained_recovery_points u16; control_cid (uint16 length + bytes) |
| 07 head | epoch_seq u64; policy_digest[32]; snapshot_cid (uint16 length + bytes); blob_cid (uint16 length + bytes); publication_count u64; prev_head_cid (uint16 length + bytes) |

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

## Bootstrap and device transitions

Bootstrap is deterministic over its inputs. Device Ed25519 and X25519 keys are generated separately
with `crypto/rand`; `Bootstrap` itself does not use a clock or randomness. A 32-byte recovery kit
and vault name derive the vault identifier. The root device's certificate is self-signed by its
Ed25519 key. The kit-derived signing key signs only the genesis checkpoint, whose `anchor` is the
SHA-256 fingerprint of the root signing public key. Genesis policy and control are root-signed,
and genesis has no snapshot head.

On first use, the operator supplies the kit and treats it as the root of trust:
`RecoveryKitSigningPublicKey` derives the verifier key and `VerifyCheckpoint` checks the
checkpoint's kit signer, key fingerprint and signature. The verified checkpoint's `anchor`
then becomes the `TrustAnchor` used for certificate-chain verification. This is the operator's
assertion that the vault is theirs, not a provider-derived fact. A stolen kit can vouch for an
attacker's root. A checkpoint older than unseen history cannot reveal that missing history;
anything below the pinned anchor is still rejected. Later starts use a checkpoint already held
by the device. `dottie account bootstrap` prints the grouped kit plus vault, anchor, checkpoint
and kit-public-key fingerprints for independent recording. Durable checkpoint storage is
the state store's responsibility; V03 stops at verification.

`PrepareTransition` supports enrollment and revocation. Enrollment binds the authenticated
predecessor's control CID, policy digest, epoch and head CID to a successor root-signed policy,
control, enrollment certificate and head, plus the sealed snapshot bytes and recipient certificate
set. It seals caller-provided packed state for a genesis predecessor, or caller-provided current
plaintext for an existing head, under the successor epoch. Revocation keeps the surviving active
recipient certificates, removes the revoked device from both policy roles and recipients, appends
its certificate epoch to the control's revoked set, and seals the complete current plaintext under
the successor epoch. Revocation emits no certificate. Each transition advances the epoch, resets
the head publication count to zero and binds the control's epoch-start snapshot CID to the new
snapshot. The caller supplies content keys, publication IDs, content nonces and one ephemeral key
and wrap nonce per successor recipient, so the prepared bundle is reproducible without hidden
entropy. The transition digest is SHA-256 over length-delimited policy, control, certificate,
head and snapshot encodings in that order; the certificate slot is empty for revocation. No
private key material is returned.

`PreparePublication` accepts a publisher or root certificate named by the current policy and
seals under the existing epoch and policy. The signed head advances the predecessor count by
exactly one and points to the new snapshot; publication neither changes epoch nor writes control.
The current head and policy are revalidated before the candidate can be committed. A count skip,
repeat, revoked certificate or certificate absent from the policy is refused.

`ValidateTransition` authenticates the predecessor, requires one-step epoch advance and policy
and control ancestry, and verifies the successor signatures. Enrollment must add exactly its
certificate and recipient. Revocation must remove exactly one non-root device from roles and
recipients, preserve all other bindings, list that device and certificate epoch as revoked, and
carry no certificate object. Both transition kinds require the successor head count to be zero,
the snapshot and head to name the same candidate, and the control's epoch-start snapshot CID to
match it. `ValidatePublication` checks the same-epoch policy, active signer certificate,
predecessor head and exact count increment. These checks do not provide transactionality; the
atproto package owns staging, durable attempts and the separate fenced write sets.

Check 7 proves recipient identity binding only: each envelope key ID maps to the certified key
named by policy, with no extras or omissions. It cannot prove that encryption used that recipient's
key correctly without the recipient's private key. Snapshot record schemas and record-to-blob
binding remain the record schemas work; this package prepares encoded signed objects and raw CIDs without
introducing a competing snapshot-record codec.

## Recovery kits and checkpoint verification

A recovery kit is exactly 32 random bytes, rendered as uppercase base32 in groups of four characters. `ParseRecoveryKit` accepts that rendering with hyphens and surrounding whitespace and rejects any value that does not decode to exactly 32 bytes. The vault identifier is derived from the kit and the vault name. The existing kit signing-key derivation is vault-specific; its public-key fingerprint is the kit key ID used by `VerifyCheckpoint`. A verified checkpoint supplies the root signing-key fingerprint (`anchor`); the recovery command cannot print that anchor unless an authenticated checkpoint is supplied. Recovery does not mint a kit: bootstrap is the operation that creates a secret the operator must keep offline.

`VerifyControlState` authenticates the supplied control, its signed policy and certificate chain before it compares freshness. When a local checkpoint is held, it authenticates that control and its separately supplied policy and certificate evidence too. Any signature, key, policy-digest, vault or chain failure is a refusal, not `unverifiable`; consent is not available on that path. `AcceptUnverifiableConsent` can record consent only on a verified result whose outcome offered it.

The five outcomes are checked in this strict precedence: `current` when CIDs match; `descendant` when the supplied control's authenticated predecessor chain reaches the held control; `stale` when the held control's authenticated predecessor chain reaches the supplied control; `conflicting` when both authenticated histories are complete and neither contains the other; and `unverifiable` only when no checkpoint is held, a required intermediate is missing locally, or the walk exceeds its bound. A direct predecessor link is enough; deeper links are followed only through control objects explicitly supplied as local evidence. The walk is capped at eight links, each intermediate is authenticated with its policy and certificate chain, and nothing is fetched. Missing evidence reports `missing-intermediate` and the required CID; depth exhaustion reports `depth-exceeded`. Invalid supplied evidence is refused as `invalid-intermediate`, never downgraded to uncertainty. An epoch number, device count, provider assertion or head snapshot is never used as ancestry proof.

Checkpoint currency is about the control record, not the live head. An ordinary publication advances the head within the epoch and writes no control, so it does not change this verdict. A checkpoint proves only that the kit signed that position; it cannot prove that the provider is serving the newest position the kit ever signed. Local evidence can establish authenticated ancestry but not global freshness, and a malicious provider can still withhold later history. Kit reissue is not implemented; until it is, a compromised kit can re-root the vault. Consent on an unverifiable report does not apply data or advance stored checkpoint state.

`account recovery --vault-name NAME` reads the existing kit from stdin, validates and re-renders it, and prints the derived vault and kit public-key fingerprints. `--checkpoint FILE` optionally supplies the local signed checkpoint whose signature is verified before printing its root anchor fingerprint. The command never generates or stores a replacement kit. `account verify --bundle FILE` consumes one offline JSON bundle with hexadecimal `vault`, `trust_anchor`, and `supplied` control/policy/certificate bytes; optional `held` evidence supplies the policy and certificates for the checkpoint already in local state, and optional `intermediates` supplies authenticated chain objects. The held control bytes are taken from the local checkpoint table and must match the bundle. `--consent` is accepted only for an authenticated `unverifiable` result and permits reporting/inspection/export only; `--record` writes the supplied position only after `current` or `descendant`. Neither command fetches, publishes or applies data.

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
