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

Default bounds match filesystem capture where applicable:

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
truncation. These digests establish integrity, not authenticity. `Pack` returns plaintext;
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

Recipient entries follow strictly ascending raw key_id byte order; duplicates and out-of-order
entries are rejected. The envelope signature preimage ends at the final tag byte, so it covers
the ciphertext length and all preceding serialized fields. Trailing bytes are rejected.

Administrative objects start `DTE | version | kind | vault[32]`; each ends with signer
(device_id then key_id, each uint16 length plus bytes) and a 64-byte signature. Between the vault and signer, fields appear in this
order:

| Kind/object | Fields in order |
| --- | --- |
| 02 policy | epoch_seq u64; roles count u16 and `{device_id, role u8}`; recipients count u16 and `{device_id, key_id, x25519_pub[32]}`; policy_retention_floor u64; retained_recovery_points u16; max_publications u32; max_epoch_age u32; recovery_anchor[32]; prev_policy_digest[32] |
| 03 control | epoch_seq u64; policy_digest[32]; head_snapshot_cid (uint16 length + bytes); revoked count u16 and `{device_id, cert_epoch u64}`; prev_control_cid (uint16 length + bytes) |
| 04 certificate | device_id; key_id; ed25519_pub[32]; x25519_pub[32]; role u8; cert_epoch u64; issuer device_id; revocation_ref (uint16 length + bytes) |
| 05 checkpoint | snapshot_cid (uint16 length + bytes); epoch_seq u64; policy_digest[32]; anchor[32]; control_cid (uint16 length + bytes) |
| 06 attestation | V1 body: device_id; policy_digest[32]; retention_floor u64; retained_recovery_points u16; control_cid (uint16 length + bytes). V2 body: uint16 schema version `2`; the same fields, followed by recovery-point count and ordered `{epoch u64, snapshot_cid (uint16 length + bytes)}` entries before control_cid |
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
for the selected purpose. `SealPrepared` requires policy evidence, enforces exact recipient pairs
and matching vault/epoch/policy digest, and is the primitive used by `PrepareTransition` and
`PreparePublication`. Its fixed key inputs are supplied by its caller, which owns their entropy
handling.

## Bootstrap and device transitions

Bootstrap is deterministic over its inputs. Device Ed25519 and X25519 keys are generated separately
with `crypto/rand`; `Bootstrap` itself does not use a clock or randomness. A 32-byte recovery kit
and vault name derive the vault identifier. The root device's certificate is self-signed by its
Ed25519 key. The kit-derived signing key signs only the genesis checkpoint, whose `anchor` is the
SHA-256 fingerprint of the root signing public key. `ComposeGenesis` seals the canonical empty
snapshot and builds the count-zero head, control and kit-signed checkpoint so the control and
checkpoint bind the final snapshot and control CIDs. `ValidateGenesis` verifies those bindings
and signatures. This is the seal composition only; repository publication and verified read-back
are owned by `internal/remote/atproto`.

On first use, the operator supplies the kit and treats it as the root of trust:
`RecoveryKitSigningPublicKey` derives the verifier key and `VerifyCheckpoint` checks the
checkpoint's kit signer, key fingerprint and signature. The verified checkpoint's `anchor`
then becomes the `TrustAnchor` used for certificate-chain verification. This is the operator's
assertion that the vault is theirs, not a provider-derived fact. A stolen kit can vouch for an
attacker's root. A checkpoint older than unseen history cannot reveal that missing history;
anything below the pinned anchor is still rejected. Later starts use a checkpoint already held
by the device. `dottie account bootstrap` prints the grouped kit plus vault, anchor, checkpoint
and kit-public-key fingerprints for independent recording. `SignRecoveryKitCheckpoint` accepts
a 32-byte kit and the explicit successor vault, root anchor, nonzero supported epoch, policy digest,
control CID and epoch-start snapshot CID; it derives the same labeled signing key as bootstrap,
signs one checkpoint and retains no kit. It rejects malformed CIDs, invalid position sizes and
unsupported administrative epochs. Durable checkpoint storage is the state store's responsibility.

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

`PreparePublicEnrollment` accepts only a `PublicDeviceInput` for the newcomer: bounded device and
key IDs, Ed25519 signing public key and X25519 recipient public key. Its approval fingerprint binds
the vault, device ID, key ID, requested role and both public keys. The administrator supplies its
own root `DeviceMaterial` for signing; the newcomer's private keys are not accepted. The path shares
the transition checks with private-material enrollment, including the exact recipient/wrap set,
certificate bindings, epoch and ancestry checks, and checkpoint exclusion. The older private-material
`PrepareTransition` API remains unchanged for existing callers.

`OnboardingBundle` is version 1 canonical JSON with exactly these fields: `version`, `vault_id`,
`anchor_fingerprint`, `recovery_anchor`, `successor_checkpoint`, `successor_policy`,
`successor_control`, `predecessor_policy`, `predecessor_control`, `predecessor_head`,
`predecessor_snapshot` and `predecessor_certificates`. The vault ID and fingerprints are 32-byte
lowercase hex strings; object fields and each certificate are lowercase hex encodings of signed vault
objects. Policy, control, head, checkpoint and certificate objects are bounded by
`MaxPolicyObjectBytes` (64 KiB), the predecessor snapshot by `MaxEnvelopeBytes` (384 MiB), and the
certificate count by `MaxRecipients` (64). The complete JSON is bounded by
`MaxOnboardingBundleBytes`, which includes the hex expansion of these bounds. No fields are optional.
Decode rejects unknown or duplicate fields, non-canonical encodings, trailing values, unsupported
versions and oversized input. The bundle contains no kit, private device key, token, approval or
snapshot plaintext; the predecessor snapshot is encrypted ciphertext.

Predecessor certificates are deterministically ordered by `(device_id, key_id)`. The bundle binds
the predecessor policy/control/head/snapshot/certificates to one another and to the successor epoch,
policy digest and control ancestry; it verifies predecessor certificate chains, head and snapshot
signatures. The coordinator authenticates predecessor and successor policy/control signatures against
the explicit root anchor before import, then persists the full predecessor position through the
existing evidence API. The kit-signed successor checkpoint is bound to the successor control and
recovery-key fingerprint, but its signature cannot be verified by a newcomer that does not possess the
kit; the operator-supplied root anchor remains independent and must be confirmed out-of-band. The
first remote read re-authenticates the successor position and exact checkpoint control. The bundle is
public evidence, not provider authority. No AT Protocol record-CID assertion is made by this vault
format.

`ValidateTransition` authenticates the predecessor, requires one-step epoch advance and policy
and control ancestry, and verifies the successor signatures. Enrollment must add exactly its
certificate and recipient. Revocation must remove exactly one non-root device from roles and
recipients, preserve all other bindings, list that device and certificate epoch as revoked, and
carry no certificate object. Both transition kinds require the successor head count to be zero,
the snapshot and head to name the same candidate, and the control's epoch-start snapshot CID to
match it. `ValidatePublication` checks the same-epoch policy, active signer certificate,
predecessor head and exact count increment. These checks are not transactional; the
atproto package owns staging, durable attempts and the separate fenced write sets.

Check 7 proves recipient identity binding only: each envelope key ID maps to the certified key
named by policy, with no extras or omissions. It cannot prove that encryption used that recipient's
key correctly without the recipient's private key. Snapshot record schemas and record-to-blob
binding remain the record schemas work; this package prepares encoded signed objects and CIDv1 raw-codec
SHA-256 CIDs over those canonical bytes. AT Protocol repository records remain DAG-CBOR records with
DAG-CBOR CIDs; they are a different object family and do not use the vault-object CID codec.

## Recovery kits and checkpoint verification

A recovery kit is exactly 32 random bytes, rendered as uppercase base32 in groups of four characters. `ParseRecoveryKit` accepts that rendering with hyphens and surrounding whitespace and rejects any value that does not decode to exactly 32 bytes. The vault identifier is derived from the kit and the vault name. The existing kit signing-key derivation is vault-specific; its public-key fingerprint is the kit key ID used by `VerifyCheckpoint`. A verified checkpoint supplies the root signing-key fingerprint (`anchor`); the recovery command cannot print that anchor unless an authenticated checkpoint is supplied. Recovery does not mint a kit: bootstrap is the operation that creates a secret the operator must keep offline.

`VerifyControlState` takes an opaque `TrustedContext` separately from the artifact-facing `VerificationRequest`. The request contains supplied and intermediate control evidence only: it has no trust-anchor or held-position fields, and the former caller-constructible `HeldCheckpoint` and `CheckpointPosition` types are not part of the API. `NewTrustedContext` takes the vault ID and anchor in a separate call and takes no verification artifact; `SetHeldCheckpoint` adds locally held control evidence to that context. A nil or zero-value context is refused. The context fields are unexported and `SetHeldCheckpoint` copies its evidence.

Separating the APIs prevents a verification request or bundle from establishing its own anchor or held position. Go cannot prove the provenance of a `[32]byte` anchor or control evidence: a caller can copy an anchor and held control from an artifact into the separate `NewTrustedContext` and `SetHeldCheckpoint` calls. Those calls have no path that reads fields from the verification request, but the library cannot enforce that their arguments came from independent sources. Callers must obtain the anchor from locally held trusted state or an explicit operator trust input and provide held evidence from local checkpoint state. The API does not claim cryptographic proof of that caller obligation.

Verification authenticates the supplied control, its signed policy and certificate chain before comparing freshness. When a local checkpoint is held, it authenticates that control and its separately supplied policy and certificate evidence too. Any signature, key, policy-digest, vault or chain failure is a refusal, not `unverifiable`; consent is not available on that path. `AcceptUnverifiableConsent` can record consent only on a verified result whose outcome offered it.

Verification checks the five outcomes in this strict precedence: `current` when CIDs match; `descendant` when the supplied control's authenticated predecessor chain reaches the held control; `stale` when the held control's authenticated predecessor chain reaches the supplied control; `conflicting` when both authenticated histories are complete and neither contains the other; and `unverifiable` only when no checkpoint is held, a required intermediate is missing locally, or the walk exceeds its bound. A direct predecessor link is enough; deeper links are followed only through control objects explicitly supplied as local evidence. The walk is capped at eight links, each intermediate is authenticated with its policy and certificate chain, and nothing is fetched. Missing evidence reports `missing-intermediate` and the required CID; depth exhaustion reports `depth-exceeded`. Invalid supplied evidence is refused as `invalid-intermediate`, never downgraded to uncertainty. An epoch number, device count, provider assertion or head snapshot is never used as ancestry proof.

Checkpoint currency is about the control record, not the live head. An ordinary publication advances the head within the epoch and writes no control, so it does not change this verdict. A checkpoint proves only that the kit signed that position; it cannot prove that the provider is serving the newest position the kit ever signed. Local evidence can establish authenticated ancestry but not global freshness, and a malicious provider can still withhold later history. Kit reissue is not implemented; until it is, a compromised kit can re-root the vault. Consent on an unverifiable report does not apply data or advance stored checkpoint state.

`account recovery --vault-name NAME` reads the existing kit from stdin, validates and re-renders it, and prints the derived vault and kit public-key fingerprints. `--checkpoint FILE` optionally supplies the local signed checkpoint whose signature is verified before printing its root anchor fingerprint. The command never generates or stores a replacement kit. `account verify --bundle FILE` consumes one offline JSON bundle with hexadecimal `vault` and `supplied` control/policy/certificate bytes; optional `held` evidence supplies the policy and certificates for the checkpoint already in local state, and optional `intermediates` supplies authenticated chain objects. The bundle format rejects a trust anchor or checkpoint field. With a local checkpoint, verification uses its locally recorded anchor; without one, the operator must supply `--trust-anchor HEX` as a distinct command-line input. The held control bytes are taken from the local checkpoint table and must match the bundle. `--consent` is accepted only for an authenticated `unverifiable` result and permits reporting/inspection/export only; `--record` writes the supplied position only after `current` or `descendant`. Neither command fetches, publishes or applies data.

### Retention declarations

`EvaluateRetentionDeclaration` authenticates each point's control evidence under the held checkpoint and accepts only `current` or `descendant` outcomes. Its boundary point matches the held checkpoint's epoch, snapshot CID, policy digest and control CID. Every control authenticates its epoch-start snapshot; an ordinary-publication point also requires its signed head and exact CID-verified envelope whose parent equals `head.PrevHeadCID`. A below-policy confidentiality floor is surfaced as compromised without refusing valid evidence. Unknown-epoch material forces the signed floor to zero and cannot produce a compliant judgement. `BuildAttestation` keeps the published device-signed body schema version 2 and its explicit ordered `(epoch, snapshot CID)` list; per-point policy/control bindings remain local declaration evidence and do not change attestation bytes. Version-1 count-only attestations decode and re-encode byte-identically. The shared DTE header remains wire version 1. Evaluation is pure and does not persist declarations. State owns declaration history, exact-body verification and pruning. The signed floor is the confidentiality floor (oldest known surviving material), while the recovery floor is the oldest epoch with a complete inventory. Growth is not bounded by the retained-point cap, and unknown-epoch leftovers cannot be counted as deleted or hidden behind a compliant floor.

### Current-format test vectors

The lowercase-hex vectors in `testdata/` are current version-1 examples, not
historical artifacts. `envelope-one-recipient-chain.hex` and
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

## Offline vault export archive primitives

`export.go` defines a versioned `DTVA` USTAR archive for caller-supplied signed policy/control/certificate/checkpoint/head objects, lineage and recovery positions, and referenced encrypted snapshot blobs. The manifest inventories every archive entry by kind, length, digest and member ordinal, and records fixed limitations plus omission codes from a closed set. It has no free-form DID or descriptive metadata. The archive binds to the 32-byte vault ID and anchor fingerprint. The reader streams bounded members, requires current to descend from the authenticated checkpoint through supplied control and policy predecessors, validates policy publication bounds, and refuses missing checkpoint/current/recovery blob CIDs before returning in-memory objects. It never writes an import.

These primitives do not implement a working `account export` or `account import` feature. There is no local artifact store for policy, certificates, head history, envelopes, retained recovery points or payloads, so commands wait for that store. The APIs do not access the network. The filesystem writer requires a caller-supplied capture-selection predicate and uses a pinned directory handle for output, but the library cannot prove that the callback checks trusted local selections; product wiring must provide the trusted boundary. The manifest states that caller-supplied inventory is not proof of completeness and includes this warning: **A repository CAR holds references, not payloads, and is not a complete blob backup.** See [`docs/recovery.md`](../../docs/recovery.md) for the format and validation order.

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
informational only; these measurements add no compression dependency and keep the codec `none`.
