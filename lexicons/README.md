# Vault lexicons

The seven Lexicon 1 record schemas define publishable address forms for the V02 signed
objects. All use the `systems.lamb.dottie` namespace:

- `systems.lamb.dottie.vaultHead`
- `systems.lamb.dottie.vaultControl`
- `systems.lamb.dottie.vaultSnapshot`
- `systems.lamb.dottie.vaultPolicy`
- `systems.lamb.dottie.vaultCertificate`
- `systems.lamb.dottie.vaultCheckpoint`
- `systems.lamb.dottie.vaultAttestation`

Head, control and policy are the current state records at the `self` key. Snapshot, certificate,
checkpoint and attestation records use TID keys. Records carry signed-object fields rather than
local configuration authority. The snapshot record carries the typed `application/octet-stream`
blob reference, its size, the envelope metadata and a separate signature. It contains no local path,
target or mode fields. The encrypted snapshot payload is the only place for user configuration.

## Binding and context

`internal/remote/atproto.VerifyRecordBinding` takes DAG-CBOR record bytes and the corresponding
V02 envelope or signed-object bytes. It compares only fields duplicated between those two inputs.
The snapshot comparison binds vault, publication ID, epoch, policy digest, parent, signer identity,
blob CID, blob size and SHA-256 digest of the envelope signature. The other six comparisons bind
every represented signed-object field, including the object's signature. A mismatch returns a typed
error naming the field. The head publication count must equal the signed head's count; whether it is
zero at enrollment or predecessor count plus one is a transition rule, not a binding rule.

`VerifyRecordContext` checks relationships that require neighboring records or a trust anchor.
Its context's `Policy`, `Control`, `Certificate`, `Snapshot` and `PreviousPolicy` values are
DAG-CBOR records; `Snapshot` supplies the referenced snapshot record bytes so the verifier can
compute its CID and compare its blob reference (an explicitly non-nil empty value represents the
genesis empty-head marker). Absent required entries are not skipped. Checkpoint trust-anchor
context is required when the checkpoint anchor is nonzero.

| Record | Required context | Context checks |
| --- | --- | --- |
| snapshot | policy, certificate | policy digest and vault; signer device/key and permitted role |
| head | policy, snapshot CID | policy digest and vault; snapshot reference |
| control | policy, snapshot CID | policy digest and vault; head snapshot reference |
| policy | certificate; previous policy when `prevPolicyDigest` is nonzero | root signer identity; previous policy digest and vault |
| certificate | policy, control | vault, device role, key ID and recipient X25519 key; revocation reference |
| checkpoint | policy, control; trust anchor when anchor is nonzero | policy digest, vault, snapshot/control references and anchor |
| attestation | policy, control | vault, policy digest, control reference and retention floor at least the policy floor |

Binding and context checks do not authenticate authorship. `VerifyRecordBinding` does no
cryptography. The snapshot record signature is Ed25519ctx with context `dottie/v1/recordsig` over
the context label followed by canonical DAG-CBOR of the record fields excluding `signature`.
`SignSnapshotRecord` and `VerifySnapshotRecordSignature` implement that record signature, but the
certificate chain must still establish that the same device key signed both the envelope and the
record. The record's signer device and key IDs must match the envelope's. The envelope's signature
digest does not replace the record signature or the envelope signature verification.

A policy names roles and each recipient's X25519 public key by value. Its recipient `keyId` is the
X25519 wrapping-key identifier; a certificate's `keyId` identifies the Ed25519 signing key. These
identifiers are different namespaces and must never be compared. The policy does not duplicate
Ed25519 signing public keys: policy role authorizes the device, the certificate chain binds that
device to its Ed25519 key, and the certificate record binds both keys to its signed certificate
object. Context checks match the policy-authorized role and recipient X25519 key; certificate-chain
verification authenticates the Ed25519 signing key. Neither check substitutes for the other.

## Atomic write sets

The transition table lists the complete set of record types written together by each state transition.
The snapshot blob reference is part of the snapshot record write, except the transition table's
snapshot-blob notation describes the bytes uploaded before the fenced commit.

| Transition | Records written |
| --- | --- |
| Bootstrap | policy, control, certificate, checkpoint |
| Enroll | policy, control, certificate, head, snapshot |
| Publish | head, snapshot |
| Policy change, revoke, rotate, root rotation | policy, control, certificate, head, snapshot |
| Reissue kit | control, checkpoint, certificate |
| Recover | policy, control, certificate, checkpoint, head |
| Retention attestation | attestation |

The publication write set does not include control. Schema, scope and write-set tests keep the full
seven-record set visible.

## Versions and bounds

Three version concepts remain separate:

- The V02 `DTE` wire-format version is the envelope/object encoding version.
- An object-level version is reserved for object evolution; V02 objects do not add a competing
  lexicon version field.
- `schemaVersion` is the Lexicon record shape version and is `1` here.

V02 uint64 values that appear in records use Lexicon `integer` fields bounded by 9007199254740991
(2^53-1), the interoperable safe-integer ceiling; `EncodeRecord` rejects larger values instead of
truncating them. CIDs, parent values, and CID references use raw CID bytes, at most 128 bytes
inclusive. Device identifiers and key identifiers are at most 255 UTF-8/byte units as applicable;
policy recipients are capped at 64. Every administrative V02 object is at most 65536 bytes
inclusive. Lexicon field constraints alone cannot express all V02 decoder bounds, so these byte
and aggregate object limits are recorded here; `internal/remote/atproto` also enforces them. Snapshot envelopes are subject to the V02 envelope and ciphertext caps.

The snapshot signature covers the record as encoded: the Ed25519ctx preimage is the context label
followed by canonical DAG-CBOR with only `signature` removed. `$type` and `schemaVersion` are
included, and the blob is encoded in its typed blob form. Adding a record field therefore changes
the signature preimage and is a signature-compatibility break even when the DTE wire version does
not change.

The schema and scope tests load the top-level `lexicons/*.json` v1 inventory directly. Separate
v2 schema tests load only `lexicons/v2/*.json`; the v2 records are inactive and are not included in
the OAuth repository-scope grant. The recursive release-domain guard still scans both directories.
The OAuth metadata's repo scope set must equal these seven record NSIDs, with the blob scope for the
snapshot payload and the `atproto` base scope. `docs/client-metadata.json` is served byte-for-byte,
and its own public URL remains equal to `client_id`.
