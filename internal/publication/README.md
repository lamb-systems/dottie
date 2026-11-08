# Publication record boundary

This package contains transport-free codecs and joins for the inactive v2 snapshot and head
records, an outbound record-value JSON adapter, and a bounded decoder for the referenced raw
snapshot payload. Record blocks are DAG-CBOR; canonicality is checked by typed validation plus exact
canonical re-encoding and byte comparison. `RecordToJSON` accepts only canonical snapshot/head
blocks and emits their AT Protocol JSON record values, capped at 8,192 bytes. It reparses generated
JSON with the pinned Indigo data model and returns it only when reconstructed canonical bytes and
the locally computed record CID match the input. It uses `$bytes` for byte fields (including the
head's snapshot and payload CIDs), and `$link` only for the snapshot blob's typed `ref`; a genesis
parent is `{"$bytes":""}`.

Initial canonical record-validation errors pass through unchanged. Post-validation conversion failures use
`ErrRecordJSON` and closed `Violation` field/reason metadata: `encoding`, `size_limit`,
`reconstruction`, `cid_mismatch` or `byte_mismatch`. The byte comparison follows the CID comparison
and is a redundant defense against a hash collision; it is not independently covered by a changed-
record test. Output is deterministic and detached, but is not a canonical-JSON signing format.
This adapter is outbound only: it does not parse untrusted JSON, build XRPC requests, authenticate
records, select a backend, or establish provider/Spaces compatibility. Record CIDs are locally
computed over canonical record bytes, not provider attestations.

A future authorized transport caller must convert retained candidate records and construct the
complete request body before `BeginSubmission`. After a successful reservation, compare every
returned `SubmissionMaterial` field encoded in or constraining that body with its preflighted values,
including records, expected snapshot CID, keys, collections, create/update flags, predecessor and
context fences, and required publication conditions. On any mismatch, refuse to send and leave the
attempt unresolved; never reset it or infer retry permission. If all comparisons and separate
transport authorization/preconditions pass, use only those exact in-process bytes for the initial
one-shot send. Neither this package nor `BeginSubmission` durably retains a request body or grants
replay or retry; automatic SDK authentication or nonce retries that resend a POST are not authorized
by these APIs. No post-restart resend mechanism is provided, and a supplied absence does not prove
finality. The local composition demonstrates preflight ordering but does not enforce it in a
production sender. First serialization and complete body construction must not become fallible work
after the boundary.

Snapshot records use 16-digit zero-padded ASCII decimal sequence keys and sequences from zero through
9007199254740991. A sequence-zero parent is an empty byte string; later snapshots must name the exact
previous snapshot record CID. Head binding compares vault, sequence, snapshot key, snapshot record
CID, and payload CID. Record CIDs are CIDv1 DAG-CBOR/SHA2-256/32-byte digest; payload CIDs are CIDv1
raw/SHA2-256/32-byte digest. The blob MIME type is `application/octet-stream`, and the payload size
is positive and at most 402653184 bytes.

The snapshot NSID pins the payload profile to `vault.Version` 1 and `vault.CodecNone`: canonical
uncompressed USTAR and JSON-manifest Pack output, without a DTE envelope. A different payload format
requires a separately reviewed profile and NSID. `VerifyPayload` checks only the byte length and
raw CID; it does not inspect or authorize content.

`DecodePayload` accepts only payload bytes and a `BlobReference`. It calls `VerifyPayload` first to
check exact positive size, the fixed packed-size ceiling and raw CID, then delegates to
`vault.UnpackPayload` for the pinned Version 1 / CodecNone USTAR snapshot profile. It returns a
complete `model.Snapshot` or its zero value. Reference failures preserve `VerifyPayload`'s existing
`ErrPayload` violation with field and reason. After reference verification, payload parser errors
expose only safe stage, reason and closed bound-kind metadata. No sender, key, path, session or
transport metadata is accepted.

These APIs verify structure and byte integrity only. They do not authenticate account or repository
membership, authorship, global freshness, privacy, or provider behavior. The unwired
`internal/publicationstate` library calls `DecodePayload` on caller-supplied packed bytes when locally
validating a candidate. Remote fetch, service coordination and CLI integration remain unwired, and
this use does not change the package's authentication boundary. Its v2 attempt layer's first-conflict
retention also preserves caller-supplied structural evidence only; it is not provider-authenticated.
Provider conformance for the fixed MIME type is deferred to transport work.
