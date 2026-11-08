# Publication v2 records

These two Lexicon 1 documents define an inactive, transport-free publication record boundary:
`vaultSnapshotV2` stores a sequence-keyed snapshot reference, and `vaultHeadV2` binds the current
snapshot-record CID to its payload CID. They are separate from the seven v1 record schemas and do
not enter the active OAuth repository-scope grant.

`internal/publication` validates bounded DAG-CBOR record blocks and provides `DecodePayload` for
referenced raw snapshot bytes. The snapshot key is exactly 16 zero-padded ASCII decimal digits; the
head key is `self`. Record CIDs use CIDv1 DAG-CBOR/SHA2-256, while payload CIDs use CIDv1
raw/SHA2-256. A sequence-zero snapshot has an empty parent; a successor must link the exact previous
snapshot record CID. The head must bind the sequence-keyed snapshot's vault, sequence, record CID,
and blob CID.

The `vaultSnapshotV2` NSID pins plaintext payload Version 1 with CodecNone: the current canonical
USTAR container and JSON manifest, without an envelope or compression. The blob MIME type is fixed
as `application/octet-stream`, and the size is bounded by the schema and codec. Another payload
format requires a separately reviewed profile and NSID.

`DecodePayload` verifies the referenced blob's exact size and raw CID before calling the bounded
`vault.UnpackPayload` decoder for Version 1 / CodecNone USTAR snapshot bytes. It returns a complete
validated snapshot or the zero value. Reference failures are the existing `ErrPayload` violation
with field and reason; after a valid reference, parser failures expose only safe stage, reason and
closed bound-kind metadata. The decoder is structure and byte-integrity validation only. It does not authenticate
account or repository membership, authorship, global freshness, privacy, or provider behavior.
Locally computing a record CID is not a provider attestation or a claim of Spaces compatibility.
XRPC request construction and inbound JSON parsing remain outside this boundary; the outbound
record-value conversion is described below.

`publication.RecordToJSON` converts only canonical snapshot/head record blocks to outbound AT Protocol
record-value JSON, with an 8,192-byte ceiling and a pinned-SDK reconstruction check for exact DAG-CBOR
bytes and record CID. Byte fields use `$bytes` (including both head CIDs); only the typed blob `ref`
uses `$link`. Initial canonical record-validation errors pass through; adapter-stage failures use `ErrRecordJSON`
with closed field/reason metadata. The final byte-equality guard follows the CID check and is redundant
under the collision-resistance assumption; a distinct byte-mismatch failure is not independently
exercised.

A future authorized transport caller must serialize retained candidate values and the complete
request body before `BeginSubmission`. After a successful reservation, compare every returned
`SubmissionMaterial` field encoded in or constraining the body with that preflight. A mismatch refuses
sending and leaves the attempt unresolved; if all comparisons and separate authorization/preconditions
pass, only those exact in-process bytes may be used for the initial one-shot send. These APIs provide
no durable request-body custody, replay or retry authorization, including automatic SDK
authentication/nonce resends. The local composition demonstrates ordering/equality across two
explicit synthetic store bindings; it does not enforce that order in a production sender, send
requests or choose a backend. This outbound converter provides no inbound JSON parsing,
authentication, request construction, provider compatibility or Spaces readiness.

The production fetched-payload decoder exists, but remote fetch, publication-state and restore CLI
wiring remain deferred. The synthetic integration composition also exercises `DecodePayload` directly.
Transport conformance for provider handling of the fixed MIME type is deferred.
