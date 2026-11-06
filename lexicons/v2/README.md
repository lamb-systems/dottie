# Publication v2 records

These two Lexicon 1 documents define an inactive, transport-free publication record boundary:
`vaultSnapshotV2` stores a sequence-keyed snapshot reference, and `vaultHeadV2` binds the current
snapshot-record CID to its payload CID. They are separate from the seven v1 record schemas and do
not enter the active OAuth repository-scope grant.

`internal/publication` accepts bounded DAG-CBOR record blocks only. The snapshot key is exactly 16
zero-padded ASCII decimal digits; the head key is `self`. Record CIDs use CIDv1 DAG-CBOR/SHA2-256,
while payload CIDs use CIDv1 raw/SHA2-256. A sequence-zero snapshot has an empty parent; a successor
must link the exact previous snapshot record CID. The head must bind the sequence-keyed snapshot's
vault, sequence, record CID, and blob CID.

The `vaultSnapshotV2` NSID pins plaintext payload Version 1 with CodecNone: the current canonical
USTAR container and JSON manifest, without an envelope or compression. The blob MIME type is fixed
as `application/octet-stream`, and the size is bounded by the schema and codec. Another payload
format requires a separately reviewed profile and NSID.

The package verifies structure, canonical record bytes, CID roles, bindings, ancestry joins, and
payload byte length/CID. It does not authenticate account or repository membership, prove freshness,
authorize privacy, or call a provider. Locally computing a record CID is not a provider attestation
or a claim of Spaces compatibility. JSON/XRPC adaptation is outside this strict decoding boundary.

This slice does not implement a production fetched-bytes adapter or remote restore. The integration
composition test reconstructs bounded `vault.Blob` metadata locally from synthetic fetched bytes
before calling the existing Unpack implementation. A reviewed production bytes-to-Blob adapter and
its malformed-payload tests are required before v2 restore is wired. Transport conformance for
provider handling of the fixed MIME type is also deferred.
