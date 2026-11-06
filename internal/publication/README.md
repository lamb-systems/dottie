# Publication record boundary

This package contains transport-free codecs and joins for the inactive v2 snapshot and head
records. It accepts and emits DAG-CBOR record blocks only. Canonicality is checked by typed
validation plus exact canonical re-encoding and byte comparison; JSON and XRPC adapters are outside
this guarantee. Record CIDs are locally computed over canonical record bytes, not provider attestations
or evidence of Spaces compatibility.

Snapshot records use 16-digit zero-padded ASCII decimal sequence keys and sequences from zero through
9007199254740991. A sequence-zero parent is an empty byte string; later snapshots must name the exact
previous snapshot record CID. Head binding compares vault, sequence, snapshot key, snapshot record
CID, and payload CID. Record CIDs are CIDv1 DAG-CBOR/SHA2-256/32-byte digest; payload CIDs are CIDv1
raw/SHA2-256/32-byte digest. The blob MIME type is `application/octet-stream`, and the payload size
is positive and at most 402653184 bytes.

The snapshot NSID pins the payload profile to `vault.Version` 1 and `vault.CodecNone`: canonical
uncompressed USTAR and JSON-manifest Pack output, without a DTE envelope. A different payload format
requires a separately reviewed profile and NSID. Payload validation checks only the byte length and
raw CID; it does not inspect or authorize content.

This package checks structure and byte integrity only. It cannot authenticate account authority,
repository membership, authorship, global freshness, or privacy. It performs no provider, session,
or filesystem operations and does not implement a publisher or remote restore. The integration
composition test reconstructs `vault.Blob` metadata from synthetic fetched bytes using a bounded
test-local manifest inspection before calling existing `UnpackWithLimits`. A reviewed production
fetched-bytes adapter, with malformed-payload tests, is required before v2 restore is wired. Provider
conformance for the fixed MIME type is deferred to transport work.
