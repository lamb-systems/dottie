# Publication record boundary

This package contains transport-free codecs and joins for the inactive v2 snapshot and head
records, plus a bounded decoder for the referenced raw snapshot payload. Record blocks are DAG-CBOR;
canonicality is checked by typed validation plus exact canonical re-encoding and byte comparison.
JSON and XRPC record adapters are outside this guarantee. Record CIDs are locally computed over
canonical record bytes, not provider attestations or evidence of Spaces compatibility.

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
membership, authorship, global freshness, privacy, or provider behavior. The decoder is not wired to
remote fetch, publication state or a restore CLI. Provider conformance for the fixed MIME type is
deferred to transport work.
