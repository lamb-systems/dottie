# Offline vault export archive

The vault package provides version-1 archive primitives over caller-supplied signed objects and encrypted snapshot blobs. This is not an end-to-end backup command: the repository has no local store for the current vault policy, certificate set, head chain, envelopes, retained recovery points or payload blobs. `account export` and `account import` are therefore not wired. A later task must provide that local artifact store and decide where validated imports are persisted.

## Archive layout

The archive starts with `DTVA`, followed by an uncompressed USTAR stream. The first regular-file member is `000000`, the canonical JSON manifest. Remaining members use six-digit ordinal names in inventory order. The reader rejects noncanonical USTAR framing, extensions, trailing data and non-regular members.

The manifest contains the format version, canonical 32-byte vault ID, anchor fingerprint, epoch, policy digest, an inventory entry for each member, fixed limitation statements and bounded omission codes. Each inventory entry has a kind, optional group and blob CID, exact byte length, SHA-256 digest and ordinal member name. The archive includes the caller-supplied current policy and control, active certificate set, checkpoint and head; authenticated lineage positions; retained recovery positions; and the encrypted snapshot blobs those positions reference. Arbitrary descriptive metadata and DID text are not part of the manifest.

The core identity is the vault's 32-byte ID, not an account DID. Import checks the expected vault ID and anchor; a different vault ID is refused unless the caller explicitly sets `AllowVaultMove`. Moving account DID metadata is not implemented here.

The archive's typed manifest does not provide free-form channels for caller descriptions. It contains public signed objects and encrypted snapshot envelopes, not device private keys, recovery kits, content keys or recipient private keys. The recovery kit is supplied separately to the encoder/reader so the kit-signed checkpoint can be verified; it is never serialized. Entry digests detect archive corruption but do not authenticate an archive independently of its signed objects and trust anchor.

## Import validation and writes

`ReadExportArchive` returns validated objects in memory and has no destination parameter or filesystem write path. Its refusal order is fixed:

1. Read and require the four-byte `DTVA` magic. Read the tar manifest header and a bounded prefix containing its version; refuse an unsupported version before reading the rest of the manifest or any payload member. Member bodies are read individually under their declared and aggregate bounds; the whole archive is not buffered.
2. Validate canonical manifest/inventory structure, exact member lengths, per-entry SHA-256 digests, archive framing and absence of unexpected members.
3. Bind the manifest vault ID and anchor to the caller's expected values. A foreign vault ID requires explicit move intent; the anchor must still match.
4. Verify the kit-signed checkpoint, require its control position and nonempty checkpoint snapshot payload, walk authenticated control and policy predecessor links from current back to the checkpoint, validate supplied same-control publication-head predecessors, verify policy publication bounds and signed objects/certificate chains, and require every referenced blob under its CID.
5. Return the complete validated in-memory archive. Persistence is deliberately left to a future local-store implementation; the reader has not written anything.

The policy, control, certificate, head, checkpoint and envelope bytes are retained exactly as received. Decoding validates them but does not re-sign or rewrite signed bytes. The archive reader authenticates evidence, not global freshness; an offline archive cannot prove that a provider did not withhold later history.

`WriteExportArchive` writes only to the caller's absolute destination. It requires a caller-supplied `IsCaptured` predicate, checks it before encoding and rechecks it immediately before writing, and uses one pinned directory descriptor for temporary-file creation and publication so pathname replacement cannot redirect output. The archive's manifest entries and remote-shaped data never choose a path. The library cannot prove that the predicate reflects trusted local capture selections; a callback that always returns false satisfies the type but not the safety intent. A product caller must supply trusted roots before this can be enforced internally; until then the callback is a caller obligation. `EncodeExportArchive` is the in-memory alternative.

## Completeness limits

The exporter is a pure bundle operation over its caller's inventory. It cannot retrieve or infer artifacts the caller did not supply. The manifest always records these limits:

- Anything the vault never held locally is absent.
- The archive contains only caller-supplied objects and blobs; this format does not independently prove that the local inventory is complete.
- **A repository CAR holds references, not payloads, and is not a complete blob backup.**

Caller-known omissions are selected from a closed set of codes and listed in the manifest. A missing blob referenced by a supplied current head, checkpoint snapshot or retained recovery position causes refusal and names its CID. Publication heads in the same control position must link to their authenticated predecessor head position and blob. Import refuses when a required control or policy predecessor between current and the checkpoint is absent. A CAR-shaped input is not a valid complete archive. No network access is used by the archive APIs or their tests.

## API boundary

- `EncodeExportArchive` accepts the current position, checkpoint, lineage positions, retained recovery positions, blob inventory, fixed identity values, bounded omission codes and a recovery kit; it returns archive bytes.
- `ReadExportArchive` validates bytes with caller-supplied expected vault ID, anchor, optional explicit move intent and recovery kit; it returns the signed objects and blobs without writing them.
- `WriteExportArchive` is an optional atomic filesystem writer guarded by the caller's capture-selection predicate.

These library APIs do not connect to a PDS, read internal state, fetch CAR blocks, restore user files, or implement `account export`/`account import` commands.
