# Vault export archives and recovery boundaries

The coordinator and CLI provide ciphertext-only export, validation-only archive import, and checkpoint-backed archive restore. `dottie export` assembles an authenticated archive and writes it atomically; `dottie import --archive` validates without changing local state; `dottie restore --archive` opens and applies only the kit-signed checkpoint snapshot through the ordinary candidate, consent, journal and rollback path. Archive restore does not contact a PDS, and the archive may not contain the newest provider state.

The recovery kit authorizes root recovery and signs checkpoints. It cannot decrypt content. Plaintext recovery requires a surviving compatible device recipient private key, either used with the provider or with an independent complete archive. If all device keys are lost without an independent export, the data is lost; a kit alone cannot recover it. An archive without a compatible recipient private key is also ciphertext only. A repository CAR is not a complete blob archive.

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
5. Return the complete validated in-memory archive. The library reader has not written anything; the CLI `dottie import --archive` remains validation-only.

The policy, control, certificate, head, checkpoint and envelope bytes are retained exactly as received. Decoding validates them but does not re-sign or rewrite signed bytes. The archive reader authenticates evidence, not global freshness; an offline archive cannot prove that a provider did not withhold later history.

`WriteExportArchive` writes only to the caller's absolute destination. It requires a caller-supplied `IsCaptured` predicate, checks it before encoding and rechecks it immediately before writing, and uses one pinned directory descriptor for temporary-file creation and publication so pathname replacement cannot redirect output. The coordinator supplies the predicate from its locally selected capture roots; the library itself cannot prove that an arbitrary callback expresses trusted selections. The archive's manifest entries and remote-shaped data never choose a path. `EncodeExportArchive` is the in-memory alternative.

## Completeness limits

The archive encoder is a pure bundle operation over its caller's inventory. The coordinator fetches required snapshot bodies by CID through the verified remote reader and uses locally retained authenticated history for lineage; it refuses when required bodies or predecessors are unavailable. It cannot retrieve or infer artifacts neither the provider nor the local authenticated history supplies. The manifest always records these limits:

- Anything the vault never held locally is absent.
- The archive contains only caller-supplied objects and blobs; this format does not independently prove that the local inventory is complete.
- **A repository CAR holds references, not payloads, and is not a complete blob backup.**

Caller-known omissions are selected from a closed set of codes and listed in the manifest. A missing blob referenced by a supplied current head, checkpoint snapshot or retained recovery position causes refusal and names its CID. Publication heads in the same control position must link to their authenticated predecessor head position and blob. Import refuses when a required control or policy predecessor between current and the checkpoint is absent. A CAR-shaped input is not a valid complete archive. The archive library itself uses no network; coordinator export may make verified provider reads, while archive validation and archive restore do not contact a provider.

## API boundary

- `EncodeExportArchive` accepts the current position, checkpoint, lineage positions, retained recovery positions, blob inventory, fixed identity values, bounded omission codes and a recovery kit; it returns archive bytes.
- `ReadExportArchive` validates bytes with caller-supplied expected vault ID, anchor, optional explicit move intent and recovery kit; it returns the signed objects and blobs without writing them.
- `WriteExportArchive` is an atomic filesystem writer guarded by the caller's capture-selection predicate.
- The service coordinates authenticated inventory assembly and `Export`, validation-only `ImportExportArchive`, and `RestoreFromArchive`. The CLI surfaces are `dottie export`, `dottie import --archive`, and `dottie restore --archive`.

The archive library APIs do not connect to a PDS, read internal state, or restore user files. Export's service coordinator can fetch required blobs using the verified reader. Archive restore authenticates and applies only the checkpoint snapshot, requires a selected device recipient private key, and uses no provider transport. Global freshness is not established by an archive. Remote freshness-unverified state remains inspection/export-only: `--consent` cannot authorize apply.
