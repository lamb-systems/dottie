# Schema-2 publication-attempt fixture images

These immutable test inputs contain two synthetic schema-2 SQLite publication-state images: a prepared, unsent pending-genesis attempt and a mixed history with finalized genesis, abandoned-but-catalogued bytes without an owner, an active submitted absence-unresolved successor, and replacement-floor/cache evidence. The first-conflict envelope, detached sequence-2 result, and final sequence-3 outcome/retirement remain distinct. The current replacement floor is position-only and has no retained incoming payload: `ReadAcceptedMaterial` refuses with `material_not_retained`. Historical finalized genesis remains readable through its retained attempt; the abandoned candidate is not owner-readable.

Producer baseline: commit `f5387d6a5fd3a9f6902e6fa8cea271aec24fba26`, archive SHA-256 `c1fb2a175051fcc899149549ce15e1e35eaa59cd62d1ded2d46a0f71b4e8d4be`, accepted generator source SHA-256 `68a52b789512bd2b5c2d587fa0838d02b6d6fb83ebb957ae32693ae5a16bd1ca`. The images use random DatabaseIDs; regeneration is not byte-identical and does not replace these pinned inputs.

The pair inventories all 15 schema tables (14 rows in pending-genesis and 44 in mixed); every table is nonempty across the pair. Raw-row companions preserve typed SQL cells; replay companions retain synthetic candidate/view bytes and documented public results. Replay recipes describe source order, not recorded execution, and retained results do not cover every call. The manifest records 4 packed payload files, each fully decoded during the recorded fixture validation.

- `pending-genesis`: DatabaseID `61e438c87e5165a7218e18a9aaad2c651f0d3a095adc90acc5858a8973522c17`, revision `0`, generation `0`, attempt mutation revision `1`; payload roles: `pending-genesis` (attempt, 3072 bytes, SHA-256 `f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea`).
- `mixed`: DatabaseID `96e9eaf5938c944476328415ab4c139ed8831f1fb129165ce50c5678c55de857`, revision `2`, generation `2`, attempt mutation revision `17`; payload roles: `active-unresolved` (attempt, 3072 bytes, SHA-256 `30f2aa3a007e288f7be544ec498a8af23c00da7b97222e550e3d18ee7cd105be`), `abandoned-catalogued` (none, 3072 bytes, SHA-256 `b18a43634e93d947bc5ac352d6332aca3036f921e21087a5ee1a4acdab9b72bb`), `retained-genesis` (retained-publication, 3072 bytes, SHA-256 `dfaa8ec95e4c6ac302aa5baa54ceadb96a5610a34b4d121d8ddc0fc976457fdc`).

## Immutable files

| Path | Role | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `manifest.json` | manifest | 28705 | `8a2691b039967fc2d980413bc7204b883199ac7853a5cfbb414bb6dd4a665103` |
| `mixed-inputs.json` | replay-inputs | 195211 | `b71f799e7f61408aa189e9a230fa9e4809b10c1f692dd67d702e540cfcfc32a6` |
| `mixed-rows.json` | raw-row-inventory | 103211 | `ed33147af1d8fec48d17e4006bb668fbd74d92698a605e974f21bf78e6367431` |
| `mixed/payloads/30f2aa3a007e288f7be544ec498a8af23c00da7b97222e550e3d18ee7cd105be.payload` | payload | 3072 | `30f2aa3a007e288f7be544ec498a8af23c00da7b97222e550e3d18ee7cd105be` |
| `mixed/payloads/b18a43634e93d947bc5ac352d6332aca3036f921e21087a5ee1a4acdab9b72bb.payload` | payload | 3072 | `b18a43634e93d947bc5ac352d6332aca3036f921e21087a5ee1a4acdab9b72bb` |
| `mixed/payloads/dfaa8ec95e4c6ac302aa5baa54ceadb96a5610a34b4d121d8ddc0fc976457fdc.payload` | payload | 3072 | `dfaa8ec95e4c6ac302aa5baa54ceadb96a5610a34b4d121d8ddc0fc976457fdc` |
| `mixed/publication.db` | database | 200704 | `e956014827b1ec6bcb3b43ed4f425a29383ad0f14f20352de05c5a4a054a0939` |
| `mixed/publication.db.lock` | lock | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `pending-genesis-inputs.json` | replay-inputs | 8739 | `0fcacb20644ac01b8232c6235dd8dc5c576ac5c3ca773e56b4edc120d575d4ed` |
| `pending-genesis-rows.json` | raw-row-inventory | 24589 | `5061a24e521f27923557ada45ae7654919ee42c52ce6861581823c0f372dd857` |
| `pending-genesis/payloads/f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea.payload` | payload | 3072 | `f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea` |
| `pending-genesis/publication.db` | database | 139264 | `d2e446ca0e728ac4af1835c2d4e65c4809fb17f19ef9729f0cc305b87b45f108` |
| `pending-genesis/publication.db.lock` | lock | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

## Safe use

Verify the fixed file hashes, then copy only the exact required files into fresh private `0700` directories with `0600` regular files. Open and test only disposable copies; never open the checked-in SQLite images writable and never regenerate them from ordinary tests or current libraries. Git does not preserve the private mode bits on arbitrary checkouts. Compare old raw rows and payload bytes before and after any later, separately authorized operation on a copy.

These fixtures are synthetic and local-only. They do not prove provider membership, freshness, authentication, remote publication, user-data safety, or migration behavior. They are schema-2 inputs only; no migration or schema-3 behavior is claimed.
