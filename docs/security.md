# Security model

What Dottie protects, what it does not, and which limits were measured rather than assumed. This page is
for someone deciding whether to trust the tool with their configuration.

## Present and target, stated separately

| Capability | Present | Target |
| --- | --- | --- |
| Directory selection and consent | yes | — |
| Filesystem capture with containment | yes, library only | reachable from the CLI |
| Bounded snapshots | yes | encrypted envelopes |
| OAuth against a real provider | yes, internal boundary | user-facing account linking |
| Blob lifecycle and fenced publication | yes, harness and library | wired into a product command |
| Encryption and signatures | yes, vault library (ADR 015) | wired into a sync command |
| Device roles, revocation, epochs | yes, vault library (ADR 014); `account bootstrap`, `enroll`, `recovery`, `verify` | transitions driven end to end against a provider |
| Recovery kit and checkpoints | yes, vault library; `account recovery` and `account verify` | restore driven end to end |
| Vault export and import | yes, library only (`EncodeExportArchive`/`ReadExportArchive`); no command | a product export/import command |
| Remote vault sync | no; `dottie plan` previews a local view bundle only | a sync command that publishes and reads a vault |
| GNOME settings capture and apply | boundary only, opt-in cgo | the GNOME capture work to G04 |

The CLI exposes target selection, `dottie plan`, and the `account` command group (`bootstrap`, `enroll`,
`recovery`, `verify`). Account OAuth linking remains an internal boundary with an unsupported login path. No
command publishes or reads a vault against a provider, and vault export and import are library functions only.
No real data should be stored with this build.

## Authorities

Three separate things grant power, and none of them substitutes for another.

**Account authority** is the OAuth session: discovery, PKCE, PAR, DPoP, `iss` and `sub` binding, strict
scope enforcement, one atomic Secret Service envelope. It grants access to a repository and nothing else.
This is an internal boundary; there is no command that runs it yet.

**Device authority** is a root-signed certificate naming a signing key, a recipient key, a role and the
epoch at enrollment. Root, publisher and restore-only are distinct. Not implemented.

**Recovery authority** is material held offline, independent of the account. It can re-establish a root
device. Not implemented.

## What the transport guarantees

A verified revision proves membership of records at a commit the provider asserted. It does not prove who
wrote them, what policy applied, or that the commit is current.

`VaultReader` enforces one authenticated edge over caller-supplied control history. It refuses forged or
skipped ancestry; it does not prove the control this device observed. ADR 014:52-54 requires the observed
control, and only a held checkpoint supplies it.

The publication fence is measured on two providers: a stale writer loses on a structured error rather than
silently overwriting. Whether a provider can accept two identical batches and produce two effects is
**unproven**, because the measurement could not distinguish one commit from two by final membership.

The fence does not protect bytes already uploaded, because the upload precedes the fenced commit that would
reject them.

## Measured limits

From live runs on two hosting categories.

- A batch rejected after blob processing leaves its candidate anonymously retrievable by exact bytes. A
  never-referenced control blob stays unreachable, so the negative result is meaningful.
- A rejected candidate was reachable at one minute and at five minutes. The end of that window has not been
  measured and nothing here bounds it. These are the historical the fence work/F05 rejected-candidate observations;
  the checked-in harness's long referenceability schedule has not been run, and it measures a different
  property.
- A lost response cannot be distinguished from a request that was never sent without a re-read.
- Advertised blob ceilings differ: 300 MiB on one provider, 100 MiB on another. Neither is a tested
  rejection boundary. The entryway advertises no limit at all; only the resolved PDS does.
- `applyWrites` latency differed by roughly five times at n=50, which is exploratory rather than
  decision-grade.

## Threats

**A malicious provider** controls what it serves and keeps. It can withhold records, serve a stale but
correctly signed state, and retain blobs. Checkpoints reject a state below a held checkpoint and reject
ancestry that does not reach it. They cannot detect a provider that withholds newer history after the
checkpoint, which is an equivocation and availability limit rather than rollback. A provider colluding with
a revoked keyholder can reference temporary blobs outside our writes.

**A revoked device** keeps whatever keys it already had. Revocation stops it publishing; it does not make
ciphertext it can already decrypt unreadable, and no client-side protocol can.

**A stolen recovery kit** can mint a new root certificate and administer the vault. That is the cost of an
anchor independent of the provider. A kit-signed root replacement is accepted only above the last
kit-announced checkpoint, and reissuing a kit retires the old one at that checkpoint.

**An attacker with account credentials but no device key** still controls remote storage: it can delete,
corrupt, withhold and replace records and blobs. What it must not achieve is decrypting protected plaintext
or forging content that passes signature and policy checks as an authorized publication. Availability of
the remote copy is lost in either case.

**An attacker with an offline, read-only copy of the filesystem** reaches the state database, the
configuration, captured payloads and the local journal, which are plaintext on disk today. It does not reach
the session token or the vault keys, which live in Secret Service.

That exclusion is narrower than it sounds. Secret Service protects a key at rest, not a running process: an
attacker who can read process memory, a dump, swap, or who can replace a binary in the writable path, is
inside the session and is not excluded by this row. Collapsing those two attackers into one would turn a
real limit into a comforting sentence.

## Retention and deletion limits

Retention declarations are stored per vault and device with the policy digest, declared floor, and retained
recovery points. A below-policy floor is recorded and surfaced as a confidentiality-compromise signal rather
than refused. Re-declarations preserve the previous declaration and its digest so the change remains visible.

No epoch-scoped ciphertext cache exists yet, so the epoch dimension currently constrains only which recovery
points are retained; when the sync path introduces a snapshot cache, the same declaration and preconditions
govern it.

Pruning currently covers payload files not referenced by any applied base, outbound intent, or conflict, and
rollback backups past their existing age bound. Dry-run lists the exact payload files and backup entries that
apply would remove. It preserves any payload still referenced by an applied base, outbound intent, conflict,
or non-expired journal backup. Apply requires a stored checkpoint whose epoch and snapshot CID exactly match
the selected retained recovery point and whose policy digest matches the declaration. It also requires an
observed live head and refuses a boundary epoch greater than or equal to that head.

Complete here means pinned by a verified checkpoint, not that every referenced blob is present, because no
blob inventory is persisted and downloads are transient. This precondition constrains pruning to checked
evidence; it does not claim the snapshot is reconstructable. The live-head observation also fails closed when
no head epoch has been observed locally.

No content-key store or epoch-scoped ciphertext cache currently exists. The local payload store is plaintext
and is retained by content references; rollback backups are plaintext and age-pruned only after verified
apply or rollback. The declaration and preconditions govern any snapshot cache if the sync path introduces
one. A device's X25519 private key can still unwrap archived wrappers for epochs where it was a recipient, so
pruning locally held bytes does not revoke a secret someone already kept.

## First restore

A device restoring onto a machine with no prior state holds no local checkpoint, so the kit's checkpoint is
its only anchor and everything below it is rejected. With no kit checkpoint the device stays
freshness-unverified and is restricted to inspection and export.

Regaining authorization is not regaining data. A kit cannot retrieve bytes the provider no longer holds;
data recovery needs the independent complete export, and a repository CAR alone is not a complete blob
backup.

## Residual risks

- Disclosed ciphertext stays readable indefinitely by whoever holds that epoch key.
- A candidate uploaded during a concurrent revocation is readable by the pre-revocation recipient set. The
  staging interval can be narrowed; the decryption capability cannot be revoked retroactively.
- A revoked or offline device that ignores its deletion obligation retains access to what it held.
- The end of the post-rejection disclosure window is unmeasured.
- Global freshness is not provided. The only remote claim is membership at a provider-asserted commit.
- A stolen recovery kit is equivalent to administrative control of the vault.

## Stored secrets

| Secret | Where it lives | Lifetime | If stolen |
| --- | --- | --- | --- |
| OAuth session and refresh token | Secret Service, one atomic envelope | until logout or reauthorization | writes and deletes repository records; cannot decrypt vault content |
| Device signing key (Ed25519) | Secret Service | until the device is revoked | forges publications accepted as that device, until revocation lands |
| Device recipient key (X25519) | Secret Service | until the device is revoked; **not** erased by epoch rotation | unwraps every epoch ever wrapped to that device, including keys deleted locally |
| Epoch content key | caller-supplied process memory; not persisted by Dottie | used to seal and discarded by the caller | decrypts snapshots under that epoch while held |
| Recovery kit | offline, not on the machine | until reissued | administrative control of the vault |
| Local state and captured payloads | filesystem | until deleted | plaintext configuration, as in the filesystem row above |

The recipient key row is the one people get wrong: revoking a device stops it publishing, and it does not
take away its ability to unwrap ciphertext that was already wrapped to it.

## Adversarial corpus (DOT-V07)

ADR 014 and ADR 015 define the target contract. The DOT-V07 corpus attacks the vault authorization and
decoder paths with runtime constructors in `internal/vault/hostile_test.go`,
`internal/vault/hostile_export_test.go` and `internal/remote/atproto/hostile_reader_test.go`; the case matrix
and each case's first mandatory check live in those files as the `caseMatrix` table. The fourteen DOT-V07a
findings are closed: their tagged refusal tests remain in the frozen inventories and the security gate passes.

Case 1a now refuses the head/envelope parent mismatch with `ErrReadHeadEnvelopeLinkage` on both observed and
empty observation stores. Its refusal tests assert hostile fields on decoded inputs, not plaintext or a result
returned alongside an error.

### Proven refusals

The reader and the vault library refuse these, with the sentinel and stage named in each test:

- a snapshot with no membership in a valid revision, before any blob fetch (`ErrReadRecordMissing`);
- a restore-only device that signs a snapshot (`ErrReadRecordContext`, field `role`);
- a revoked device's envelope at its successor epoch (`ErrReadVaultAuthentication`);
- a successor policy signed by a root the predecessor never authorized (`ErrReadVaultAuthentication`);
- an epoch-mixed object, an epoch-1 envelope under an epoch-2 record (`ErrReadRecordBinding`, field `epochSeq`);
- a current policy naming an unrelated predecessor (`ErrReadRecordContext`, field `prevPolicyDigest`);
- opening a recipient the policy does not name (`ErrRecipient`);
- an export whose kit-signed checkpoint names a root the archive chain does not contain (`ErrAuthorization`),
  and an export whose member inventory is over its cap or whose first member header disagrees with its entry,
  each refused before any member payload is read (the case 12 guard asserts no payload is read past the manifest).

### Closed defect gate

`make known-defects` passes with the fourteen tagged refusal tests intact, all fourteen matrix rows at
`new-refusal`, both package registries empty, and `TestCaseSecurityGateIsClosed` passing. The matrix and
frozen inventories remain the record of each case and its refusal test.

| Package | Closed case IDs |
| --- | --- |
| `internal/remote/atproto` | 1a, 3b, 3c, 5b, 5c, 10, 11, 18 |
| `internal/vault` | 1b, 13, 14, 15, 19, 20 |

Checkpoint verification joins signer certificates to the policy role for the policy/control authorization
checks. It also checks every derivable control predecessor edge: the predecessor epoch must advance by exactly
one without uint64 overflow, and the successor policy's `PrevPolicyDigest` must equal the predecessor policy
digest. This covers direct descendant and stale shortcuts, each supplied walk link including its terminal
target, and every edge examined before `conflicting` can be returned. Each control position is authenticated
with its matching policy evidence; missing predecessor policy evidence remains unverifiable rather than being
treated as a proven edge.

### Recipient-wrap guarantees

`SealPrepared` requires the policy evidence and enforces exact `(KeyID, PublicKey)` pairs against its
recipients; substitution, omission, extra and duplicate pairs are refused with `ErrRecipient`. It
also requires the prepared vault, epoch and policy digest to match that policy. Production transition
and publication preparation pass their current or successor policy directly to this primitive.
`SealAuthorized` performs the signer-role checks and delegates sealing with that policy.

`VaultReader` separately enforces equality of the envelope's recipient key-ID set with policy,
returning `ErrReadRecipientSet` whether or not a device key was supplied. This is defence in depth;
the wire format carries no recipient public key (`envelope.go:93-98`), so reader set validation alone
cannot prove which public key built another recipient's wrap. `TestRogueWrapDisclosesContentKeyOutsideReader`
and `TestRogueWrapUnderPolicyKeyIDStillDisclosesContentKey` now prove the hostile wraps are refused by
the production sealing primitive. The earlier framing of recipient substitution as an accepted residual
risk was wrong.

### Undetectable limits

- A coherent, correctly signed, older revision is undetectable without an independent freshness floor. Global
  freshness is not provided; the only remote claim is membership at a provider-asserted commit.
- `max_epoch_age` is a **local rotation trigger, not a validity rule** (ADR 014:148-164). It is a local-clock
  trigger persisted in state, and a device treats the trigger as met when its state is lost. A reader that
  accepts an old epoch is therefore correct, and no refusal case is claimed for epoch age. This is separate
  from `max_publications` and `max_epoch_age` *numeric range* (ADR 014:158-159), which the vault wire decoder
  now refuses with `ErrLimit` when the bounds are out of range (case 20).
- `ATProtoTransitionIO.ReadCurrent` enforces publication count and head ancestry only; it does not check
  envelope-parent linkage or the policy `max_publications` bound (P04).
- Availability: withheld blobs and refused reads are `unavailable`, not a rollback signal.
