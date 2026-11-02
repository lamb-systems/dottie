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

## Deletion and what it actually buys

Every authorized device is required to delete epoch keys it no longer needs, and retention is derived from
the recovery points it keeps rather than from a fixed epoch count.

That bounds what a stolen honest device can reveal only if its old keys are genuinely gone. A device
retains its own X25519 private key, and a stolen private key can unwrap archived wrappers for any epoch that
was wrapped to it, recovering a content key that was deleted locally. So deletion limits the copies we keep,
not the capability of anyone who kept a secret. Historical ciphertext also stays readable to anyone holding
the epoch key, indefinitely.

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
| Epoch content key | memory, and Secret Service while current | until the epoch is superseded and pruned | decrypts every snapshot under that epoch |
| Recovery kit | offline, not on the machine | until reissued | administrative control of the vault |
| Local state and captured payloads | filesystem | until deleted | plaintext configuration, as in the filesystem row above |

The recipient key row is the one people get wrong: revoking a device stops it publishing, and it does not
take away its ability to unwrap ciphertext that was already wrapped to it.

## Adversarial corpus (DOT-V07)

ADR 014 and ADR 015 define the target contract. The DOT-V07 corpus attacks the vault authorization and
decoder paths with runtime constructors in `internal/vault/hostile_test.go`,
`internal/vault/hostile_export_test.go` and `internal/remote/atproto/hostile_reader_test.go`; the case matrix
and each case's first mandatory check live in those files as the `caseMatrix` table. It is evidence, not a
clean bill of health: the security gate it defines is expected to fail today, because fourteen ADR-violating
behaviours are recorded as known defects.

Case 1a proves that the unequal ancestry fields are accepted on both an observed and an empty observation
store, but cannot prove that a future fix implements the Parent-to-PrevHeadCID join rather than an unrelated
refusal; that is verified in the fix's own implementation review.

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

### Known defects and the gate

Each known defect carries an owner and the ADR contract it violates; the registry is `knownSecurityDefects`
in each package. `accepted-risk` is non-waivable for any authentication, authorization, signature,
policy-digest or consent failure. The gate is closed only when `make known-defects` passes **and**
`TestCaseSecurityGateIsClosed` passes, which requires both an empty registry and no `known-defect` matrix
row. Today the gate is open:

| Case | Finding | Owner | Contract | Observation |
| --- | --- | --- | --- | --- |
| 1a | P03 | vault-read | refuse | accept |
| 1b | V03 | vault-devices | refuse | accept |
| 3b | P03 | vault-read | refuse | accept |
| 3c | P03 | vault-read | refuse | accept |
| 5b | P05 | vault-read | refuse | accept |
| 5c | P03 | vault-read | refuse | accept |
| 10 | P03 | vault-read | refuse | accept |
| 11 | V04 | vault-read | refuse | accept |
| 13 | V04 | vault-checkpoint | refuse | accept |
| 14 | V03 | vault-devices | refuse | accept |
| 15 | V04 | vault-devices | refuse | accept |
| 18 | P04 | vault-read | refuse | accept |
| 19 | V05 | vault-checkpoint | refuse | accept |
| 20 | V02 | vault-objects | refuse | accept |

The shared shape is a check that is individually correct but either not on the path that runs or not joined
to the field it must agree with: the reader never joins `head.PrevHeadCID` to `envelope.Parent` (1a) and never
compares either ancestry field with its observed head (5c); it never compares `envelope.Recipients` with the
policy (3b, 3c), authorizes the head and envelope signers independently (10), accepts a head above
`max_publications` (18) and never walks control ancestry (11). Enrollment omits the `envelope.Parent` to
predecessor `HeadCID` join (1b); the enrollment and revocation deltas leave non-roster policy fields unchecked
(14, 15), and the vault decoder accepts out-of-range bounds (20). The checkpoint verifier follows control links
without mirroring the policy chain or consulting `policy.Roles` (13, 19). An older but coherent revision
replayed at the next count is likewise accepted (5b).

### Retracted claim and the extra-wrap mechanism

An earlier note implied extra envelope wraps were rejected. That is retracted. `SealAuthorized` does not
filter recipients, the read path never compares the envelope recipient set with the policy, and an
unauthorized recipient's wrap recovers the prepared envelope's content key with X25519, HKDF-SHA256 and
XChaCha20-Poly1305, which decrypts that snapshot. Case 3c unwraps that route independently and recovers the
exact content key. `Seal` generates a fresh content key per call (envelope.go:203-206), so this proves
disclosure of the one prepared envelope's key, not of every snapshot in the epoch. A wrap being *malformed*
is separate, detectable only by attempting the unwrap, and no refusal is claimed for it.

### Undetectable limits

- A coherent, correctly signed, older revision is undetectable without an independent freshness floor. Global
  freshness is not provided; the only remote claim is membership at a provider-asserted commit.
- `max_epoch_age` is a **local rotation trigger, not a validity rule** (ADR 014:148-164). It is a local-clock
  trigger persisted in state, and a device treats the trigger as met when its state is lost. A reader that
  accepts an old epoch is therefore correct, and no refusal case is claimed for epoch age. This is separate
  from `max_publications` and `max_epoch_age` *numeric range* (ADR 014:158-159), which case 20 characterizes
  as an unfixed defect: the vault wire decoder accepts out-of-range bounds rather than refusing them.
- Availability: withheld blobs and refused reads are `unavailable`, not a rollback signal.
