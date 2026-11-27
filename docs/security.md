# Security model

Dottie's current security model is an account-authorized plaintext publication model. The v1
envelope, device-role, checkpoint, retention and archive material recorded later in this document is
historical: it is not a present protection and no current command exercises it. Use the current
boundaries below to decide whether to publish configuration with this tree.

## Current v2 access model

A v2 snapshot is an ordered list of plaintext payload segments, one per target, published in the
account's own AT Protocol repository. A files target is published either as an ordered plaintext
file-set (one plaintext blob per entry) or as one packed plaintext tar; a GNOME settings target is
carried inline in the snapshot record. Dottie does not add a client-side confidentiality layer over
any of it.

A fresh-machine `dottie pull` resolves the publication, fetches and decodes every packed blob and
entry blob, and reads the inline settings from the snapshot record, using the account session and
the published `vaultHeadV2` record. It applies the files targets the published position names; a
configured target that the position does not name is not planned, captured or mutated, although the
root safety checks and interrupted-apply recovery still observe the paths they recorded. An accepted
floor never advances while an apply journal entry is unresolved: the interrupted operation is resolved
first, and an operation that cannot be classified blocks the run. Writing inline settings back to a
settings backend is not implemented in this tree, so a published settings segment the local
configuration selects refuses the apply plan instead of being applied silently, and a settings target
is never adopted without a build that can write it. It does not load a Dottie device key. The reader verifies
account identity, publication scopes, record membership in a signed commit, the head/snapshot
chain, each payload CID and size, and the payload format. Those checks establish repository-scoped authenticity and
integrity, not global freshness or device authorization.

`dottie push` resolves the vault it acts on from local evidence: an explicit `--vault`, the recorded local vault
selection, or the stored publication binding recorded for the same account. It prepares a candidate under the same
account authority. It does not load a Dottie device key to publish. The consent, review, repair and
accepted-floor checks around a publication remain mandatory, but they are local policy checks; the
publication authority is the authenticated account session.

Consequences:

- Losing every Dottie device key is not, by itself, loss of access to the published plaintext
  position. The account session can retrieve it.
- Holding a Dottie device key does not add publication authority on the v2 path, and losing one does
  not remove it.
- The account session is the confidentiality and availability authority for the published copy.
  Losing account access, or losing provider-held data, is the data-loss boundary.
- Repository signatures establish account repository authority. They do not establish which Dottie
  device or authenticated session authored a record.

Every payload object is uploaded before the record batch, so a rejected or ambiguous batch can leave
unattached plaintext blobs that remain retrievable by CID at the provider. Dottie cannot delete them.
Dottie itself never surfaces candidate bytes for a publication that did not succeed: no command,
log, error, report or archive surfaces them, and the accepted position does not advance. The
residual is provider-side only.

A publication is now several payload objects, one per segment that carries data, so the residual is
one unattached plaintext blob per object that was already uploaded: one per entry for a file-set
segment, one per packed segment, and none for an inline settings segment. A mid-upload failure or a
rejected batch can therefore leave up to N unattached plaintext blobs at the provider, and Dottie
still cannot delete them. Inline settings are not blobs, but a rejected or ambiguous `applyWrites`
batch has already sent their values to the provider in the record body, so a settings segment can
disclose plaintext to the provider even when no blob exists and no record was committed. The blob
residual is bounded by the managed-object ceiling and the custody byte limit, it stays
provider-side, and it does not license exposing candidate bytes locally: a
submission that did not succeed surfaces no entry content and no setting value through any Dottie
command, log, error, report or archive, and the accepted position does not advance. A failure before
submission is abandoned automatically by the confirmation wrapper; once submission may have happened,
the attempt remains unresolved and blocking. Dottie never retries a different form after an attempt
starts. The 64-object custody limit is shared across retained publications, not newly granted per
publication, so a representable successor that changes a CID can still be refused before any
upload.

## Evidence behind a submission

The segment forms do not rest on the same evidence, and the difference is deliberate.

- A packed segment submits a blob reference that the attempt core already carries. The store records
  that the upload phase started and hands out the staged payload; it cannot observe the provider.
- A file-set segment requires the caller to name the entries it uploaded, exactly and in full: same
  count, same order, same path, same CID, same size as the authenticated entry list in the attempt
  core. The store refuses a partial, reordered, substituted or extended list, and it corroborates the
  list against local custody first, so a caller cannot satisfy the gate by naming entries it never
  staged. The refusal leaves the attempt in its upload-started, not-submitted state: unresolved and
  blocking, never terminal.
- A settings segment carries no blob at all: its values are authenticated by the snapshot record.

A file-set entry list is strictly more evidence than a packed blob reference, not a substitute for it.

## Public metadata visibility

V2 typed repository records are public plaintext metadata. The published head and snapshot records
disclose the vault and publication identifiers, sequence, parent and CIDs. Each segment also
discloses its target id, its portable root of base, relative path and kind when it has one, and its
form. A file-set segment discloses every file path, mode, size and blob CID, although not the file
content in the record itself; the blobs are plaintext. A packed segment discloses one blob CID and
size. A settings segment discloses the schema id, settings path, key, state and value of every
setting inline in the snapshot record, so setting values are record metadata rather than blob
content, exactly as they were previously public inside a packed tar manifest. Do not publish
configuration or setting values you are unwilling to place in the account repository and provider
storage.

Dottie has no log facility. Routine status, read, push, pull, sync and position output omits file
contents, setting values, private keys, session material, relative entry locators and absolute
home/config/cache/data/temp roots. The account DID appears only in the resolved-session line that a
run without `--did` prints. Provider error text is reduced to a closed refusal-code allowlist and a
fixed unknown label before it can reach output.

A client cannot observe hosted provider logs or server-side storage. An owner-authorized read-only
observation on a disposable identity found that `com.atproto.sync.listBlobs` required an
authenticated request, while `com.atproto.repo.listRecords` and `com.atproto.sync.getBlob` were
public. That observation is specific to that identity and is not a protocol guarantee.

## Authenticity and recovery boundary

Authenticity is repo-scoped through AT Protocol account authority. A Dottie record set is authentic
for an account because it lives in that account's repository, is signed by that account's repository
key, and was written by an authenticated session. Dottie adds no vault signature over a published
position and no offline anchor. A reader can verify membership and integrity at a provider-asserted
commit; it cannot prove the commit is current or that the provider withheld nothing.

There is no cross-machine recovery path that works without a live PDS and account access. There is no
recovery kit and no export archive in this tree, and no command mints, reads or stores one. Losing
account access or provider-held data can therefore lose the published position; losing Dottie device
keys alone does not.

Every segment names the target it was captured from: an id and, for files segments, a portable root
of base, relative path and kind. Settings segments name the target without a root. A record cannot
grant local path access on its own. Adoption happens only on its own pull confirmation, and only after the same checks and
canonicalization `targets add` performs: a files root must resolve inside HOME or XDG_CONFIG_HOME,
must not overlap Dottie's own directories or an existing target, and the adopted target is stored
at its resolved path. A settings target is adopted only when the user names it on the pull command
with a category selection, which resolves from the local catalog into the approved key set and
digest the plan shows; the record cannot choose categories, approval or a matrix version. Proposed
roots are resolved and validated before that confirmation but their contents are not captured: the
plan that reads a target is composed only after adoption is confirmed, and its confirmation binds
the resolved root or the derived settings policy. Adopted targets use review mode and no excludes,
targets that cannot be resolved are skipped and reported rather than adopted, and the sync path
refuses adoption because its push half is already composed. An existing target is left alone: the
published root is not enforced against it, so a record cannot redirect it, and a legacy file-set
record without a target names no root, so it cannot be adopted and pull requires a local files
target for it. A single-file target publishes its file under the basename of its configured path,
and pull maps the sole file-set entry back to that file without synthesizing parent directories.
The pull confirmation binds the local target id, portable root and selection/approval revisions,
including any adopted target, so changing the local target, root or
configuration between review and confirmation refuses. Multi-target configurations cannot consume a
file-set base; they fall back to packed only when the accepted base is packed. The target root must
exist before apply. Missing parent directories named implicitly by a directory file-set entry are
created with mode `0755`; directory modes are not carried in the record.

Local state is plaintext on disk. The publication position database, the apply journal, journal
preimage backups and captured payloads are readable by anyone who can read the state directory. Local
filesystem access is equivalent to reading that material. The OAuth session and device keys live in
Secret Service, which protects a key at rest, not a running process.

## Authorities

**Account authority** is the only v2 publication authority. It is the OAuth session: discovery, PKCE,
PAR, DPoP, `iss` and `sub` binding, strict scope enforcement, and one atomic Secret Service envelope.
It grants repository access and nothing else. `account login`, `status` and `logout` operate on that
authorization; they do not capture or sync target data.

**Device authority was a v1 concept.** `account bootstrap` still mints and stores local device keys
for the recorded local vault identity, but on the current v2 path those keys are not required to read
or publish a position. V1 device certificates, root/publisher/restore-only roles, epochs, revocation
and device-signed checkpoints are historical material, described below.

There is no recovery authority. Nothing offline can authorize a root replacement, sign a position or
restore data. Genesis checkpoints and their recovery anchors, where they still appear in historical
documentation, are not part of the current path.

## Bootstrap custody and local identity

`account bootstrap --vault-name NAME --device-id ID (--did DID | --handle HANDLE)` requires a
signed-in account. Before minting device keys or local state, it authenticates a repository revision
and refuses, with exit 3, an account whose repository already holds a Dottie publication: a record in
the v2 `vaultSnapshotV2`/`vaultHeadV2` collections or in any retired v1 `vault*` collection. Records
from other applications do not block bootstrap. Bootstrap writes no repository record: it derives the
vault identity from the vault name and the freshly minted root key, stores the root device keys in
Secret Service, and records the local vault selection. The first `push` is the only publication of
that vault, through the v2 plaintext profile; Dottie chooses packed or file-set automatically. An
account can hold only one published Dottie vault because bootstrap refuses an account that already
holds one. Multi-vault selection means only
locally recorded vaults, not multiple published vaults on one account.

Bootstrap mints no secret for offline use, prints none and flushes none. A keyring or local selection
failure exits 3 with `bootstrap: not-recorded`, deletes the pending device keys best-effort and
publishes nothing, because nothing was sent to the provider. Because the local vault identity is
derived from fresh device keys, repeating bootstrap with fresh keys derives a second local vault
identity; the account holds no Dottie publication until one is published, and multi-vault selection
then requires `--vault` and `--device-id`.

## Historical v1 material

None of this is a protection in this tree: encrypted snapshot envelopes, epoch content keys,
device certificates and roles, revocation authority, signed genesis, kit-signed checkpoints,
offline anchors, retention floors, export archives and the v1 record-key inventory. The commands
that served them are gone, and a repository holding those records is refused as `legacy_profile`.

## Threats and residual risks

**A malicious provider** controls what it serves and keeps. It can withhold records, serve a stale but
correctly signed state, and retain blobs. Dottie has no independent freshness anchor, so it cannot
detect a coherent older revision. A provider colluding with a revoked v1 keyholder could reference
temporary blobs outside our writes.

**An attacker with account credentials** controls remote storage and can read the plaintext
publication. Account credentials are the publication authority on the v2 path.

**An attacker with an offline, read-only copy of the filesystem** reaches the position database, the
configuration, captured payloads, the apply journal and its plaintext backups. It does not reach the
session token or the device keys, which live in Secret Service.

**A lost or stolen device key** does not by itself disclose or unlock the v2 plaintext publication.
V1 envelopes it could already decrypt remain decryptable by whoever holds those epoch keys, but that
is historical material.

- Disclosed plaintext remains readable indefinitely by whoever holds it.
- A candidate uploaded before a rejected or ambiguous record batch remains retrievable by CID; the end
  of that window is unmeasured.
- Global freshness is not provided. The only remote claim is membership at a provider-asserted commit.
- Provider-side at-most-once effects, hidden provider logs and server-side retention are unobservable.

## Freshness-unverified inspection policy

Authenticated content and global freshness are distinct. If freshness cannot be verified against a
local position, an apply refuses in the publication-apply path; no risk flag or consent bypass grants
apply authority. A freshness-unverified inspection path may report a position, but it does not mutate
target data or create an apply journal. Invalid signatures, wrong keys and failed policy checks remain
unconditional refusals.

## First use

A device with no prior local state has no local accepted floor. A fresh `pull` may adopt the vault the
account publishes, but it applies nothing and accepts no floor before `--confirm`. The confirmed run
establishes the first accepted position from the account-authorized publication; it does not need a
surviving Dottie device key. Regaining authorization is not regaining data: Dottie cannot retrieve
bytes the provider or account no longer makes available.

## Stored secrets

| Secret | Where it lives | Lifetime | If stolen |
| --- | --- | --- | --- |
| OAuth session and refresh token | Secret Service, one atomic envelope | until logout or reauthorization | reads, writes and deletes the account repository, including the plaintext publication |
| Device signing key (Ed25519) | Secret Service | until local deletion or keyring loss | historical v1 publication authority; not a v2 read or write gate |
| Device recipient key (X25519) | Secret Service | until local deletion or keyring loss | unwraps historical v1 envelopes ever wrapped to that device |
| Local state, journal backups and captured payloads | filesystem | until deleted | plaintext configuration and retained preimages |

Local logout deletes a session item without decoding it, so corrupt, unknown-version and pending items
can be removed offline. Remote logout means the authorization server accepted a revocation request,
not that every issued access token or other device session has been invalidated.
