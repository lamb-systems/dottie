# 014 — The vault authorization and key state machine

Status: accepted, 2026-10-31. Amends ADR 005, 006, 012 and 013, each marked in place. ADR 003 predates
this directory and lives in the planning graph; the constraints it contributes are restated here rather
than cited, so a public reader is not sent to a document they cannot open.

## Context

A fence protects promotion, not transmission. `uploadBlob` happens before the `applyWrites` the fence
guards, and the fence work and the contention measurements measured that a candidate rejected after blob processing stays anonymously
retrievable. An earlier draft claimed epoch equality made "never stage under an epoch a revoked device
holds" a checkable predicate. It does not; the ordering section states what is available instead.

A certificate binding only a signing key leaves the encryption key substitutable, because wrapping needs a
recipient key and nothing authenticated it. An earlier draft also used "the floor" for four unrelated
things; each now has its own name.

## Decision

Every section below is normative. Terms and object schemas come first because the rest depends on them.

## Terms

- `epoch_seq` — monotonic integer naming a content-key generation. Ordering only, never a time.
- `cert_epoch` — the `epoch_seq` at which a certificate was issued.
- `checkpoint` — a signed object naming a snapshot CID, `epoch_seq`, policy digest and signer, used for
  rollback detection.
- `retention floor` — the oldest `epoch_seq` for which a device still holds content keys.
- `policy retention floor` — the minimum `retention floor` the current policy requires of every device.
- `retention points` — the recovery points a device has chosen to keep, each pinning a snapshot CID and
  the `epoch_seq` needed to decrypt it.

## Signed objects

Four objects are signed. Fields are normative; encodings are in the envelope specification.

| Object | Fields |
| --- | --- |
| **Policy** | `v`, `vault`, `epoch_seq`, `roles[]` (`device_id`, role), `recipients[]` (`device_id`, `key_id`, X25519 public key), `policy_retention_floor`, `retained_recovery_points`, `max_publications`, `max_epoch_age`, `recovery_anchor` (kit anchor fingerprint), `prev_policy_digest` |
| **Control** | `v`, `vault`, `epoch_seq`, `policy_digest`, `head_snapshot_cid`, `revoked[]` (`device_id`, `cert_epoch`), `prev_control_cid`, `signer` |
| **Head** | `v`, `vault`, `epoch_seq`, `policy_digest`, `snapshot_cid`, `blob_cid`, `publication_count`, `prev_head_cid`, `signer` |
| **Certificate** | `v`, `vault`, `device_id`, `key_id`, Ed25519 public key, X25519 public key, role, `cert_epoch`, `issuer` (`device_id` of the signing root, or the bootstrap anchor), `revocation_ref` |
| **Checkpoint** | `v`, `vault`, `snapshot_cid`, `epoch_seq`, `policy_digest`, `anchor` (root signing-key fingerprint the kit vouches for), `control_cid`, `signer` |

Every object carries `prev_*` where shown, so an ancestry check is a chain of authenticated digests rather
than a trusted counter. A verifier rejects a control record whose `prev_control_cid` is not the control it
observed, except at bootstrap.

The recovery kit vouches for an anchor; it does not issue certificates. A device root certificate is
self-signed, and the kit-signed checkpoint pins its signing-key fingerprint, which is what a verifier is
given as `TrustAnchor`. An earlier draft had the kit sign the root certificate itself, which no verifier
can accept: chain resolution terminates at a self-signed certificate, so a kit-issued root would have no
verifiable issuer.

Root succession is represented as **two signatures on one control record**: the retiring root signs
`"dottie/v1/root-retire"` and the kit signs `"dottie/v1/root-appoint"`, both over the same successor
certificate digest. A control record changing the root is accepted only when both are present and both
verify against the predecessor state. A single new root certificate is never sufficient, which is what
stops a stolen kit from silently appointing itself without the retiring root, and what stops a stolen root
device from retiring the kit anchor.

## Authorization predicate

A device may perform an action when all of these hold: its certificate chains to the vault anchor, names
this vault, is not listed in the control record's `revoked` set, satisfies `epoch_seq >= cert_epoch`, and
the policy **at the predecessor state** assigns the required role to its `device_id`.

Administrative authority is checked against the predecessor, then the successor is validated. Checking the
successor's own policy would let a transition authorize itself. Role disagreement between certificate and
policy is a validation failure, never a precedence question.

## Ordering

Three linearization points, and no fourth:

1. **Observe** — a verified revision is read, yielding epoch E, policy digest P, control CID C, head H.
2. **Transmit** — the candidate blob is uploaded under E. These bytes cannot be withdrawn.
3. **Commit** — a fenced `applyWrites` against the observed revision either commits or loses.

The guarantee is: *a candidate is promoted only if its epoch and policy digest equal those in the control
record it commits against.*

Three intervals, distinct:

- **Preparation to transmission** — client-local. A device should discard a prepared candidate when the
  control record changes, but nothing enforces that on a delayed or hostile client.
- **Transmission to outcome** — bounded by the transport's own timeouts and the fence. After commit the
  outcome is decided; after transmission the bytes are out regardless.
- **Decryption capability** — indefinite for anyone holding epoch E or an unwrap capability for E.

Rotation bounds the first interval in practice, by making a prepared candidate stale sooner. It does not
bound the second, and it cannot bound the third: rotation limits future authorized key use, not the
lifetime of a ciphertext already disclosed.

## Transitions

Every row names its authority, the predecessor it must be checked against, the complete write set, and the
outcome of a lost race. A losing transition re-reads and re-derives; it never reuses a prepared candidate
after a policy or epoch change.

| Transition | Authority | Predecessor | Successor state | Atomic write set | Lost race |
| --- | --- | --- | --- | --- | --- |
| **Bootstrap** | recovery kit | none | `epoch_seq=0`, genesis policy, genesis control, genesis checkpoint, root certificate; **no snapshot exists yet and the head is the explicit empty marker**. The root certificate is **self-signed**; the kit signs the checkpoint that names its key fingerprint, and that fingerprint becomes `TrustAnchor`. | policy, control, certificate, checkpoint | re-read; kit signs again |
| **Enroll** | root | control C, epoch E | certificate for the new device, `epoch_seq=E+1`, new wrappers, head re-encrypted under E+1 | certificate record, snapshot blob ref, head, control, policy | discard, re-encrypt under E+1 |
| **Publish** | publisher | control C, epoch E | head advances to the new snapshot and carries `publication_count+1`; epoch and control unchanged | snapshot blob ref, head | re-read, discard candidate |
| **Policy change** | root | control C, epoch E | new policy document, `epoch_seq=E+1`, new key, new wrappers, head re-encrypted, **reissued certificates for any device whose role changed** | certificate records, snapshot blob ref, head, control, policy | discard, re-encrypt |
| **Revoke** | root | control C, epoch E | device added to `revoked`, `epoch_seq=E+1`, wrappers to the remaining set, head re-encrypted | snapshot blob ref, head, control, policy | discard, re-encrypt |
| **Rotate** | root | control C, epoch E | `epoch_seq=E+1`, new wrappers, head re-encrypted | snapshot blob ref, head, control, policy | discard, re-encrypt |
| **Root rotation** | old root plus kit | control C, epoch E | new root certificate, `epoch_seq=E+1` | snapshot blob ref, head, control, policy, certificate | discard, re-encrypt |
| **Reissue kit** | root only | control C, epoch E | replacement kit anchor in the control record, accepted only above the current checkpoint; `epoch_seq` unchanged and the head is untouched | control, checkpoint | retry after re-read |
| **Recover** | kit, plus a surviving root device for anything that rewrites the head | control C, or the kit checkpoint when control is unavailable | new root certificate at `epoch_seq+1`; head rewritten **only** when a device that can decrypt the current head is present | certificate, control, policy; snapshot blob ref and head when a decrypting device participates | kit-only: authorization restored, freshness-unverified, inspection and export only |

Every administrative transition advances the epoch, which means the live head is re-encrypted under the
successor key and written as a new first blob reference. There is no transition that changes the epoch
without rewriting the head.

`epoch_seq` assignment is serialized by the fence. Two root devices cannot both mint `N+1`; the second
loses on `InvalidSwap` and must re-read.

Administrative transitions prepare successor state in this order: authorize against the predecessor,
construct the successor policy and wrappers, allocate the publication identity, encrypt the candidate
under the **successor** epoch, upload, then commit the batch. An ordinary publication encrypts under the
current epoch and changes only head and count.

## Bootstrap anchor

The kit's public anchor must be pinned independently of the provider: printed with the kit, recorded in the
checkpoint the user keeps, and never read back from the account. A bootstrap that resolves its own root
from the PDS is circular and is rejected.

## Unknown outcomes

A commit can fail without an answer. ADR 006's durable attempt contract applies here in full: the marker
identity, expected record CID, candidate CID, epoch and policy digest are persisted before the send; an
unknown outcome is resolved by a verified re-read; `committed-but-superseded` is recorded and never
retried; `not-landed` is the only state that permits a fresh attempt; `unavailable` is terminal for that
decision.

## Rotation

An epoch rotates on every administrative transition, and after either `max_publications` publications or
`max_epoch_age`, whichever comes first. Both thresholds are policy fields, so an implementation reads them
rather than inventing them.

`publication_count` lives in the **head** record, not the control record. It is initialised to zero at
bootstrap and resets to zero at each epoch change, and it is incremented by the same fenced write that
advances the head, so it remains authenticated state rather than a local guess.

It sits in the head because ordinary publication is publisher-authorized and the control record is
root-authorized. Keeping the counter in control would mean a publisher could not publish at all, which an
earlier draft of this record required without noticing. `max_publications` is a `uint32` in the range 1 to 100000; `max_epoch_age`
is a `uint32` count of seconds in the range 3600 to 31536000.

The count comparison happens before preparing a publication, and a device at or above the threshold does not
prepare one at all. First-seen time for the current epoch is persisted in local state, so a restart does not
reset it; if local state is lost, the device treats the age trigger as met rather than restarting the clock,
because restarting it would postpone rotation indefinitely.

Rotation is not authorization. It moves no device into or out of a role, so it does not conflict with ADR
006's rule that wall-clock time never authorizes a vault action. Age is evaluated against a locally
tracked first-seen time for the current epoch; with no trusted clock the count trigger alone applies. When
either threshold is met and no root-capable device is present, the device stops publishing and reports
that rotation is due.

## Retention

Deletion is an obligation on every authorized device. A device keeps exactly the epochs its `retention
points` need and deletes the rest, so the tunable is how many recovery points are retained, not a raw
epoch count. The default is 3, as a policy field.

Compliance is attested, not verified. The attestation is a separately **device-signed** object, not a field
the publisher may author: it names its subject `device_id`, the vault, the policy digest, the declared
retention floor, the recovery points still held, and the control CID it was made against. The device's own
signature is what makes it an attestation; a publisher relaying it cannot alter it without invalidating it.

Attestations are published as their own record (ADR 015's attestation object), never inside the control
record. An earlier draft had publishers append attestations to ordinary control updates, which quietly
required publisher authority to write a root-authorized record — the same defect that kept the publication
counter in control. A restore-only device hands its signed attestation to a publisher over the local IPC
channel, and the publisher publishes those bytes unchanged. Relaying is a transport detail, not an
authority.

A declared floor below the `policy retention floor` is surfaced to the user and the device is treated as
compromised for confidentiality purposes. Nothing here revokes anything: a revoked or offline device that
never deletes keeps its access, and a device that retains its X25519 private key can unwrap archived
wrappers indefinitely.

Pruning requires a complete snapshot at the retention boundary with a verified checkpoint, and never
prunes the epoch of the live head.

## Checkpoints and rollback

A checkpoint names a snapshot CID, `epoch_seq`, policy digest, control CID and signer. A device compares a
supplied state against its held checkpoint and accepts **equality or a verified descendant**, following the
`prev_control_cid` chain.

Two distinct outcomes follow. A state below the checkpoint, or one whose ancestry does not reach it, is
**rejected**. A state that is a genuine descendant is accepted even when the device has not seen the
intervening history, so a provider that withholds newer records is not detectable by this check alone;
that is an availability and equivocation limit, not a rollback.

First restore has no local checkpoint. The kit's checkpoint is then the only anchor, and everything below it
is rejected. With no kit checkpoint at all, the device enters the freshness-unverified state and is
restricted to inspection and export.

## Recovery kit

32 random bytes from `crypto/rand`, shown as grouped base32 with the vault identifier and the anchor
fingerprint. Derived with distinct HKDF labels: a **recovery signing key** that may sign a new root
certificate, a bootstrap transition, a checkpoint, and a kit reissue; and a **checkpoint seed**. It derives
no content key, so a stolen kit does not decrypt stored snapshots.

A stolen kit can mint a new root certificate and administer the vault. That is the cost of an anchor
independent of the provider, and it is recorded rather than softened. A kit-signed root replacement is
accepted only above the last kit-announced checkpoint, so a retired kit cannot re-root history; reissuing a
kit therefore records a new anchor and retires the old one at that checkpoint.

Losing the kit is recoverable while a **root-capable** device remains, which signs a reissue and rotates
the root. A publisher or restore-only device cannot re-root.

The kit does not recover data the provider no longer holds, and it derives no content key, so a kit alone
cannot rewrite the head: every epoch-changing transition re-encrypts the live head, and encrypting requires
the current plaintext. Three artifacts are therefore required for full recovery, and the specification names
them because "recovery" without them is a promise the design cannot keep:

1. the kit, for authorization;
2. the independent complete export, which carries the snapshot payloads; and
3. a secret that can decrypt that export, since the export is encrypted under an epoch key the kit does not
   hold.

Without all three, recovery stops at authorization plus inspection and export, and the specification says
so rather than implying the head can always be rebuilt.

## Consequences

Recovery from a concurrent revocation does not include bytes already transmitted. The exposure window is
narrowed by successor-epoch staging and rotation; it is not closed.

Revocation means "cannot publish after this point", not "cannot read anything ever again".

## Alternatives

Claiming atomic staging was rejected: the fence cannot enforce it.

Per-publication epochs were rejected: they multiply wrapper sets and control transitions without
tightening the decryption capability, which rotation and deletion address instead.

One device key for both signing and encryption was rejected: every party able to verify a signature would
be able to decrypt.
