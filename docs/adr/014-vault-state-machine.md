# 014 — The vault authorization and key state machine

Status: accepted, 2026-10-31. Amends ADR 005, 006, 012 and 013, each marked in place. ADR 003 predates
this directory and lives in the planning graph; the constraints it contributes are restated here rather
than cited, so a public reader is not sent to a document they cannot open.

## Context

A fence protects promotion, not transmission. `uploadBlob` precedes the fenced `applyWrites`. The
fence work and contention measurements showed that a candidate rejected after blob processing stays
anonymously retrievable. An earlier draft claimed epoch equality made "never stage under an epoch a revoked device
holds" a checkable predicate. It does not. The ordering section states the available guarantee.

A certificate that binds only a signing key leaves the encryption key open to substitution: wrapping
needs a recipient key, and nothing authenticated that key. An earlier draft also called four unrelated
things "the floor"; each now has a distinct name.

## Decision

Every section below is normative. Terms and object schemas precede the sections that depend on them.

## Terms

- `epoch_seq` — monotonic integer naming a content-key generation. Ordering only, never a time.
- `cert_epoch` — the `epoch_seq` at which a certificate was issued.
- `checkpoint` — a signed object naming a snapshot CID, `epoch_seq`, policy digest and signer, used for
  rollback detection.
- `confidentiality floor` — the oldest known `epoch_seq` with any surviving retained material, including protected rollback backups; it is not a count of content keys.
- `recovery floor` — the oldest epoch with a complete authenticated material inventory; it governs pruning eligibility.
- `policy retention floor` — the minimum signed `confidentiality floor` the current policy requires of every device.
- `retention points` — recovery positions identified by `(epoch_seq, snapshot_cid, policy_digest, control_cid)` and independently authenticated control evidence.

## Signed objects

Four objects carry signatures. The fields are normative; the envelope specification defines their
encodings.

| Object | Fields |
| --- | --- |
| **Policy** | `v`, `vault`, `epoch_seq`, `roles[]` (`device_id`, role), `recipients[]` (`device_id`, `key_id`, X25519 public key), `policy_retention_floor`, `retained_recovery_points`, `max_publications`, `max_epoch_age`, `recovery_anchor` (kit anchor fingerprint), `prev_policy_digest` |
| **Control** | `v`, `vault`, `epoch_seq`, `policy_digest`, `head_snapshot_cid`, `revoked[]` (`device_id`, `cert_epoch`), `prev_control_cid`, `signer` |
| **Head** | `v`, `vault`, `epoch_seq`, `policy_digest`, `snapshot_cid`, `blob_cid`, `publication_count`, `prev_head_cid`, `signer` |

`control.head_snapshot_cid` names the snapshot the epoch **began** with at the last administrative
transition. It does not name the live head. At genesis the control and count-zero head name the same
canonical empty snapshot. An ordinary publication advances the head within the epoch without writing
a control record, so the two intentionally differ after the first publication. A reader requires the
head's `epoch_seq` and `policy_digest` to equal the control's and must **not** require matching snapshot
identifiers. An earlier draft required that match, making the vault unreadable after the first
publication and blocking every later transition.
| **Certificate** | `v`, `vault`, `device_id`, `key_id`, Ed25519 public key, X25519 public key, role, `cert_epoch`, `issuer` (`device_id` of the signing root, or the bootstrap anchor), `revocation_ref` |
| **Checkpoint** | `v`, `vault`, `snapshot_cid`, `epoch_seq`, `policy_digest`, `anchor` (root signing-key fingerprint the kit vouches for), `control_cid`, `signer` |

Each object carries `prev_*` where shown. An ancestry check follows authenticated digests rather than
trusting a counter. Except at bootstrap, a verifier rejects a control record whose `prev_control_cid`
is not the control it observed.

The recovery kit vouches for an anchor; it does not issue certificates. A device root certificate is
self-signed. The kit-signed checkpoint pins its signing-key fingerprint, which the verifier receives
as `TrustAnchor`. An earlier draft had the kit sign the root certificate itself. No verifier can
accept that: chain resolution terminates at a self-signed certificate, leaving a kit-issued root
without a verifiable issuer.

Root succession requires **two signatures on one control record**: the retiring root signs
`"dottie/v1/root-retire"` and the kit signs `"dottie/v1/root-appoint"`, both over the same successor
certificate digest. A control record that changes the root is accepted only when both signatures are
present and verify against the predecessor state. A new root certificate alone is never sufficient.
This prevents a stolen kit from silently appointing itself without the retiring root and prevents a
stolen root device from retiring the kit anchor.

## Authorization predicate

A device may perform an action when all of these hold: its certificate chains to the vault anchor, names
this vault, is not listed in the control record's `revoked` set, satisfies `epoch_seq >= cert_epoch`, and
the policy **at the predecessor state** assigns the required role to its `device_id`.

Check administrative authority against the predecessor before validating the successor. Checking the
successor's own policy would let a transition authorize itself. If certificate and policy disagree on
a role, validation fails; neither takes precedence.

## Ordering

Three linearization points, and no fourth:

1. **Observe** — a verified revision is read, yielding epoch E, policy digest P, control CID C, head H.
2. **Transmit** — the candidate blob is uploaded under E. These bytes cannot be withdrawn.
3. **Commit** — a fenced `applyWrites` against the observed revision either commits or loses.

Promotion has one guarantee: *a candidate is promoted only if its epoch and policy digest equal those
in the control record it commits against.*

Three intervals, distinct:

- **Preparation to transmission** — client-local. A device should discard a prepared candidate when the
  control record changes, but nothing enforces that on a delayed or hostile client.
- **Transmission to outcome** — bounded by the transport's own timeouts and the fence. After commit the
  outcome is decided; after transmission the bytes are out regardless.
- **Decryption capability** — indefinite for anyone holding epoch E or an unwrap capability for E.

Rotation bounds the first interval in practice by making prepared candidates stale sooner. It does
not bound the second and cannot bound the third. Rotation limits future authorized key use, not the
lifetime of already-disclosed ciphertext.

## Transitions

Each row names the authority, the predecessor against which it must be checked, the complete write
set, and the outcome of a lost race. A losing transition re-reads and re-derives. It never reuses a
prepared candidate after a policy or epoch change.

| Transition | Authority | Predecessor | Successor state | Atomic write set | Lost race |
| --- | --- | --- | --- | --- | --- |
| **Bootstrap** | recovery kit | none | `epoch_seq=0`, genesis policy, genesis control, genesis checkpoint, root certificate, count-zero head and canonical empty snapshot. The root certificate is **self-signed**; the kit signs the checkpoint naming the final control CID and snapshot CID, and the certificate fingerprint becomes `TrustAnchor`. | policy, control, certificate, checkpoint, snapshot blob reference, head | re-read; kit signs again |
| **Enroll** | root | control C, epoch E | certificate for the new device, `epoch_seq=E+1`, new wrappers, head re-encrypted under E+1 | certificate record, snapshot blob ref, head, control, policy | discard, re-encrypt under E+1 |
| **Publish** | publisher | control C, epoch E | head advances to the new snapshot and carries `publication_count+1`; epoch and control unchanged | snapshot blob ref, head | re-read, discard candidate |
| **Policy change** | root | control C, epoch E | new policy document, `epoch_seq=E+1`, new key, new wrappers, head re-encrypted, **reissued certificates for any device whose role changed** | certificate records, snapshot blob ref, head, control, policy | discard, re-encrypt |
| **Revoke** | root | control C, epoch E | device added to `revoked`, `epoch_seq=E+1`, wrappers to the remaining set, head re-encrypted | snapshot blob ref, head, control, policy | discard, re-encrypt |
| **Rotate** | root | control C, epoch E | `epoch_seq=E+1`, new wrappers, head re-encrypted | snapshot blob ref, head, control, policy | discard, re-encrypt |
| **Root rotation** | old root plus kit | control C, epoch E | new root certificate, `epoch_seq=E+1` | snapshot blob ref, head, control, policy, certificate | discard, re-encrypt |
| **Reissue kit** | root only | control C, epoch E | replacement kit anchor in the control record, accepted only above the current checkpoint; `epoch_seq` unchanged and the head is untouched | control, checkpoint | retry after re-read |
| **Recover** | kit, plus a surviving root device for anything that rewrites the head | control C, or the kit checkpoint when control is unavailable | new root certificate at `epoch_seq+1`; head rewritten **only** when a device that can decrypt the current head is present | certificate, control, policy; snapshot blob ref and head when a decrypting device participates | kit-only: authorization restored, freshness-unverified, inspection and export only |

Every administrative transition advances the epoch, re-encrypts the live head under the successor key
and writes it as a new first blob reference. No transition changes the epoch without rewriting the head.

The fence serializes `epoch_seq` assignment. Two root devices cannot both mint `N+1`; the second
loses on `InvalidSwap` and must re-read.

Administrative transitions prepare successor state in this order: authorize against the predecessor,
construct the successor policy and wrappers, allocate the publication identity, encrypt the candidate
under the **successor** epoch, upload, then commit the batch. An ordinary publication encrypts under the
current epoch and changes only head and count.

## Bootstrap anchor

Pin the kit's public anchor independently of the provider: print it with the kit, record it in the
checkpoint the user keeps, and never read it back from the account. Reject a bootstrap that resolves
its own root from the PDS; that trust is circular.

## Unknown outcomes

A commit can fail without an answer. ADR 006's durable attempt contract applies here in full: the marker
identity, expected record CID, candidate CID, epoch and policy digest are persisted before the send; an
unknown outcome is resolved by a verified re-read; `committed-but-superseded` is recorded and never
retried; `not-landed` is the only state that permits a fresh attempt; `unavailable` is terminal for that
decision.

## Rotation

An epoch rotates on every administrative transition and after either `max_publications` publications
or `max_epoch_age`, whichever comes first. Implementations must read both thresholds from policy
fields, not invent them.

`publication_count` lives in the **head** record, not the control record. It starts at zero at
bootstrap and resets to zero at each epoch change. The fenced write that advances the head also
increments the count, keeping it authenticated rather than locally estimated.

The counter belongs in the head because ordinary publication is publisher-authorized, while the
control record is root-authorized. Keeping it in control would prevent publishers from publishing,
an unintended requirement of an earlier draft. `max_publications` is a `uint32` in the range 1 to 100000;
`max_epoch_age` is a `uint32` count of seconds in the range 3600 to 31536000.

A device compares the count before preparing a publication and prepares nothing at or above the
threshold. Local state persists the current epoch's first-seen time across restarts. If that state is
lost, the device treats the age trigger as met; restarting the clock would postpone rotation indefinitely.

Rotation is not authorization. It moves no device into or out of a role, so it does not conflict with ADR
006's rule that wall-clock time never authorizes a vault action. Age is evaluated against a locally
tracked first-seen time for the current epoch; with no trusted clock the count trigger alone applies, and
publication exposes `PublicationAgeTriggerNotEvaluatedNoTrustedClock`. Refusing solely because the clock is
absent would block a legitimate caller when the available count trigger permits publication. When either
threshold is met and no root-capable device is present, the device stops publishing and reports that rotation
is due.

## Retention

Deletion is an obligation on every authorized device. A device keeps exactly the epochs its `retention
points` need and deletes the rest, so the tunable is how many recovery points are retained, not a raw
epoch count. The default is 3, as a policy field.

**What is deleted, and what is never held.** Dottie does not persist content keys. A publication's content
key and nonce are supplied by the caller, used to seal, and discarded; nothing writes them to local state,
so there is no key material on disk to retain or delete. The retained material a device actually holds for
an epoch is cached ciphertext (downloaded snapshots and blobs) and rollback copies. Retention and pruning
therefore apply to those, and the attestation below attests the declared floor, the retained recovery points
and the deletion of that retained material. An earlier draft stated the obligation over "epoch keys", which
presupposed a key store the implementation deliberately does not have; deleting nothing is a stronger
property than deleting on schedule, and this record says so rather than implying a store that does not exist.

Compliance is attested, not verified. The attestation is a separate **device-signed** object, not a
field the publisher may author. It names its subject `device_id`, the vault, the policy digest, the
declared retention floor, the recovery points still held, and the control CID it was made against.
The device's signature makes it an attestation; a publisher cannot alter it during relay without
invalidating it.

Attestations have their own record (ADR 015's attestation object); they never appear inside the control
record. An earlier draft had publishers append attestations to ordinary control updates. That required
publisher authority to write a root-authorized record, the same defect as keeping the publication
counter in control. A restore-only device sends its signed attestation to a publisher over the local
IPC channel. The publisher publishes those bytes unchanged. Relay supplies transport, not authority.

The signed attestation floor is the `confidentiality floor`, not the `recovery floor`. An unknown-epoch holding means the confidentiality floor is unknown; it must not be reported as a positive or policy-compliant floor. A declared floor below the `policy retention floor` is surfaced to the user and the device is treated as compromised for confidentiality purposes. Nothing here revokes anything: a revoked or offline device that never deletes keeps its access, and a device that retains its X25519 private key can unwrap archived wrappers indefinitely.

Each retained point requires its exact CID-verified envelope body. Its authenticated control must be current or a descendant of the held checkpoint; the boundary point matches the checkpoint's epoch, snapshot CID, policy digest and control CID exactly. A later same-epoch publication cannot replace that boundary. Ordinary-publication points require their signed head and an envelope parent equal to the head's `prev_head_cid`. Pruning requires complete inventories, revalidated payload hashes, the exact checkpoint boundary and a live head strictly later than the boundary.

## Checkpoints and rollback

A checkpoint names a snapshot CID, `epoch_seq`, policy digest, control CID and signer. A device compares a
supplied state against its held checkpoint and accepts **equality or a verified descendant**, following the
`prev_control_cid` chain.

A state below the checkpoint, or whose ancestry does not reach it, is **rejected**. A genuine
descendant is accepted even if the device has not seen the intervening history. This check alone
cannot detect a provider withholding newer records; that is an availability and equivocation limit,
not a rollback.

First restore has no local checkpoint, so the kit's checkpoint is the only anchor. Everything below
it is rejected. Without a kit checkpoint, the device enters the freshness-unverified state, restricted
to inspection and export.

## Recovery kit

32 random bytes from `crypto/rand`, shown as grouped base32 with the vault identifier and the anchor
fingerprint. Derived with distinct HKDF labels: a **recovery signing key** that may sign a new root
certificate, a bootstrap transition, a checkpoint, and a kit reissue; and a **checkpoint seed**. It derives
no content key, so a stolen kit does not decrypt stored snapshots.

A stolen kit can mint a new root certificate and administer the vault. An anchor independent of the
provider carries that cost without qualification. A kit-signed root replacement is accepted only
above the last kit-announced checkpoint, so a retired kit cannot re-root history. Reissuing a kit
records a new anchor and retires the old one at that checkpoint.

Losing the kit is recoverable while a **root-capable** device remains, which signs a reissue and rotates
the root. A publisher or restore-only device cannot re-root.

The kit cannot recover data the provider no longer holds and derives no content key. A kit alone
therefore cannot rewrite the head: every epoch-changing transition re-encrypts the live head, which
requires the current plaintext. Full recovery requires three artifacts; without them, the design
cannot promise "recovery":

1. the kit, for authorization;
2. the independent complete export, which carries the snapshot payloads; and
3. a secret that can decrypt that export, since the export is encrypted under an epoch key the kit does not
   hold.

Without all three, recovery stops at authorization plus inspection and export. The specification
cannot promise to rebuild the head in every case.

## Consequences

Recovery from a concurrent revocation does not include bytes already transmitted. Successor-epoch
staging and rotation narrow the exposure window; they do not close it.

Revocation means "cannot publish after this point", not "cannot read anything ever again".

## Alternatives

Claiming atomic staging was rejected: the fence cannot enforce it.

Per-publication epochs were rejected: they multiply wrapper sets and control transitions without
tightening the decryption capability, which rotation and deletion address instead.

One device key for both signing and encryption was rejected: every party able to verify a signature would
be able to decrypt.
