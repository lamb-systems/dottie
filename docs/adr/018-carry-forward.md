# ADR 018: carry forward the targets a machine does not configure

Status: accepted.

## Context

A publication record holds one segment per target. Until now a push composed every segment from
the targets in the local `config.toml`, so a machine that configures only some of them published a
head that silently dropped the rest. The record is the vault's authority, not one machine's
configuration: a laptop that configures a `~/.config/nvim` target must not delete a desktop's second
target by publishing from a smaller configuration.

The obvious alternative — require every machine to configure every target — was rejected. It makes
`config.toml` a distributed-consistency artifact, and the first machine that forgets a target
publishes a head that deletes it. The lexicon was left untouched: an accepted segment already
satisfies the published schema, so carrying it forward needs no new field, no version bump and no
marker. Provenance stays local.

## Decision

A push composes configured targets fresh and copies the rest from the accepted record verbatim. The
carried segment is not re-encoded: the exact record segment, the exact blob bytes and the exact entry
contents are spliced into the single sorted candidate that review and confirmation both consume, so
the carried targets are byte-identical in the new record and keep their CIDs, modes, sizes and
settings digest.

Carry is verified before it is trusted. The accepted material the store holds for the floor is
compared against the record segment it claims to serve: a carried packed segment's bytes must hash to
the recorded CID and match the recorded size, a carried entries segment's contents must hash to the
recorded entry CIDs, and a carried settings segment's digest must equal the recorded one. A segment
with no matching material, or with material that does not reproduce the record, refuses the whole
publication.

Carried blobs are uploaded again rather than referenced by a manufactured receipt. The dispatch path
already requires an ordered upload receipt per blob, and re-uploading identical bytes yields the same
CID for the same content, so a carried segment costs one idempotent upload and needs no new evidence
type. A receipt is never invented from an old CID, and the provider's own deduplication is what makes
the re-upload cheap.

The union is validated as one record before any consent is shown: a sorted, unique set of at most 256
segments, the entries bounds per segment, and the record byte cap including carried inline settings.
An oversized union refuses the publication; it is never trimmed.

A drop is explicit and separate from carry. `--drop-target` on `push` and `sync` is the only way to
leave an accepted target out of the next head. The drop set must be sorted, unique and a subset of the
published targets, must not empty the union, and is bound into the proposal record and into the
confirmation, so a stale or surplus consent refuses instead of being intersected or retargeted. A
generation without an accepted floor refuses a drop outright. Dropping the only old target is valid
when a fresh target joins the union.

The vault's authority stays the record. Local configuration decides what this machine writes; it
never decides what other machines' segments mean.

## Consequences

`push` publishes a head that preserves targets it does not know about, and reports them as carried in
its review. `sync` computes the same carry from the verified terminal record before it prints a
confirmation, binds the carried and dropped target ids into its token, and re-checks both after the
pull half: a carried target the review did not name, or a drop set that moved, refuses with
`post_pull_carry_mismatch` or `post_pull_drop_mismatch` and publishes nothing. The preview computes
carry from the record alone, which is enough because the record, not the payload bytes, is what the
candidate CID covers; the push half still verifies the bytes before it uploads them.

`sync` also states its partial success. Its pull half settles before the push half runs, so a refused
push leaves local deletions in place; the preview counts local deletions and writes separately from
the published effect of a drop and says which of them survive a refused push. A drop that cannot be
processed — no configured target, or a diverging position whose pull half changes nothing — refuses
instead of reporting success.

A carried segment costs one blob GET for the material the store already keeps and one idempotent
upload per packed target. A peer that still configures a dropped target can publish it again under
the compose-fresh rule; nothing in this design promises distributed removal.

## Alternatives

Leaving omission implicit was rejected: a machine with a narrower configuration would delete other
machines' segments with no consent and no trace. Marking carried segments in the record was rejected
because it changes the wire format for a purely local distinction. Refusing to publish from a
narrower configuration was rejected because it makes partial configuration unusable, which is the
normal case for a desktop and a laptop.
