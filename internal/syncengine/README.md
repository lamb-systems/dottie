# Sync engine — not implemented

Own three-way file/key reconciliation, preview, provider-scoped journaled apply,
conditional rollback and remote synchronization. Distinguish local observation,
applied base, remote intent and pending edits.

Never treat new-machine absence as deletion or write conflict markers into live
configuration. Preserve both conflicting versions until resolution. Rollback must
not overwrite intervening user changes.
