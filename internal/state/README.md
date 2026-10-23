# Local state — not implemented

SQLite bases, queues, conflicts, checkpoints and the apply journal live under private
XDG state storage. Merge bases and pending work are durable, not disposable cache.
Operational credentials belong in the keyring.

Migrations must preserve existing state and recover safely from interruption. The
coordinator must hold exclusive ownership before modifying this state.
