# Service — not implemented

Own the single coordinator, private IPC, scheduling and CLI use cases. Foreground
and daemon operation share this implementation and an exclusive state lock. The
CLI must not bypass the journaled engine to modify application preferences.
