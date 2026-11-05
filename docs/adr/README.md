# Architecture decisions

These numbered records document decisions that shaped this project. This directory is public, so the
records contain identifiers and measurements but no secrets.

Each record states what forced the decision, the decision itself, its consequences, and the rejected
alternatives. Records include wrong turns that led to a decision; omitting them makes the design look
fully formed and leaves later readers without useful history.

| ADR | Decision |
| --- | --- |
| [004](004-admission-before-upload.md) | Admit a snapshot before uploading it, on the encrypted length |
| [005](005-confidentiality-and-epochs.md) | One defense per threat, and none of them is implemented |
| [006](006-publication-contract.md) | What a verified revision proves, and what publication must record |
| [007](007-three-authorities.md) | Account, device and recovery authority are separate |
| [008](008-dependencies-and-native-boundary.md) | Dependencies, and the two build boundaries |
| [009](009-provider-support-and-evidence.md) | Describe providers, do not label them |
| [010](010-spaces.md) | Spaces stays out of scope, with a dated reassessment |
| [011](011-operator-visible-states.md) | "Local only" is not one state |
| [012](012-resource-growth.md) | Bounded proofs, bounded growth, safe pruning |
| [013](013-feasibility-verdict.md) | The feasibility verdict, in three permissions |
| [014](014-vault-state-machine.md) | The vault authorization and key state machine |
| [015](015-envelope-and-primitives.md) | Snapshot envelope, primitives and signed bytes |

Decisions 001 to 003 predate this directory and remain in the planning graph. These records continue
the numbering rather than restarting it.
