# Architecture decisions

Numbered records of decisions that shaped this project. They are served publicly from this directory,
so they contain identifiers and measurements but no secrets.

Each record states what forced the decision, what was decided, what becomes true as a result, and what
was rejected. Where a decision was reached after a wrong turn, the turn is recorded. A record that reads
as if the design arrived fully formed is not useful to anyone reading it later.

| ADR | Decision |
| --- | --- |
| [004](004-admission-before-upload.md) | Admit a snapshot before uploading it, on the encrypted length |
| [005](005-confidentiality-and-epochs.md) | One defense per threat; encryption before upload is the only one that exists |
| [006](006-publication-contract.md) | What a verified revision proves, and what publication must record |
| [007](007-three-authorities.md) | Account, device and recovery authority are separate |
| [008](008-dependencies-and-native-boundary.md) | Dependencies, and the two build boundaries |
| [009](009-provider-support-and-evidence.md) | Describe providers, do not label them |
| [010](010-spaces.md) | Spaces stays out of scope, with a dated reassessment |
| [011](011-operator-visible-states.md) | "Local only" is not one state |
| [012](012-resource-growth.md) | Bounded proofs, bounded growth, safe pruning |
| [013](013-feasibility-verdict.md) | The feasibility verdict, in three permissions |

Decisions 001 to 003 predate this directory and are preserved in the planning graph. These continue the
numbering rather than restarting it.
