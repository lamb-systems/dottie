# Vault — not implemented

Bounded snapshot encoding, library-backed envelopes/signatures, rooted device roles,
independent epochs, recovery/export and checkpoint lineage. No custom cryptographic
primitives, direct desktop writes or permanently retained root authority.

A recovery secret authenticates and decrypts available data, not its global freshness.
Independently retained checkpoints supply a known floor, verified through equality
or authenticated ancestry. Consent to uncertain freshness cannot override invalid
signatures, wrong keys or failed policy checks.

Exports must preserve every required ciphertext and signed control/history object;
a repository export alone is not a complete blob backup. Revocation cannot retract
plaintext or old keys already copied by a device.

Security validation is required before use with real preferences.
