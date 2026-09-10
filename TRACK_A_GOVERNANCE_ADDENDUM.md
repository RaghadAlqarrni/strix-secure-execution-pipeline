# Track A governance addendum

Owner-approved addendum to `DEC7_FINAL_CONTRACT_FOR_SIGNATURE_V3.md`.

## Activation

Track A was activated only by the exact independent owner command naming the
contract SHA-256
`adbacca5ff4115ba1eb7b9c9a6eec758d280d0e3c32440e8bd3b83a41f840651`.

## Tree protection and hashes

The canonical tree hash includes source, contracts, fixtures, manifests and
verifiers. Runtime outputs and only the pre-declared ignored paths are excluded.
The candidate tree is audited read-only; execution occurs on disposable copies
or writes outside the candidate tree.

The sequence is: pre-remediation hash; remediation; candidate hash; Measurement
Evidence Bundle; independent remediation audit; fresh full-tree Pass 6; final
hash equality check; Final Sealed Evidence Bundle; DEC-6 re-freeze.

If DEC-6 changes an in-tree governance document, a separate refrozen-tree hash
is recorded and the governance-only diff is included. It may not alter source,
fixtures, manifests or verifiers.

## Evidence bundles

The Measurement Evidence Bundle contains raw execution evidence and the pre and
candidate hashes. The Final Sealed Evidence Bundle embeds that first archive
unchanged, plus the independent audit, Pass 6, final hash and equality proof.
The final archive SHA-256 is a sidecar file, never a member of the archive it
hashes.

## Locked boundaries

`REQUIRED_B` remains exactly B1 through B9. B7-L2, multicast, PEP-only peer
isolation and MAC spoof resistance remain new requirements outside Track A.
Strix is prohibited locally, experimentally and in the field until Track B also
passes and the owner issues a separate target/scope/time/budget/kill-switch
authorization. Track A completion does not automatically run a release gate.
