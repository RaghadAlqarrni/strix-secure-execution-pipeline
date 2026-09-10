# Independent Review Status

Review date: 2026-09-11  
Public snapshot commit source: `8e924860bd9b6f27381c6964ec1f585edf4d5ac3`  
Disposition: **research candidate; not release-ready**

## Verified improvements

Independent source review confirmed that this snapshot materially improves the prior lifecycle design:

- AUTH, permit, release, and cancellation use one positive global sequence authority.
- `PERMIT_RELEASED` is represented as durable evidence.
- Cancellation in-flight reconstruction uses `P < C < R`.
- K-closure quiescence fields are mandatory.
- KILL, ACK/TIMEOUT, and RUN_CLOSED receive explicit semantic validation.
- RUN_CLOSED is an absorbing final audit record.

The transported review package restored successfully, its candidate descended from the required predecessor, and its 56 payload hashes matched.

## Open blocking findings

An independently generated, correctly chained and authenticated corpus received `PROVEN` for six cases that must not certify:

1. gateway history without `STARTUP`;
2. ALLOW hostname-prefix spoof;
3. ALLOW userinfo/authority spoof;
4. ALLOW request-path contradiction;
5. ALLOW authority-port contradiction;
6. CONNECTION_TERMINATED hostname-prefix spoof.

The main causes are string-prefix URL validation and the absence of an explicit gateway-versus-fixture history profile.

## Required correction

The next protocol revision must:

- introduce an explicit certifying gateway profile that requires STARTUP;
- retain startup-less fixtures only as non-certifying mechanics tests;
- parse and compare URL authorities structurally;
- reject userinfo, fragments, malformed ports, wrong schemes, host-prefix matches, and non-equivalent ports;
- record enough sanitized request fields to recompute the intent digest;
- bind method, scheme, canonical host, effective port, exact path/query, and body length;
- keep credentials and raw credential-bearing requests out of audit evidence.

External key custody, trusted configuration, revocation, WORM publication, target-filesystem compatibility, host enforcement, and production behavior remain unproven.

