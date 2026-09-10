# Security Policy

## Supported status

This repository is a research prototype. No revision is currently designated production-ready.

## Reporting a vulnerability

Use GitHub **Security → Report a vulnerability** to submit findings privately. Include:

1. the affected commit;
2. the violated security invariant;
3. a minimal deterministic reproducer;
4. the observed and expected verifier disposition;
5. whether any external target or sensitive data was involved.

Do not include credentials, private keys, access tokens, customer data, or third-party target data in a public issue.

## Scope

High-value reports include authorization/effect ordering flaws, cancellation races, evidence truncation or forgery, verifier false positives, destination-binding errors, credential exposure, and post-closure audit mutation.

Only test environments and targets you own or have explicit permission to assess.

