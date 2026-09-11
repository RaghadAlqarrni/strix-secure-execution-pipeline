# API Key Management Standard

Version: 1.0  
Status: required design; implementation evidence pending.

## Required controls

1. Use one dedicated OpenAI project or service identity per environment and workflow.
2. Create a **Restricted** key and grant only the endpoints required by the application.
3. Never use a personal all-access key for unattended execution.
4. Store secrets in an OS or managed secret vault. Never store them in source files, Git history, shell history, logs, screenshots, prompts, or evidence bundles.
5. Inject the secret at runtime through a protected process environment or secret-manager interface.
6. Keep only a non-secret credential reference in audit records.
7. Set spend and rate limits appropriate to the workflow.
8. Review key inventory and last-use evidence monthly.
9. Rotate active keys at least every 90 days and immediately after suspected exposure, personnel change, scope change, or control failure.
10. Revoke unused and replaced keys before deleting local references.
11. Record key ID, owner, purpose, scopes, creation, rotation, revocation, and evidence location in a private register. Never record the secret value.

## Repository enforcement

- GitHub secret scanning runs on this public repository.
- Private vulnerability reporting is enabled.
- Local publication checks search for common private-key and token patterns.
- Application code must fail closed when a required secret reference cannot be resolved.

## Evidence required before Daybreak attestation

- screenshot or export showing a dedicated project/service identity;
- restricted endpoint permissions;
- vault entry metadata without the secret;
- documented spend limits;
- completed rotation/revocation drill;
- private key register with current owner and review date.

