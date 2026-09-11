# Trusted Access Control Status

Assessment date: 2026-09-11  
Owner: RaghadAlqarrni  
Scope: this repository and the OpenAI credentials used for its authorized security-research workflows.

This file records implemented controls and gaps. It is not a certification and must not be used to support a legal attestation unless the listed evidence is current and the control is actually followed.

| Daybreak attestation | Status | Current evidence | Required next action |
|---|---|---|---|
| SOC 2 Type II, ISO 27001, or equivalent | Not met | No organizational certification | Do not attest |
| SSO, MFA, least-privilege roles, and RBAC for every TAC workspace | Not met | GitHub/OpenAI MFA not independently evidenced; no managed IdP, SSO, or RBAC workspace | Enable MFA; obtain a verified domain and managed workspace before claiming the full control |
| Vaulted API keys, rotation/revocation, service identities, least privilege, and scoped permissions | Partial | Public repository secret scan found no credential; policy documented in `KEY_MANAGEMENT.md` | Create a dedicated OpenAI project/service identity, use a restricted key, store it in a secret manager, record rotation/revocation evidence |
| Monitor cyber use and retain model-use logs | Partial | Network-effect audit lifecycle exists; model prompt/output usage logging is not implemented | Implement the schema and retention controls in `MODEL_USE_MONITORING.md` |
| Documented incident-response process | Documented; exercise pending | `INCIDENT_RESPONSE.md` | Perform and record the first tabletop exercise before attesting |
| Domain-specific emails for TAC users | Not met | No verified organizational domain evidenced | Use a domain-owned mailbox and verify the domain |
| Enterprise-controlled devices with encryption, patching, endpoint protection, and endpoint management | Partial | Microsoft Defender active and current Windows security updates observed; disk encryption unavailable to the audit; device is not domain/MDM managed | Verify disk encryption and enroll the device in managed endpoint control |

## Current safe form decision

Do not select any full enterprise attestation solely because this document exists. The incident-response item becomes supportable only after the owner reviews this policy and completes the recorded tabletop. The key-governance and monitoring items remain incomplete until their technical evidence exists.

