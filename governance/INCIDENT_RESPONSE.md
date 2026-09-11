# Incident Response Plan

Version: 1.0  
Effective date: 2026-09-11  
Owner and incident commander: repository owner  
Review frequency: quarterly and after every incident  
Scope: GitHub, OpenAI accounts and API credentials, the Strix secure-execution pipeline, audit evidence, test systems, and authorized bug-bounty targets.

## Severity

| Severity | Trigger | Initial response target |
|---|---|---|
| SEV-1 | Credential exposure, suspected unauthorized target access, active abuse, or evidence integrity compromise | Stop activity immediately |
| SEV-2 | Policy bypass, verifier false positive, unapproved outbound effect, or account compromise without confirmed abuse | Contain within one hour |
| SEV-3 | Non-exploitable control defect, dependency alert, or incomplete evidence | Triage within one business day |

## Response procedure

1. **Stop:** activate the project kill switch, stop agents and runners, and block new outbound execution.
2. **Contain:** revoke affected OpenAI/GitHub credentials, terminate active sessions, isolate the affected device or VM, and preserve the original logs.
3. **Assess authorization:** identify the exact program, target, scope, time window, request, policy generation, key identity, and external effect involved.
4. **Preserve evidence:** copy audit logs and relevant configuration into a read-only incident directory; record SHA-256 hashes and UTC timestamps.
5. **Notify:** contact OpenAI immediately for suspected misuse or compromised approved credentials. Notify the affected bug-bounty program or system owner through its authorized disclosure channel when required.
6. **Eradicate:** remove exposed credentials, repair the policy or verifier defect, patch dependencies, and rebuild from a known source commit.
7. **Recover:** issue separate replacement credentials with minimum permissions, rerun local controls, and resume only after the release gate and authorization scope pass.
8. **Review:** write a blameless incident report covering timeline, impact, root cause, containment, evidence, control failures, and corrective actions.

## Evidence record

For every incident, create a private record containing:

- incident identifier, severity, UTC start and detection times;
- affected accounts, projects, keys, devices, and authorized targets;
- source commit and configuration hashes;
- decisions and actions with owner and timestamp;
- notification records;
- credential revocation and replacement evidence;
- recovery validation and approval;
- post-incident corrective-action owner and due date.

Never place credentials, personal data, private vulnerability details, or third-party target evidence in a public GitHub issue.

## Tabletop exercise

Before representing this control as operational, perform one simulated leaked-API-key exercise:

1. use a fake key identifier;
2. walk through stop, revoke, preserve, notify, replace, and recover;
3. record start/end time and every missed step;
4. update this plan;
5. store the signed result privately because it may contain account metadata.

