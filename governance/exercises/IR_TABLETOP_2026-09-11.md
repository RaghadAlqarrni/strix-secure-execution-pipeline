# Incident-response tabletop: IR-TTX-2026-09-11

Date: 2026-09-11  
Scope: Strix secure-execution pipeline and its future OpenAI credential  
Mode: sanitized tabletop; no real credential, target, account, or external network action

## Scenario

A fake OpenAI credential identifier is reported together with an attempted request to `out-of-scope.example.invalid`. The exercise tests whether the documented incident-response process leads the operator to stop execution, contain the account risk, preserve evidence, assess authorization, select notification paths, and require a gated recovery.

## Result

All nine procedural stages passed in the tabletop. The source event is committed as `simulated_incident_event.json`; its SHA-256 digest is recorded in `IR_TABLETOP_2026-09-11.json` and checked by `verify_tabletop.py`.

This result proves only that the documented procedure was walked through and that the sanitized evidence record is internally consistent. It does not prove live OpenAI key revocation, a working secret vault, model-use monitoring, organizational certification, SSO/RBAC, domain email, or managed endpoint controls.

## Required owner action

The repository owner must read and adopt `INCIDENT_RESPONSE.md`, keep it current, and follow it during real incidents. After a dedicated restricted credential and vault exist, perform a separate live revocation-and-replacement drill using private evidence.
