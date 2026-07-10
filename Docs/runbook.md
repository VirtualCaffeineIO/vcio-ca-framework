# Operating Runbook

This is the half of the framework that isn't JSON. The policies define what's enforced; this document defines how the enforcement stays trustworthy over time. If you deploy the policies and skip this, you have what every other baseline gives you — a snapshot that decays.

## Enablement rings

Everything imports report-only. Enforcement happens in rings, each preceded by at least two weeks in report-only with sign-in log review and What-If validation against pilot users. CAE-dependent controls aside, report-only data is your evidence — read it before every ring.

| Ring | Policies | Gate before enabling |
|---|---|---|
| **1 — Foundation blocks** | CA000, CA001, CA002 | Break-glass verified (prereqs script passes); report-only shows no legitimate legacy-auth or device-code traffic, or identified traffic has a migration plan |
| **2 — Hygiene** | CA003, CA004, CA005, CA102, CA203, CA204, CA400, CA402, CA403 | TAP enabled and onboarding SOP in place (CA203/CA004); frontline/phoneless users have a registration path |
| **3 — Privileged, Tier 0, risk, fencing** | CA100, CA101, CA103, CA401, CA500, CA501, CA700–CA703 | Every admin has a registered phishing-resistant method **and** a compliant device or documented PAW; service-account IP fences verified against 30 days of sign-in logs; guest app list confirmed with business owners |
| **4 — Device trust and BYOD** | CA200, CA201, CA202, CA300, CA301 | Device compliance healthy (>95% of `SG-CA-Users` devices compliant or in remediation); App Protection policies assigned to **All Users** — iOS/Android with the platform's `VCIO-FLT-*-UnmanagedDevices` filter (include mode), Windows unfiltered (no managed-app filters exist for Windows; MDM coexistence + CA301's unmanaged scope handle it); BYOD mode decision recorded |
| **Per-decision** | CA006 (geo), CA600–CA602 + CA704 (agents, after inventory), CA705 (token protection pilot), 800s instances | Each has its own gate in the parameters worksheet |

Rollback: every ring change is preceded by an IntuneManagement bulk export. Reverting = set the policy to report-only, not delete — deletion loses the report-only history.

## Exclusion governance

Every exclusion group ships empty and carries its rules in its own description field. The standing rules:

1. **One group, one policy.** No exclusion group is referenced by two policies. The validator enforces this in the repo; the quarterly review enforces it in the tenant.
2. **Named owner per group** (parameters worksheet #14). The owner answers one question at review: *why is each member still here?*
3. **Quarterly access reviews** on every `SG-CA-Excl-*` group and on `SG-CA-ServiceAccounts`. Entra access reviews where licensed; a calendared manual review where not.
4. **Alert on membership change.** Log Analytics alert on group-membership modifications for all framework groups — highest priority on `SG-CA-Excl-CA002` (the MFA catch-all) and `SG-CA-BreakGlass`.
5. **Exceptions are time-boxed by default.** An exclusion without an expiry date in the review record is a finding, not a fact of life.

## Break-glass procedure

Two cloud-only accounts, FIDO2-credentialed, excluded from every policy. Quarterly, on the calendar: sign in with each, confirm access to the Entra portal, rotate any fallback credential, and confirm the sign-in alert fired. A break-glass account whose alert doesn't fire is worse than none — you've built an invisible door.

## Report-only drift

Monthly: list every policy still in report-only. Each gets one of three recorded decisions — **enable** (it graduated), **extend** (with a reason and a date), or **remove** (it's never going to enforce; stop pretending). Nothing stays report-only without a dated reason. This is the control that prevents the shelfware failure mode.

## Monitoring baseline

* Sign-in logs: weekly review of CA failures by policy; investigate spikes on CA000/CA001 (attack traffic finding closed doors is signal, not noise).
* Password-spray telemetry: alert on error 50126 volume per client app ID — CA can't see failed first factors, so this is your early warning.
* Report-only workbook: the Conditional Access insights workbook per ring gate.
* Agent inventory: monthly reconciliation of agent identities against the approved list before/while CA600 enforces.
* Framework drift: run `Tools/Test-VcioCaBaseline.ps1` against a fresh tenant export monthly — it catches manual portal edits that broke wiring (scope emptied, exclusion group swapped, break-glass removed).

## Change control

CA policy changes go through export → change → validate → document, no exceptions — the portal makes bad edits easy and history invisible. Roadmap hardening: protected actions with a phishing-resistant authentication context on CA policy modification, so changing the framework requires the strongest credential the tenant has.
