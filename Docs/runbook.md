# Operating Runbook

This is the half of the framework that isn't JSON. The policies define what's enforced; this document defines how the enforcement stays trustworthy over time. If you deploy the policies and skip this, you have what every other baseline gives you — a snapshot that decays.

## Enablement rings

Everything imports report-only. Enforcement happens in rings, each preceded by at least two weeks in report-only with sign-in log review and What-If validation against pilot users. CAE-dependent controls aside, report-only data is your evidence — read it before every ring.

Each ring's gate is a `-Gate` run of the prereqs script, not a judgement call: `Prereqs/Invoke-VcioCaPrereqs.ps1 -Gate Ring1 -Manifest <path>`. The gate exits non-zero on any FAIL in its own list. Checks outside that list still print, as INFO — they are context, not a veto.

| Ring | Policies | Gate before enabling |
|---|---|---|
| **1 — Foundation blocks** | CA000, CA001, CA002, **CA500** | `-Gate Ring1`: security defaults off; **service-account coverage (B3a)**; break-glass — two or more, cloud-only, enabled, each with a *permanent* (not PIM-eligible) Global Administrator assignment and a FIDO2 credential; registration readiness; sync accounts inventoried and none of them in `SG-CA-ServiceAccounts`. Plus: report-only shows no legitimate legacy-auth or device-code traffic, or identified traffic has a migration plan |
| **2 — Hygiene** | CA003, CA004, CA005, **CA007**, CA102, CA203, CA204, CA400, CA402, CA403 | `-Gate Ring2`: everything in Ring 1, plus the **GDAP partner sign-in test** ([partner-access.md](partner-access.md) — technician reaches Microsoft Admin Portals). Plus: TAP enabled and onboarding SOP in place (CA203/CA004); frontline/phoneless users have a registration path |
| **3 — Privileged, Tier 0, risk, fencing** | CA100, CA101, CA103, CA401, CA501, CA700–CA703 | `-Gate Ring3`: everything in Ring 2, plus every `ADMIN_ROLES` **and `SG-CA-Privileged`** holder has a phishing-resistant method registered, and `Tools/Compare-VcioPrivilegedScope.ps1`'s last run was clean — no uncovered privileged user, no INCOMPLETE scope. Plus the four-case **GDAP partner test** at this ring. Plus: guest app list confirmed with business owners |
| **4 — Device trust and BYOD** | CA200, CA201, CA202, CA300, CA301 | `-Gate Ring4`: everything above, plus the **APP assignment checks** (assignment collection read directly, filter rule text compared, targeted app list matched) and the **AER checks** — SharePoint `Get-SPOTenant` returns `AllowLimitedAccess`, and every OWA mailbox policy an `SG-CA-Users` member is mapped to is `ReadOnly` or `ReadOnlyPlusAttachmentsBlocked` ([app-enforced-restrictions.md](app-enforced-restrictions.md)). Plus: device compliance healthy (>95% of `SG-CA-Users` devices compliant or in remediation); BYOD mode decision recorded |
| **Per-decision** | CA006 (geo), CA600–CA602 + CA704 (agents, after inventory), CA705 (token protection pilot), 800s instances | Each has its own gate in the parameters worksheet |

**CA500 moves to Ring 1.** A service account exempted from CA002 with no enforced fence is an MFA-exempt account protected by nothing, and that state should never exist — not for the weeks between Ring 1 and Ring 3. The exemption and the fence enable together or neither does.

**CA501 leaves the ring model.** Restricting a service account to its assigned apps needs a discovery pass first — you cannot write the allow-list before you know what the account touches. It gets a named owner and a date in the parameters worksheet (item 6a) instead of a ring, and where the decision is to run IP-fenced without an app allow-list, that decision is recorded there too rather than left as an unfinished task.

**CA003 and CA004 do not get report-only evidence.** Report-only produces no data for user-action policies — there is no sign-in to observe when nobody is registering a device or a security method under a policy that is not enforcing. So the soak does not apply: pilot them on a test group of at least five users, including one new-hire Autopilot run with a TAP, before enabling. That pilot *is* the evidence.

**WHfB and macOS PSSO register under CA004.** Since 2026-07-06, Windows Hello for Business enrollment and macOS Platform SSO registration are treated as security-info registration and are gated by CA004. A TAP satisfies it, which is why the TAP-in-OOBE flow in [onboarding.md](onboarding.md) is the supported path rather than a convenience.

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
* Privileged scope: run `Tools/Compare-VcioPrivilegedScope.ps1 -Manifest <path> -RecordResult` monthly. The privilege-grant procedure adds the user to `SG-CA-Privileged` at grant time; this run is the backstop that catches the grant nobody logged, and the only thing that sees Azure RBAC and custom-role privilege at all.
* Transition exit: where `SG-CA-Transition-Hybrid` is in use, schedule `Tools/Invoke-VcioTransitionExit.ps1 -Manifest <path>` daily (Azure Automation or the MSP's job host). Where Entra ID Governance is licensed, a recurring access review with auto-remove on the group is the supported alternative. Expiry is monitored by a shipped script against an operator deadline — it is not enforced by the policy objects, which have nowhere to carry a date.
* Framework drift: run `Tools/Test-VcioCaBaseline.ps1` against a fresh tenant export monthly — it catches manual portal edits that broke wiring (scope emptied, exclusion group swapped, break-glass removed).

## Change control

CA policy changes go through export → change → validate → document, no exceptions — the portal makes bad edits easy and history invisible. Roadmap hardening: protected actions with a phishing-resistant authentication context on CA policy modification, so changing the framework requires the strongest credential the tenant has.
