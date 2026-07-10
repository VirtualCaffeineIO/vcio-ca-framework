# VCIO CA Framework

A Conditional Access framework for Microsoft Entra ID, built on a simple thesis: **a baseline is an operating model, not a set of JSON files.** The policies here ship together with the exception governance, the deployment parameters, the identity-onboarding method, and the runbook that make them survivable in production — because the gap between "imported the policies" and "operates the policies" is where tenants actually get compromised or locked out.

**Version 2026.7.1** · [Changelog](CHANGELOG.md) · Companion article series: virtualcaffeine.io (Phase 8)

## Design at a glance

Two axes classify everything. **Personas** say who: Privileged (role-targeted, cloud-only admin accounts), Users (your employees), Externals (guests and service providers), Non-interactive (user-shaped service accounts — a transition state, not a destination), and Agents. **Tiers** say what: Tier 0 is the control plane (phishing-resistant MFA + compliant device, no exceptions), Tier 1 is business data (managed device or a contained browser session), Tier 2 is everything else (MFA). You classify apps once at deployment; the policies never change.

Three structural rules, all validator-enforced: every policy has exactly one dedicated exclusion group and no exclusion group serves two policies; break-glass is excluded everywhere; no first-party client exclusions on phishing-resistant MFA, ever.

## Editions

| Edition | Folder | Requires | Contents |
|---|---|---|---|
| **Core** | `Config/` | Entra ID P1 (Business Premium and up) | 27 policies: foundation, privileged/Tier 0, managed users, BYOD contained path, externals, service accounts, agents |
| **Overlay** | `Config-Overlay-P2/` | Entra ID P2 (E5, or P2 add-on) | 6 policies: risk-based blocks and challenges scoped to **all users**, agent user risk, token protection pilot |
| **Templates** | `Templates/` | — | 3 per-app posture templates (Restricted / Step-Up / Fenced) — instantiate per customer app, never bulk-import |

Agent policies (600s) additionally require Microsoft Agent 365 licensing per user. Token protection (CA705) is P1-licensed but Windows-only today; it ships as a pilot.

## Quick start

> Full walkthrough with expected outputs at every step: **[Docs/implementation-guide.md](Docs/implementation-guide.md)**. The steps below are the summary.

The prereqs script runs **twice** — some checks only make sense before import, others can only pass after it.

1. **Pre-import prereqs.** Run `Prereqs/Invoke-VcioCaPrereqs.ps1 -Fix -PreImport` (PowerShell 7 recommended; the script offers to install any missing Microsoft Graph SDK modules to CurrentUser — no admin rights or app registrations needed; sign in as the tenant's Global Admin when prompted). The `-PreImport` switch gates only on what can pass before import: security defaults off, Intune Enrollment service principal present, Temporary Access Pass enabled — break-glass and App Protection report as informational. Note the shell split: this script prefers PS7, while the IntuneManagement import tool runs in Windows PowerShell 5.1.
2. **Import.** Use [IntuneManagement](https://github.com/Micke-K/IntuneManagement): Bulk → Import → select the repo root. **The tool creates the groups and named locations for you** from `Config/Groups` and `Config/NamedLocations`, and `MigrationTable.json` remaps the policy references to the newly created objects — no manual group creation. Groups import before Conditional Access (the tool's dependency ordering handles this). **Everything ships report-only** — nothing enforces at import.
3. **Populate and parameterize.** The tool creates *empty* groups — membership is yours: break-glass accounts into `SG-CA-BreakGlass`, the dynamic all-employees rule onto `SG-CA-Users`, service accounts into `SG-CA-ServiceAccounts`. Then work through the rest of [Docs/deployment-parameters.md](Docs/deployment-parameters.md): country list, service-account IP ranges, guest app list. There are no functional defaults — placeholder IPs are RFC 5737 documentation ranges and match nothing real.
4. **Post-import prereqs (the Ring 1 gate).** Re-run `Prereqs/Invoke-VcioCaPrereqs.ps1`. Everything must now pass, including break-glass (two cloud-only, FIDO2-credentialed accounts) and App Protection presence.
5. **Validate.** Run `Tools/Test-VcioCaBaseline.ps1` against the repo (and monthly against tenant exports, to catch drift). Use Entra What-If against your pilot users.
6. **Enable in rings.** Follow the ring order in [Docs/runbook.md](Docs/runbook.md) — each ring runs report-only for at least two weeks with sign-in log review before enforcement.

## Policy index

### Core — Foundation (000s), all identities
| Policy | Control |
|---|---|
| CA000 Global-BlockLegacyAuth | Block legacy protocols |
| CA001 Global-BlockDeviceCodeFlow-AuthTransfer | Block device code flow + auth transfer |
| CA002 Global-MFA | MFA catch-all (exceptions: break-glass, fenced service accounts — enumerated and closed) |
| CA003 Global-MFA-DeviceRegisterJoin | MFA to register or join devices |
| CA004 Global-ProtectSecurityInfoRegistration | MFA (TAP satisfies) to register security info — protects the MFA bootstrap |
| CA005 Global-BlockUnknownPlatforms | Block unknown device platforms |
| CA006 Global-GeoFence | Country allow-list — **parameter required**; attack-surface trimming, not a security control |

### Core — Privileged / Tier 0 (100s)
| Policy | Control |
|---|---|
| CA100 Privileged-PhishingResistantMFA | Phishing-resistant strength, all apps, **no app exclusions** |
| CA101 Privileged-CompliantDevice | Compliant device for admin roles, any platform |
| CA102 Privileged-SessionHygiene | 8h sign-in frequency + no persistent browser |
| CA103 Tier0-ControlPlane-AllUsers | Azure management + admin portals: phishing-resistant MFA **and** compliant device, for everyone |

### Core — Managed users (200s), BYOD (300s)
| Policy | Control |
|---|---|
| CA200/CA201 Users-Win/macOS-CompliantDevice | Compliant device for desktop/mobile clients (browser deliberately excluded — governed by 300s) |
| CA202 Users-Mobile-AppProtection | MAM for Office 365 on iOS/Android (companion APP policies required) |
| CA203 Users-MFA-IntuneEnrollment | MFA every time at enrollment — see [Docs/onboarding.md](Docs/onboarding.md) for the TAP/Autopilot method |
| CA204 Users-SessionHygiene-Unmanaged | 12h sign-in frequency + no persistence on unmanaged devices |
| CA300 BYOD-BrowserSessionControls | App-enforced restrictions for unmanaged browser sessions |
| CA301 BYOD-Windows-RequireAppProtection | Windows MAM (Edge) — the stronger unmanaged-Windows variant |

### Core — Externals (400s), Non-interactive (500s), Agents (600s)
| Policy | Control |
|---|---|
| CA400–CA403 | Guest MFA (incl. service providers), default-deny apps, session hygiene, admin-portal block |
| CA500 ServiceAccounts-IPFence | Block outside named IP ranges — **parameter required** |
| CA501 ServiceAccounts-RestrictApps | Default-deny apps for service accounts (add assigned apps as exclusions) |
| CA600–CA602 | Agent default-deny, high-risk agent block, compliant device for agent users — enable only after an approved-agent inventory exists |

### Overlay — P2 (700s)
| Policy | Control |
|---|---|
| CA700/CA701 | Block high user risk / high sign-in risk — **all users**, not just employees |
| CA702/CA703 | Medium sign-in risk → MFA every time; medium user risk → secure password change |
| CA704 | Block medium/high-risk agent users |
| CA705 | Token protection pilot for admins (Windows, EXO/SPO) |

### Templates (800s) — per-app posture
Classify sensitive Tier 1 apps (Salesforce, finance, HR) into one of four postures and instantiate the matching template with the app's ID: **Restricted** (compliant device on all client types — personal devices denied outright), **Step-Up** (compliant device *or* MFA — never for Tier 0), **Fenced** (Restricted plus a trusted-egress carve-out, documented as a convenience exception), **MAM-Mobile** (mobile access from personal devices only inside a containerized, APP-protected client — requires the app to support Intune APP via SDK or wrapping, and requires adding it to the VCIO-APP baselines' targeted apps). Create a dedicated `SG-CA-Excl-CA8xx-<App>` group per instance. Pair every Restricted/Fenced app with its app-side session timeout — the SaaS app holds its own sessions after Entra admits it. Apps that don't support MAM don't get the MAM posture — fall back to Restricted or browser-only.

## The operating model

The [runbook](Docs/runbook.md) is part of the framework, not an appendix: exclusion groups ship empty with named owners, quarterly access reviews, and membership-change alerting; break-glass gets a quarterly sign-in test; report-only policies get a monthly decision (enable, extend, or remove) so nothing ages into shelfware; and every change is preceded by an IntuneManagement export.

## Troubleshooting

Most classic import failures are prevented by the prereqs script — run it with `-Fix` before import and `ServicePrincipalNotFound` should never appear. The ones worth knowing about:

| Symptom | Cause | Fix |
|---|---|---|
| Import fails on CA101/CA200/CA201/CA203: `ServicePrincipalNotFound` | Microsoft Intune Enrollment SP (`d4ebce55-...`) missing from tenant | `Prereqs/Invoke-VcioCaPrereqs.ps1 -Fix` (or `New-MgServicePrincipal -AppId d4ebce55-015a-49b5-a083-c84d1797ae8c`). Note: use the Graph module — the old `New-AzureADServicePrincipal` cmdlets are retired and no longer function |
| Windows first sign-in: "You can't get there from here" during account setup/restore | CA200 blocking Microsoft Activity Feed Service on a not-yet-compliant device | Add app `d32c68ad-72d2-4acb-a0c7-46bb2cf93873` to CA200's excludeApplications (see [Docs/onboarding.md](Docs/onboarding.md)) |
| Teams Rooms, IoT, or TV/console sign-ins fail after Ring 1 | CA001 blocks device code flow, which these devices legitimately use | Put the resource accounts in `SG-CA-Excl-CA001` — fenced, owned, reviewed like any exception. Don't turn the policy off |
| Users prompted to "set up your account" in a loop on personal mobile | CA202 requires app protection but APP policies aren't assigned to the user | Assign the `Config/AppProtection` baseline to `SG-CA-Users` (the prereqs script warns about this before Ring 4) |
| Windows MAM policy missing after import (2 of 3 APP policies present) | IntuneManagement does not import the `windowsManagedAppProtection` object type | Run `Prereqs/Invoke-VcioCaPrereqs.ps1 -Fix` — it creates the Windows Edge MAM policy directly via Graph from the shipped JSON |
| Autopilot Device Preparation (v2) devices hang in OOBE | Automated enrollment can't satisfy CA203's MFA | Use the time-boxed provisioning exclusion or staging-bench named location per [Docs/onboarding.md](Docs/onboarding.md) — never a permanent exclusion |
| Guests report double MFA prompts | Cross-tenant access settings don't trust home-tenant MFA | Parameters worksheet #12 — decide and configure the cross-tenant trust before enabling CA400 |

## Rebuilding from source

`build/generate.py` produces every policy, group, and named location deterministically (same input → same GUIDs). `build/validate.py` / `Tools/Test-VcioCaBaseline.ps1` are the release gate: inert scopes, dangling GUIDs, exclusion reuse, missing break-glass exclusions, encoding drift, and escaped placeholders all fail the build.

## Lineage and credits

The persona concept descends from Claus Jespersen's [Conditional Access for Zero Trust](https://github.com/microsoft/ConditionalAccessforZeroTrustResources) framework and Joey Verlinden's [ConditionalAccessBaseline](https://github.com/j0eyv/ConditionalAccessBaseline), which made persona-based CA practical for a wide audience. The modular-baseline discipline is inspired by [OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline). This framework departs from its ancestors structurally — resource tiers, lifecycle policies, a designed BYOD path, dual editions, shipped governance — but stands on their work.

## License

MIT. Use it, fork it, deploy it for customers. No warranty — validate in a lab tenant first, and mind the deployment parameters.
