# VCIO CA Framework

A Conditional Access framework for Microsoft Entra ID, built on a simple thesis: **a baseline is an operating model, not a set of JSON files.** The policies here ship together with the exception governance, the deployment parameters, the identity-onboarding method, and the runbook that make them survivable in production — because the gap between "imported the policies" and "operates the policies" is where tenants actually get compromised or locked out.

**Version 2026.9.1** · [Changelog](CHANGELOG.md) · Companion article series: virtualcaffeine.io (Phase 8)

> **Fresh deployment only.** The 2026.9.1 upgrade path from 2026.7.1 has not been lab-validated — the F2 upgrade test needs a tenant holding the previous release and Windows PowerShell 5.1 for IntuneManagement. A tenant already running 2026.7.1 should stay there until the result is recorded in [Docs/upgrade.md](Docs/upgrade.md). New tenants are unaffected.

## Design at a glance

Two axes classify everything. **Personas** say who: Privileged (role-targeted, cloud-only admin accounts), Users (your employees), Externals (guests and service providers), Non-interactive (user-shaped service accounts — a transition state, not a destination), and Agents. **Tiers** say what: Tier 0 is the control plane (phishing-resistant MFA + compliant device, no exceptions), Tier 1 is business data (managed device or a contained browser session), Tier 2 is everything else (MFA). You classify apps once at deployment; the policies never change.

Three structural rules, all validator-enforced: every policy has exactly one dedicated exclusion group and no exclusion group serves two policies; break-glass is excluded everywhere; no first-party client exclusions on phishing-resistant MFA, ever.

## Editions

| Edition | Folder | Requires | Contents |
|---|---|---|---|
| **Core** | `Config/` | Entra ID P1 (Business Premium and up) | 28 policies: foundation, privileged/Tier 0, managed users, BYOD contained path, externals, service accounts, agents |
| **Overlay** | `Config-Overlay-P2/` | Entra ID P2 (E5, or P2 add-on) | 6 policies: risk-based blocks and challenges scoped to **all users**, agent user risk, token protection pilot |
| **Transition** | `Transition/` | — | 4 hybrid-join variants of CA200/204/300/301, targeting `SG-CA-Transition-Hybrid`. A dated stop-gap with a shipped exit script, not a second edition |
| **Templates** | `Templates/` | — | 6 templates: 4 per-app postures (Restricted / Tier 0 / Fenced / MAM-Mobile) and the CA500/CA501 per-system service-account pair. Instantiate with `build/generate.py --instance`; **never bulk-import** `Templates/` |

Agent policies (600s) additionally require Microsoft Agent 365 licensing per user. Token protection (CA705) is P1-licensed but Windows-only today; it ships as a pilot.

## Quick start

> Full walkthrough with expected outputs at every step: **[Docs/implementation-guide.md](Docs/implementation-guide.md)**. The steps below are the summary.

The prereqs script runs **twice** — some checks only make sense before import, others can only pass after it.

1. **Pre-import prereqs.** Run `Prereqs/Invoke-VcioCaPrereqs.ps1 -Gate PreImport -Fix` (PowerShell 7 recommended; the script offers to install any missing Microsoft Graph SDK modules to CurrentUser — no admin rights or app registrations needed; sign in as the tenant's Global Admin when prompted).

   **Everything in this framework is gated, and `-Gate` is how.** Each gate — `PreImport`, `SwitchReadiness`, `PostSwitch`, `Ring1`…`Ring4` — carries a fixed list of checks that are FAIL *at that gate*, and the script exits non-zero on any of them. Checks outside the list still run and print as INFO; WARN never gates. So `PreImport` blocks only on what can be true before the policies exist, and the break-glass and App Protection results are information you will need later rather than warnings to squint at now. Note the shell split: this script prefers PS7, while the IntuneManagement import tool runs in Windows PowerShell 5.1.

   **On Security Defaults?** The switch is its own two-gate procedure — `SwitchReadiness` runs while SD is still on, `PostSwitch` immediately after — and it exists to stop the tenant spending weeks with SD off and every VCIO policy still report-only. See [Switching from Security Defaults](Docs/implementation-guide.md#phase-b2--switching-from-security-defaults).
2. **Import.** Use [IntuneManagement](https://github.com/Micke-K/IntuneManagement): Bulk → Import → select the repo root. **The tool creates the groups and named locations for you** from `Config/Groups` and `Config/NamedLocations`, and `MigrationTable.json` remaps the policy references to the newly created objects — no manual group creation. Groups import before Conditional Access (the tool's dependency ordering handles this). **Everything ships report-only** — nothing enforces at import.
3. **Populate and parameterize.** The tool creates *empty* groups — membership is yours: break-glass accounts into `SG-CA-BreakGlass`, the dynamic all-employees rule onto `SG-CA-Users`, service accounts into `SG-CA-ServiceAccounts`, plus the two new ones (`SG-CA-Privileged`, and `SG-CA-Transition-Hybrid` if there is a hybrid population). Then work through the rest of [Docs/deployment-parameters.md](Docs/deployment-parameters.md): country list, service-account IP ranges, guest app list, fencing mode. There are no functional defaults — placeholder IPs are RFC 5737 documentation ranges and match nothing real.
4. **Fill in the deployment manifest.** Copy `Deploy/manifest.example.json` to `Deploy/<customer>/manifest.json` and complete it while the tenant object IDs are in front of you. It holds what the policy JSON cannot: the transition exit date, the fencing mode, per-account CA501 owners and deadlines, the expected Azure scope inventory, and the partner tenant IDs. Every tool takes `-Manifest`; several gate checks cannot run without it. `Deploy/*/` is gitignored.
5. **Post-import prereqs (the Ring 1 gate).** Run `Prereqs/Invoke-VcioCaPrereqs.ps1 -Gate Ring1 -Manifest <path>`. Zero FAIL, which now includes break-glass holding *permanent* Global Administrator (not PIM-eligible), and service-account fences verified against 30 days of sign-ins rather than merely configured.
6. **Validate.** Run `Tools/Test-VcioCaBaseline.ps1 -Path <repo-or-export>` (and monthly against tenant exports with `-Manifest`, to catch drift). Use Entra What-If against your pilot users.
7. **Enable in rings.** Follow the ring order in [Docs/runbook.md](Docs/runbook.md) — each ring runs report-only for at least two weeks with sign-in log review before enforcement.

## Policy index

### Core — Foundation (000s), all identities
| Policy | Control |
|---|---|
| CA000 Global-BlockLegacyAuth | Block legacy protocols |
| CA001 Global-BlockDeviceCodeFlow | Block device code flow (Teams Rooms / IoT / console exceptions go in `SG-CA-Excl-CA001`) |
| CA002 Global-MFA | MFA catch-all (exceptions: break-glass, fenced service accounts, and the Directory Synchronization Accounts role — enumerated and closed) |
| CA003 Global-MFA-DeviceRegisterJoin | MFA to register or join devices |
| CA004 Global-ProtectSecurityInfoRegistration | MFA (TAP satisfies) to register security info — protects the MFA bootstrap |
| CA005 Global-BlockUnknownPlatforms | Block unknown device platforms |
| CA006 Global-GeoFence | Country allow-list — **parameter required**; attack-surface trimming, not a security control |
| CA007 Global-BlockAuthTransfer | Block authentication transfer — its own exclusion group, so a device-code exception is not also an auth-transfer bypass. Ring 2, not Ring 1 |

### Core — Privileged / Tier 0 (100s)
| Policy | Control |
|---|---|
| CA100 Privileged-PhishingResistantMFA | Phishing-resistant strength, all apps, **no app exclusions** |
| CA101 Privileged-CompliantDevice | Compliant device for admin roles, any platform |
| CA102 Privileged-SessionHygiene | 8h sign-in frequency + no persistent browser |
| *(all three)* | Target the 24 built-in roles **and `SG-CA-Privileged`** — custom roles, AU-scoped grants and Azure RBAC control-plane holders that role targeting cannot see. Reconciled monthly by `Tools/Compare-VcioPrivilegedScope.ps1` |
| CA103 Tier0-ControlPlane-AllUsers | Azure management + admin portals: phishing-resistant MFA **and** compliant device, for everyone |

### Core — Managed users (200s), BYOD (300s)
| Policy | Control |
|---|---|
| CA200/CA201 Users-Win/macOS-CompliantDevice | Compliant device for desktop/mobile clients (browser deliberately excluded — governed by 300s) |
| CA202 Users-Mobile-AppProtection | Compliant device **OR** app protection for Office 365 on iOS/Android, no device filter. Compliant device passes; unmanaged device passes on APP; an enrolled **non-compliant** device is blocked unless a customer-added APP assignment reaches it (the shipped filters do not) |
| CA203 Users-MFA-IntuneEnrollment | MFA every time at enrollment — see [Docs/onboarding.md](Docs/onboarding.md) for the TAP/Autopilot method |
| CA204 Users-SessionHygiene-Unmanaged | 12h sign-in frequency + no persistence on unmanaged devices |
| CA300 BYOD-BrowserSessionControls | App-enforced restrictions for unmanaged browser sessions — **inert until switched on service-side, and EXO/SPO only**: [Docs/app-enforced-restrictions.md](Docs/app-enforced-restrictions.md) |
| CA301 BYOD-Windows-RequireAppProtection | Windows MAM (Edge) — the stronger unmanaged-Windows variant |

### Core — Externals (400s), Non-interactive (500s), Agents (600s)
| Policy | Control |
|---|---|
| CA400–CA403 | Guest MFA (incl. service providers), default-deny apps, session hygiene, admin-portal block. **CA403 excludes service providers** — GDAP partners still fall under CA400, CA402 and CA103: [Docs/partner-access.md](Docs/partner-access.md) |
| CA500 ServiceAccounts-IPFence | Block outside named IP ranges — **parameter required**. Enables in **Ring 1** with CA002, because the MFA exemption and the fence are two halves of one decision |
| CA501 ServiceAccounts-RestrictApps | Default-deny apps for service accounts (add assigned apps as exclusions). No ring — owner and deadline in worksheet item 6a, after discovery |
| CA600–CA602 | Agent default-deny, high-risk agent block, compliant device for agent users — enable only after an approved-agent inventory exists |

### Overlay — P2 (700s)
| Policy | Control |
|---|---|
| CA700/CA701 | Block high user risk / high sign-in risk — **all users**, service accounts included. A block cannot inconvenience a non-interactive account, and a compromised one is what high risk is for |
| CA702/CA703 | Medium sign-in risk → MFA every time; medium user risk → secure password change |
| CA704 | Block medium/high-risk agent users |
| CA705 | Token protection pilot for admins (Windows, EXO/SPO) |

### Transition (hybrid stop-gap)
`Transition/` holds variants of CA200, CA204, CA300 and CA301 whose device filter also admits hybrid-joined devices (`device.trustType -eq "ServerAd"`). They target `SG-CA-Transition-Hybrid`; the four standard policies **exclude** that group. Exactly one of each pair reaches a given user, so nobody is covered twice and nobody falls between them.

Emptying the group is the exit — a removed user is back under the standard policies on their next sign-in. The exit *order* matters and `Tools/Invoke-VcioTransitionExit.ps1` enforces it: verify every member is in `SG-CA-Users` and that the four standard policies are enabled, remove members, confirm a post-removal sign-in per user, and only then disable the transition policies. Disabling them while the group still has members strips protection outright, because the standard policies' exclusions are still live. The exit **date** lives in the deployment manifest, not the policy JSON — Graph documents `description` as "Not used" and nothing proves a value there survives an import/export round trip.

### Templates — per-app posture (800s) and per-system fencing (500s)
Classify sensitive Tier 1 apps (Salesforce, finance, HR) into a posture and instantiate the matching template: **Restricted** (CA800 — compliant device on all client types, personal devices denied outright), **Tier 0** (CA801 — compliant device **and** phishing-resistant MFA, CA103's shape at app level), **Fenced** (CA802 — Restricted plus a trusted-egress carve-out, documented as a convenience exception), **MAM-Mobile** (CA803 — compliant device *or* app protection on mobile; requires the app to support Intune APP via SDK or wrapping, and to be added to the VCIO-APP baselines' targeted apps). CA500/CA501 SYSTEMNAME instantiate the per-system service-account fence.

> **CA801 changed meaning in 2026.9.1.** It was Step-Up (compliant device *or* MFA), which enforced nothing new for anyone already inside CA002's MFA scope. The slot now carries the Tier 0 posture. Upgrading a tenant that instantiated the old one is a **retirement step, not a rename** — see [Docs/upgrade.md](Docs/upgrade.md).

Instantiation is a create, never an edit-in-place:

```bash
python3 build/generate.py --instance 801 Salesforce   # or 800/802/803, or 500/501 per system
```

That writes the policy, a dedicated `SG-CA-Excl-CA801-Salesforce` group with its own GUID, any per-system scope group and named location, and a MigrationTable — into `Deploy/instances/` (gitignored), so the repo tree never grows an instance. Both validators enforce that every instance owns an exclusion group no other policy uses. Pair every Restricted/Fenced/Tier 0 app with its app-side session timeout — the SaaS app holds its own sessions after Entra admits it. Apps that don't support MAM don't get the MAM posture.

## The operating model

The [runbook](Docs/runbook.md) is part of the framework, not an appendix: exclusion groups ship empty with named owners, quarterly access reviews, and membership-change alerting; break-glass gets a quarterly sign-in test; report-only policies get a monthly decision (enable, extend, or remove) so nothing ages into shelfware; and every change is preceded by an IntuneManagement export.

## Troubleshooting

Most classic import failures are prevented by the prereqs script — run it with `-Fix` before import and `ServicePrincipalNotFound` should never appear. The ones worth knowing about:

| Symptom | Cause | Fix |
|---|---|---|
| Import fails on CA101/CA200/CA201/CA203: `ServicePrincipalNotFound` | Microsoft Intune Enrollment SP (`d4ebce55-...`) missing from tenant | `Prereqs/Invoke-VcioCaPrereqs.ps1 -Fix` (or `New-MgServicePrincipal -AppId d4ebce55-015a-49b5-a083-c84d1797ae8c`). Note: use the Graph module — the old `New-AzureADServicePrincipal` cmdlets are retired and no longer function |
| Windows first sign-in: "You can't get there from here" during account setup/restore | CA200 blocking Microsoft Activity Feed Service on a not-yet-compliant device | Add app `d32c68ad-72d2-4acb-a0c7-46bb2cf93873` to CA200's excludeApplications (see [Docs/onboarding.md](Docs/onboarding.md)) |
| Teams Rooms, IoT, or TV/console sign-ins fail after Ring 1 | CA001 blocks device code flow, which these devices legitimately use | Put the resource accounts in `SG-CA-Excl-CA001` — fenced, owned, reviewed like any exception. Don't turn the policy off. Note this does **not** exempt them from CA007 (auth transfer), which is the point of the split |
| Entra Connect sync fails after Ring 1 | The sync account cannot perform interactive MFA | Nothing to do — CA002 exempts the Directory Synchronization Accounts role (`d29b2b05-…`) by design. Do **not** add the sync account to `SG-CA-ServiceAccounts`; that group's fence carries the application servers' egress, not the Connect server's. Optional fencing is a dedicated `CA500-…-DirSync` instance on `SG-CA-SA-DirSync` |
| Unmanaged browser users can still download from SharePoint | CA300's app-enforced restrictions are set on the policy but not switched on service-side | `Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess`, and every OWA mailbox policy in-scope users are mapped to. There is no organization-level Exchange switch — see [Docs/app-enforced-restrictions.md](Docs/app-enforced-restrictions.md) |
| Partner technician can't reach the admin portals | Pre-2026.9.1 CA403 blocked service providers | Fixed in 2026.9.1 — CA403 excludes `serviceProvider`. CA103 still applies to them; see [Docs/partner-access.md](Docs/partner-access.md) |
| Users prompted to "set up your account" in a loop on personal mobile | CA202 requires app protection but APP policies aren't assigned to the user | Assign the `Config/AppProtection` baseline to `SG-CA-Users` (the prereqs script warns about this before Ring 4) |
| Windows MAM policy missing after import (2 of 3 APP policies present) | IntuneManagement does not import the `windowsManagedAppProtection` object type | Run `Prereqs/Invoke-VcioCaPrereqs.ps1 -Fix` — it creates the Windows Edge MAM policy directly via Graph from the shipped JSON |
| Autopilot Device Preparation (v2) devices hang in OOBE | Automated enrollment can't satisfy CA203's MFA | Use the time-boxed provisioning exclusion or staging-bench named location per [Docs/onboarding.md](Docs/onboarding.md) — never a permanent exclusion |
| Guests report double MFA prompts | Cross-tenant access settings don't trust home-tenant MFA | Parameters worksheet #12 — decide and configure the cross-tenant trust before enabling CA400 |

## Rebuilding from source

`build/generate.py` produces every policy, group, and named location deterministically (same input → same GUIDs, unchanged across releases). **Every policy change goes through it and the tree is regenerated; the JSON is never hand-edited** — CI regenerates and fails on any diff, so a hand-edit does not survive a build.

Two validators, one rule set. `build/validate.py` is the release validator and runs in CI against the tree. `Tools/Test-VcioCaBaseline.ps1` is the operator's drift validator and runs against a tenant export with `-Manifest`. They keep their different jobs, but every structural rule is implemented in both and CI runs both against the repo so they cannot disagree. **Neither gates on a policy count** — each checks that every required policy identity is present by displayName pattern and that the relationships hold; the count is printed for information.

What fails a build: inert scopes (including an agent policy whose only "scope" is a risk level), dangling GUIDs, exclusion-group reuse, an instance that does not own its exclusion group, missing break-glass exclusions, a device filter that is not the one canonical string, a redundant compliant-device-or-MFA grant, a broken transition pairing, MigrationTable drift, encoding drift, and escaped placeholders. With a manifest, the drift validator adds the transition lifecycle and the service-account fencing mode.

## Lineage and credits

The persona concept descends from Claus Jespersen's [Conditional Access for Zero Trust](https://github.com/microsoft/ConditionalAccessforZeroTrustResources) framework and Joey Verlinden's [ConditionalAccessBaseline](https://github.com/j0eyv/ConditionalAccessBaseline), which made persona-based CA practical for a wide audience. The modular-baseline discipline is inspired by [OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline). This framework departs from its ancestors structurally — resource tiers, lifecycle policies, a designed BYOD path, dual editions, shipped governance — but stands on their work.

## License

MIT. Use it, fork it, deploy it for customers. No warranty — validate in a lab tenant first, and mind the deployment parameters.
