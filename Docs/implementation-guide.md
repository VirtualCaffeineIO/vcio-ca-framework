# Implementation Guide

The end-to-end walkthrough, in execution order. The [runbook](runbook.md) covers ongoing operations; this document covers the one-time build, from a bare admin workstation to enforced policies. Follow it top to bottom — the order is deliberate.

Time budget for a first run: about half a day of hands-on work spread across two to four weeks of report-only soak time. The waiting is part of the deployment, not a delay to it.

---

## Phase A — Workstation setup (once per admin workstation)

You need **two shells**, and it matters which one you use for what:

| Shell | Used for | Why |
|---|---|---|
| PowerShell 7 | The framework's scripts (prereqs, validator) | Modern Graph SDK behavior |
| Windows PowerShell 5.1 | IntuneManagement import tool | It's a WPF app built for 5.1 |

**A1. Install PowerShell 7** (if not present):
```powershell
winget install Microsoft.PowerShell
```

**A2. Graph SDK modules** — nothing to do in advance. The prereqs script checks for its six required modules and offers to install them to your user profile (no admin rights) on first run. To pre-install manually instead:
```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Users,
    Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns,
    Microsoft.Graph.Devices.CorporateManagement -Scope CurrentUser
```

**A3. Get the framework and the import tool:**
```powershell
# Framework → C:\vcio-ca  (extract the release zip or git clone)
# IntuneManagement → C:\IntuneManagement  (latest release from github.com/Micke-K/IntuneManagement)
Get-ChildItem -Path "C:\IntuneManagement\" -File -Recurse | Unblock-File
Get-ChildItem -Path "C:\vcio-ca\" -File -Recurse | Unblock-File
```
Skipping `Unblock-File` is the most common cause of the import tool half-loading.

**A4. Admin identity.** Use a cloud-only Global Administrator of the target tenant. If the account is passwordless/passkey-only, note that IntuneManagement's embedded sign-in window may not support WebAuthn — have Authenticator (push/TOTP) registered as a fallback method, and clear any pending registration interrupt at https://mysignins.microsoft.com/security-info in a real browser *before* launching the tool.

---

## Phase B — Tenant preparation

**B1. Run the prereqs script** (PowerShell 7):
```powershell
Set-ExecutionPolicy -Scope Process Bypass
cd C:\vcio-ca\Prereqs
.\Invoke-VcioCaPrereqs.ps1 -Gate PreImport -Fix
```
Sign in as the Global Admin in the browser popup and accept the scope consent (delegated, your account only — no app registrations are created).

**The `-Gate` switch is the whole model.** Each gate carries a fixed list of checks that are FAIL *at that gate*; the script exits non-zero if any of them fails. Checks outside the list still run and still print, as `[INFO]` — they are context for later, not a veto now. `[WARN]` never appears in a gate's list: if something matters at a gate it is a FAIL there, and if it does not, it does not get to half-block your run. That is why the pre-import run below shows the App Protection results as INFO rather than as warnings you have to interpret.

Expected result:

```
Gate: PreImport    Fencing mode: Shared

[PASS] Security defaults disabled
[INFO] Break-glass group exists                              <- import creates it
[PASS] Microsoft Intune Enrollment service principal
[PASS] Temporary Access Pass method enabled
[PASS] Assignment filter: VCIO-FLT-iOS-UnmanagedDevices      (Created via Graph)
[PASS] Assignment filter: VCIO-FLT-Android-UnmanagedDevices  (Created via Graph)
[PASS] App Protection: VCIO-APP-iOS-Baseline                 (Created via Graph)
[PASS] App Protection: VCIO-APP-Android-Baseline             (Created via Graph)
[PASS] App Protection: VCIO-APP-Windows-Edge-Baseline        (Created via Graph)

Gate PreImport: 8 pass, 0 warn, 1 info (not gating here), 0 fail
Gate PreImport PASSED.
```

> **On Security Defaults today?** Do **not** disable them yet. Read [Switching from Security Defaults](#phase-b2--switching-from-security-defaults) below first — the switch is a separate two-gate procedure and the order matters more than the speed.

`-Fix` created: the Intune Enrollment service principal (if missing), enabled Temporary Access Pass, the two managed-app filters, and all three App Protection baselines (created via Graph because IntuneManagement cannot import the Windows MAM type). If security defaults show FAIL, disable them (Entra ID → Properties) and re-run.

---

## Phase B2 — Switching from Security Defaults

**Applies only to tenants currently running Security Defaults.** Skip it entirely if the tenant already has Conditional Access.

The sequence this section exists to prevent is the common one: Security Defaults get switched off so the CA policies can be imported, the CA policies land report-only as designed, and then the tenant sits there for three weeks while somebody schedules the enablement conversation. For those three weeks the tenant has **no legacy-authentication block, no device-code block, and no MFA on anything**. It is strictly less protected than it was before the project started, and it got that way through a deployment step that looked like progress.

Security Defaults and CA policies cannot both be on, so the gap is structural. What you can do is make it minutes rather than weeks.

### B2.1 — Clear the readiness gate while SD is still on

```powershell
.\Invoke-VcioCaPrereqs.ps1 -Gate SwitchReadiness -Manifest ..\Deploy\<customer>\manifest.json
```

This gate deliberately does **not** fail on Security Defaults being enabled — that is the point of splitting it from PostSwitch. It fails on everything that must be true *before* you have the authority to turn them off:

* Break-glass: two or more accounts, cloud-only, enabled, each with a **permanent** (not PIM-eligible) Global Administrator assignment and a FIDO2 credential.
* Registration readiness: no enabled member user without a usable MFA method, or the remainder recorded as worksheet exceptions.
* Service-account coverage (B3a).
* CA000, CA001 and CA002 present in the tenant and report-only — so the import has already happened.
* Every pre-existing enforced CA policy listed in the manifest against its VCIO equivalent.

Clear every FAIL. Do not proceed on a gate that did not pass.

### B2.2 — The switch, in one working session

Three actions, back to back, with nobody's calendar in between:

1. Disable Security Defaults (**Entra ID → Properties → Manage security defaults**).
2. Set `CA000-VCIO-Global-BlockLegacyAuth`, `CA001-VCIO-Global-BlockDeviceCodeFlow` and `CA002-VCIO-Global-MFA` to **On**.
3. Run the post-switch gate:

```powershell
.\Invoke-VcioCaPrereqs.ps1 -Gate PostSwitch -Manifest ..\Deploy\<customer>\manifest.json
```

PostSwitch fails on: Security Defaults still enabled; any of those three policies not `enabled`; no sign-in in the last hour showing CA002 applied with result success for a pilot user; and legacy-auth or device-code attempts in the last hour that did not show a CA000/CA001 failure result. If no such attempts occurred at all, that passes — absence of attack traffic in a one-hour window is not evidence of a broken policy.

Have a pilot user ready to sign in on request. The gate needs a real sign-in to read.

### B2.3 — CA007 is not part of the switch

`CA007-VCIO-Global-BlockAuthTransfer` stays **report-only** through the switch and joins **Ring 2**. Authentication transfer is a legitimate flow (it is what hands a desktop session to a phone), and blocking it belongs behind a soak with real data, not in the same breath as the emergency-shaped foundation blocks. CA001 covers device code flow, which is the flow with the live abuse pattern.

### B2.4 — Tenants that already have enforced CA policies

Do not delete anything at the switch. For each existing enforced policy:

1. **Leave it On** until the VCIO ring carrying its equivalent enforces.
2. Then set the old policy to **report-only** for one cycle, and watch that nothing depended on it that the VCIO policy does not cover.
3. Then delete it.

Record the old-policy-to-VCIO-equivalent mapping in the manifest (`preexistingPolicies`) — the SwitchReadiness gate reads it, and an enforced policy nobody mapped is a FAIL there. Overlapping enforcement is safe; a silent gap between deleting the old control and enabling the new one is not.

---

## Phase C — Import

**C1. Launch the tool** (Windows PowerShell 5.1):
```powershell
cd C:\IntuneManagement
.\Start-IntuneManagement.ps1
```
Sign in via the profile icon (top right). At the consent prompt, do **not** tick "consent on behalf of your organization." If the left menu shows red text, use Request Consent from the profile menu and accept again.

**C2. Core import.** Bulk → Import:
- **Import root:** `C:\vcio-ca\Config`
- **Replace Dependency IDs:** checked
- **Conditional Access State:** Report-only if offered; Off otherwise (everything ships report-only in the JSON regardless)
- Click Import.

Notes on what you'll see: "No migration table found" at folder selection can be ignored if it appears — every group and location the policies reference is inside the import set, and the tool resolves them live as it creates them. There is no "Groups" row in the object-type list; groups are dependency objects, created automatically when the CA policies that reference them import.

**C3. Overlay import** (P2 tenants). Repeat Bulk → Import with root `C:\vcio-ca\Config-Overlay-P2`.

**C4. Do not import `Templates/`.** Those are per-app patterns with placeholder IDs, instantiated manually per customer app (see README, Templates section).

**C5. Verify the import.** Expected tenant state:

| Where | Expect |
|---|---|
| Entra → Conditional Access | 28 core policies (+6 overlay), all `CA###-VCIO-*`, all report-only/off |
| Entra → Groups | 35 `SG-CA-*` groups, all empty |
| Entra → Named locations | 3 `VCIO-NL-*` entries (placeholder values) |
| Intune → App protection | 3 `VCIO-APP-*` policies, unassigned |
| Intune → Filters | 2 `VCIO-FLT-*` managed-app filters |

Then the two structural canaries — open these two policies and confirm the complex structures survived:
- **CA103**: grant shows *Require authentication strength: Phishing-resistant MFA* **AND** *Require device to be marked as compliant*
- **CA203**: session shows *Sign-in frequency: every time*

---

## Phase D — Population and parameters

The import created structure; this phase gives it meaning. Work from the [deployment parameters worksheet](deployment-parameters.md) — every row, no defaults assumed.

**D1. Break-glass** — two cloud-only accounts (the customer's naming, not ours) into `SG-CA-BreakGlass`. FIDO2 credentials per the runbook standard; configure sign-in alerting for both.

**D2. Users persona** — set the dynamic membership rule on `SG-CA-Users` (the all-employees rule from worksheet #2). Reconcile the resulting count against licensed headcount before trusting it.

**D3. Named locations** — replace the placeholder country list (`VCIO-NL-AllowedCountries`) and the RFC 5737 placeholder IP ranges (`VCIO-NL-ServiceAccountIPs`, per system where practical). A location still holding `203.0.113.0/24` matches nothing real, and the Ring 1 gate fails on it by name.

**D3a. The deployment manifest** — copy `Deploy/manifest.example.json` to `Deploy/<customer>/manifest.json` and fill it in *now*, while the tenant object IDs are in front of you. Every tool in `Tools/` takes `-Manifest`, and several gate checks cannot run without it. `Deploy/*/` is gitignored.

**D4. Service accounts** — populate `SG-CA-ServiceAccounts`, and decide the **fencing mode** (worksheet 6b), which goes in the manifest:

* **Shared** (default; one or two accounts): the shipped CA500/CA501 on `SG-CA-ServiceAccounts` and `VCIO-NL-ServiceAccountIPs`.
* **Per-System**: one instance pair per system — `build/generate.py --instance 500 BACKUP` and `--instance 501 BACKUP` — each on its own `SG-CA-SA-<SYSTEM>` group and `VCIO-NL-SA-<SYSTEM>` location. Every service account is a member of exactly one `SG-CA-SA-*` group **and** of the shared `SG-CA-ServiceAccounts`, which is what carries the CA002 exemption. In this mode the shared CA500 and CA501 are set to **disabled**, not report-only: report-only still evaluates, and would impose the shared location on a per-system account.

One mode per tenant. **Entra Connect sync accounts are never members of `SG-CA-ServiceAccounts`** — CA002 exempts them by role (A4), and if the customer wants them fenced it is a dedicated `CA500-VCIO-ServiceAccounts-IPFence-DirSync` instance on `SG-CA-SA-DirSync` carrying the Connect server's egress, which is a different scope from the application servers'.

**D4a. Privileged and transition groups** — populate `SG-CA-Privileged` from a first run of `Tools/Compare-VcioPrivilegedScope.ps1 -Manifest <path>` (worksheet 15), and `SG-CA-Transition-Hybrid` if the tenant has a hybrid-joined population, with an EXIT date recorded in the manifest (worksheet 16).

**D5. Guest apps and Tier 0 additions** — adjust CA401's excluded apps and CA103's included apps per worksheet #7/#8.

**D5a. App-enforced restrictions** — CA300's session control does nothing until SharePoint and Exchange are switched on service-side, and Exchange has no organization-level switch. Work through [app-enforced-restrictions.md](app-enforced-restrictions.md) before Ring 4; the Ring 4 gate reads both.

**D6. Assign App Protection:**
- `VCIO-APP-iOS-Baseline` → All Users, **include filter** `VCIO-FLT-iOS-UnmanagedDevices`
- `VCIO-APP-Android-Baseline` → All Users, **include filter** `VCIO-FLT-Android-UnmanagedDevices`
- `VCIO-APP-Windows-Edge-Baseline` → All Users, **no filter** (managed-app filters don't exist for Windows; MDM coexistence and CA301's unmanaged scope handle it)

**D7. The Ring 1 gate.** Re-run the prereqs script (PowerShell 7), naming the gate and the manifest:
```powershell
.\Invoke-VcioCaPrereqs.ps1 -Gate Ring1 -Manifest ..\Deploy\<customer>\manifest.json
```
Required result: **0 fail**. That now means break-glass membership ≥ 2 with FIDO2 *and* a permanent Global Administrator assignment on each, registration readiness, sync accounts inventoried and out of `SG-CA-ServiceAccounts`, and service-account coverage (B3a) — the fence verified against 30 days of sign-ins, not merely configured. This is the entry ticket to Phase E.

---

## Phase E — Enablement, in ring order

Nothing enables on import day. Each ring: switch its policies from report-only to **On**, after the previous ring has soaked and its gate is met. Between rings: minimum two weeks report-only observation via the Conditional Access insights workbook and sign-in logs, plus What-If checks against pilot users.

**Why this order:** Ring 1 closes the attack paths that cause most compromises and affects almost no legitimate users. Ring 2 is session hygiene — visible but low-harm. Ring 3 is privileged and risk enforcement — needs admin passkey enrollment lead time, so it can't go first. Ring 4 is device trust — the most user-visible, so it goes last, when compliance data is healthy and the BYOD path is ready to catch what it displaces.

### Ring 1 — Foundation blocks
`CA000` (legacy auth) · `CA001` (device code flow) · `CA002` (MFA catch-all) · `CA500` (service-account IP fence)

Gate: `-Gate Ring1` passes (D7); report-only shows no legitimate legacy-auth traffic, or what exists has a migration plan (scan-to-email devices are the classic finding — they need a relay or Graph sending, not an exclusion). Watch for: Teams Rooms and TV/console devices tripping CA001 — those go in `SG-CA-Excl-CA001`, fenced and reviewed.

**CA500 enables here, with CA002, not three rings later.** CA002's service-account exclusion and CA500's fence are two halves of one decision. Enabling the exclusion without the fence creates an account that is exempt from MFA and protected by nothing, and leaving it that way from Ring 1 to Ring 3 is weeks of exactly the gap an attacker looks for. The B3a check makes this concrete: it will not pass on an account in the exemption group with no enforced fence, and it will not pass on "no sign-ins in the window" either.

### Ring 2 — Hygiene
`CA003` (device-join MFA — disable the overlapping tenant toggle) · `CA004` (registration protection) · `CA005` (unknown platforms) · `CA007` (auth transfer) · `CA102` (admin sessions) · `CA203` (enrollment MFA) · `CA204` (unmanaged sessions) · `CA400/402/403` (guest MFA/sessions/portals)

Gate: `-Gate Ring2` passes, which adds the GDAP partner sign-in test ([partner-access.md](partner-access.md)) to Ring 1's list. TAP issuance SOP in place ([onboarding](onboarding.md)) — CA004 and CA203 both lean on it; frontline/phoneless users have a registration path; the cross-tenant MFA trust decision (worksheet #12) is configured before CA400.

**CA003 and CA004 are piloted, not soaked.** Report-only produces no data for user-action policies, so the two-week observation gives you an empty workbook. Pilot on a test group of at least five users including one real new-hire Autopilot run with a TAP. Remember CA004 now also gates WHfB and macOS PSSO registration — the TAP satisfies it.

### Ring 3 — Privileged, Tier 0, risk, fencing
`CA100` (phishing-resistant MFA) · `CA101` (admin device trust) · `CA103` (Tier 0 control plane) · `CA401` (guest default-deny) · `CA700–703` (risk, P2)

Gate: `-Gate Ring3` passes. **Every admin has a registered phishing-resistant method and a compliant device** — and "every admin" now means every `ADMIN_ROLES` holder *and* every `SG-CA-Privileged` member, so enroll passkeys weeks before this ring, not the day of. `Tools/Compare-VcioPrivilegedScope.ps1` must have a clean last run: no privileged principal uncovered, and no INCOMPLETE scope, because a management group you could not read is not a management group with nobody in it. The four-case GDAP partner test ([partner-access.md](partner-access.md)) runs here. Guest app list confirmed with business owners.

**CA501 is not in this ring.** It needs a discovery pass — you cannot write an app allow-list for an account before you know what it touches — so it gets a named owner and a date in worksheet item 6a instead, or a recorded decision to run IP-fenced without one.

### Ring 4 — Device trust and BYOD
`CA200/201` (Windows/macOS compliance) · `CA202` (mobile MAM) · `CA300/301` (BYOD browser controls)

Gate: `-Gate Ring4` passes, which reads the APP assignment collection directly (not `isAssigned`), resolves the iOS/Android filter and compares its **rule text**, checks the targeted app list against the shipped JSON, and verifies app-enforced restrictions in both SharePoint and Exchange ([app-enforced-restrictions.md](app-enforced-restrictions.md)). Plus: >95% of `SG-CA-Users` devices compliant or in remediation; the BYOD mode decision (contained vs hard) recorded. This ring displaces users onto the contained path — communicate it before enabling, not after.

**CA202's model changed in 2026.9.1.** It no longer filters managed devices out; it grants on compliant device **OR** app protection across the whole mobile population. A compliant device passes on compliance, an unmanaged device passes on APP, and an enrolled device that has fallen out of compliance is blocked unless a customer-added APP assignment reaches it. If that last case needs to keep working, that is an assignment you add deliberately and record in worksheet 13.

### Per-decision (no ring)
`CA006` (geo — customer decision, after parameters) · `CA600–602` + `CA704` (agents — only after an approved-agent inventory exists) · `CA705` (token protection — pilot with admins) · `800s` instances (as classified).

---

## After enablement

You're now in [runbook](runbook.md) territory: quarterly break-glass tests and exclusion reviews, monthly report-only drift decisions, monthly `Test-VcioCaBaseline.ps1` against a fresh tenant export to catch portal drift, and export-before-change discipline. The build is done; the operating model is permanent.
