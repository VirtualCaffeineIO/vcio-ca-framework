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
.\Invoke-VcioCaPrereqs.ps1 -Fix
```
Sign in as the Global Admin in the browser popup and accept the scope consent (delegated, your account only — no app registrations are created).

The script auto-detects that no VCIO policies exist yet and runs in **pre-import mode**. Expected result:

```
No VCIO CA policies found in tenant — running in PRE-IMPORT mode automatically.
[PASS] Security defaults disabled
[WARN] Break-glass group exists          <- expected: import creates it
[PASS] Microsoft Intune Enrollment service principal
[PASS] Temporary Access Pass method enabled
[PASS] Assignment filter: VCIO-FLT-iOS-UnmanagedDevices      (Created via Graph)
[PASS] Assignment filter: VCIO-FLT-Android-UnmanagedDevices  (Created via Graph)
[PASS] App Protection: VCIO-APP-iOS-Baseline                 (Created via Graph)
[PASS] App Protection: VCIO-APP-Android-Baseline             (Created via Graph)
[PASS] App Protection: VCIO-APP-Windows-Edge-Baseline        (Created via Graph)
Pre-import gate PASSED.
```

`-Fix` created: the Intune Enrollment service principal (if missing), enabled Temporary Access Pass, the two managed-app filters, and all three App Protection baselines (created via Graph because IntuneManagement cannot import the Windows MAM type). If security defaults show FAIL, disable them (Entra ID → Properties) and re-run.

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
| Entra → Conditional Access | 27 core policies (+6 overlay), all `CA###-VCIO-*`, all report-only/off |
| Entra → Groups | 32 `SG-CA-*` groups, all empty |
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

**D3. Named locations** — replace the placeholder country list (`VCIO-NL-AllowedCountries`) and the RFC 5737 placeholder IP ranges (`VCIO-NL-ServiceAccountIPs`, per system where practical).

**D4. Service accounts** — populate `SG-CA-ServiceAccounts`.

**D5. Guest apps and Tier 0 additions** — adjust CA401's excluded apps and CA103's included apps per worksheet #7/#8.

**D6. Assign App Protection:**
- `VCIO-APP-iOS-Baseline` → All Users, **include filter** `VCIO-FLT-iOS-UnmanagedDevices`
- `VCIO-APP-Android-Baseline` → All Users, **include filter** `VCIO-FLT-Android-UnmanagedDevices`
- `VCIO-APP-Windows-Edge-Baseline` → All Users, **no filter** (managed-app filters don't exist for Windows; MDM coexistence and CA301's unmanaged scope handle it)

**D7. The full gate.** Re-run the prereqs script (PowerShell 7):
```powershell
.\Invoke-VcioCaPrereqs.ps1
```
It now detects the VCIO policies and runs the complete check set. Required result: **0 fail** — including break-glass membership ≥ 2 and FIDO2 registered. This is the entry ticket to Phase E.

---

## Phase E — Enablement, in ring order

Nothing enables on import day. Each ring: switch its policies from report-only to **On**, after the previous ring has soaked and its gate is met. Between rings: minimum two weeks report-only observation via the Conditional Access insights workbook and sign-in logs, plus What-If checks against pilot users.

**Why this order:** Ring 1 closes the attack paths that cause most compromises and affects almost no legitimate users. Ring 2 is session hygiene — visible but low-harm. Ring 3 is privileged and risk enforcement — needs admin passkey enrollment lead time, so it can't go first. Ring 4 is device trust — the most user-visible, so it goes last, when compliance data is healthy and the BYOD path is ready to catch what it displaces.

### Ring 1 — Foundation blocks
`CA000` (legacy auth) · `CA001` (device code flow/auth transfer) · `CA002` (MFA catch-all)

Gate: full prereqs pass (D7); report-only shows no legitimate legacy-auth traffic, or what exists has a migration plan (scan-to-email devices are the classic finding — they need a relay or Graph sending, not an exclusion). Watch for: Teams Rooms and TV/console devices tripping CA001 — those go in `SG-CA-Excl-CA001`, fenced and reviewed.

### Ring 2 — Hygiene
`CA003` (device-join MFA — disable the overlapping tenant toggle) · `CA004` (registration protection) · `CA005` (unknown platforms) · `CA102` (admin sessions) · `CA203` (enrollment MFA) · `CA204` (unmanaged sessions) · `CA400/402/403` (guest MFA/sessions/portals)

Gate: TAP issuance SOP in place ([onboarding](onboarding.md)) — CA004 and CA203 both lean on it; frontline/phoneless users have a registration path; the cross-tenant MFA trust decision (worksheet #12) is configured before CA400.

### Ring 3 — Privileged, Tier 0, risk, fencing
`CA100` (phishing-resistant MFA) · `CA101` (admin device trust) · `CA103` (Tier 0 control plane) · `CA401` (guest default-deny) · `CA500/501` (service accounts) · `CA700–703` (risk, P2)

Gate: **every admin has a registered phishing-resistant method and a compliant device** — enroll passkeys weeks before this ring, not the day of; service-account fences verified against 30 days of CA500 report-only data (each would-be block explained); guest app list confirmed with business owners.

### Ring 4 — Device trust and BYOD
`CA200/201` (Windows/macOS compliance) · `CA202` (mobile MAM) · `CA300/301` (BYOD browser controls)

Gate: >95% of `SG-CA-Users` devices compliant or in remediation; APP policies assigned per D6; the BYOD mode decision (contained vs hard) recorded. This ring displaces users onto the contained path — communicate it before enabling, not after.

### Per-decision (no ring)
`CA006` (geo — customer decision, after parameters) · `CA600–602` + `CA704` (agents — only after an approved-agent inventory exists) · `CA705` (token protection — pilot with admins) · `800s` instances (as classified).

---

## After enablement

You're now in [runbook](runbook.md) territory: quarterly break-glass tests and exclusion reviews, monthly report-only drift decisions, monthly `Test-VcioCaBaseline.ps1` against a fresh tenant export to catch portal drift, and export-before-change discipline. The build is done; the operating model is permanent.
