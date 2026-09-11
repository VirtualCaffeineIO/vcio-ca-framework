# Deployment Parameters Worksheet

Nothing in this framework carries a functional default that could lock a tenant out — which means these parameters are **required**, not suggestions. Complete this worksheet per customer before enabling anything past Ring 1. Keep the completed copy with the customer's engagement records; the exclusion-group owner column is what the quarterly reviews audit against.

## Required parameters

| # | Parameter | Where it lands | Value (fill in) | Owner |
|---|---|---|---|---|
| 1 | Break-glass account UPNs (2, cloud-only, FIDO2) | `SG-CA-BreakGlass` members | | |
| 2 | All-employees dynamic membership rule | `SG-CA-Users` | | |
| 3 | Admin role list confirmation (default: 24 shipped roles) | 100s policies | | |
| 4 | Allowed countries | `VCIO-NL-AllowedCountries` | | |
| 5 | Service account UPNs | `SG-CA-ServiceAccounts` members | | |
| 6 | Service account egress IP ranges (per account/system) | `VCIO-NL-ServiceAccountIPs`, or `VCIO-NL-SA-<SYSTEM>` per instance | | |
| 6a | **CA501 owner and deadline, per service account** — or the "IP-fenced without an app allow-list" decision, recorded as a decision | Manifest `serviceAccounts[]`; CA501 | | |
| 6b | **Fencing mode: Shared (default) or Per-System.** One mode per tenant | Manifest `fencingMode` | | |
| 7 | Guest-accessible apps (default: Office 365 + My Apps) | CA401 excludeApplications | | |
| 8 | Tier 0 additions (customer control-plane apps) | CA103 includeApplications | | |
| 9 | Linux endpoints in scope? (Y → edit CA005 excludePlatforms) | CA005 | | |
| 10 | BYOD mode: Contained (default) or Hard-block | 300s | | |
| 11 | Hybrid transition needed? (Y → deploy Transition variants + exit date) | 200s | | |
| 12 | Cross-tenant access: trust home-tenant MFA for guests? | Entra cross-tenant settings (companion to CA400) | | |
| 13 | Tier 1 app classification + posture (per sensitive app) | 800s templates | | |
| 14 | **Cross-tenant inbound trust for compliant devices from the partner tenant** — an organizational setting, off by default | Entra cross-tenant access (companion to CA103 over GDAP) | | |
| 15 | **`SG-CA-Privileged` membership source** — who reconciles it, how often, and at which step of the privilege-grant procedure a user is added | `SG-CA-Privileged`; `Tools/Compare-VcioPrivilegedScope.ps1` | | |
| 16 | **`SG-CA-Transition-Hybrid` membership and EXIT date** | Group membership; manifest `transition.exitDate` | | |
| 17 | Exclusion-group owners (one named owner per SG-CA-Excl-*) | Governance | | |

## Notes on specific parameters

**2 — the Users group is the persona linchpin.** Every device, session, and BYOD control keys on `SG-CA-Users`. An employee not in it silently loses all of them and keeps only catch-all MFA. Use a dynamic rule you can reason about (e.g. `user.accountEnabled -eq true and user.userType -eq "Member" and user.employeeId -ne null` — adapt to the tenant's attribute hygiene), then reconcile its count against licensed headcount. Treat divergence as an incident, not housekeeping.

**4 — geo honesty.** CA006 trims commodity noise. Any targeted attacker rents an in-country proxy for pennies. Ship it if the customer expects it, but the roadmap control for location is the Global Secure Access compliant network check (requires Entra Internet Access licensing).

**6 — per-system fencing.** One big "all our service accounts, all our IPs" range recreates the coarse country fence with extra steps. Fence per system where practical: the backup service account gets the backup server's egress, nothing else.

**13 — the OR-grant model for mobile.** CA202 (and the CA803 MAM-Mobile template) grant on `compliantDevice` **OR** `compliantApplication`, with no device filter. Read what that means before classifying an app: a compliant enrolled device passes on compliance; an unmanaged device passes on app protection; and an enrolled device that has *fallen out of compliance* is blocked, unless some other effective APP assignment happens to reach it — the shipped filters (`app.deviceManagementType -eq "Unmanaged"`) do not, though a customer-added assignment might. The previous model filtered managed devices out of the policy entirely, which meant a non-compliant enrolled phone was governed by nothing. If a customer wants the non-compliant enrolled device to keep working through MAM, that is an APP assignment they add deliberately and record here — not a side effect of a filter.

**14 — partner device trust is not the same setting as partner MFA trust.** Item 12 is whether you trust the partner tenant's MFA claim; item 14 is whether you trust its device-compliance claim. Both are off by default and they are configured separately. CA103 requires a compliant device of everyone including service providers, and without item 14 the customer tenant has no compliance signal for a partner technician's device at all — no matter how well the partner manages it. See [partner-access.md](partner-access.md), including the fallbacks if the Ring 3 test says this cannot be satisfied over GDAP.

**16 — the exit date is an operator deadline, not an enforced expiry.** It lives in the deployment manifest because the policy objects have nowhere to carry it: Graph documents `conditionalAccessPolicy.description` as "Not used" and nothing proves a value there survives an import/export round trip. What enforces it is the drift validator's C2 rule plus `Tools/Invoke-VcioTransitionExit.ps1` on a daily schedule — or, where Entra ID Governance is licensed, a recurring access review with auto-remove on the group. Emptying the group is the exit; the exit *order* is fixed and the script implements it.

**13 — App Protection settings.** The companion MAM baseline is aligned to Microsoft's Data Protection Framework Level 2 (enterprise enhanced): PIN 6-digit, org data to managed apps only, paste-in allowed, save-as restricted to OneDrive/SharePoint, print blocked, 90-day offline wipe. Raise to L3 settings per customer where warranted; document deviations here.

**APP assignment pattern (fixed, not a parameter):** assign the iOS and Android APP policies to **All Users** with the platform's `VCIO-FLT-*-UnmanagedDevices` managed-app filter in include mode (`app.deviceManagementType -eq "Unmanaged"`) — MAM applies only where MDM doesn't, and enrolled devices never get double-managed. The prereqs script creates both filters. **Windows is different:** managed-app filters don't exist for Windows, so `VCIO-APP-Windows-Edge-Baseline` assigns to All Users with no filter — MDM-enrolled Windows yields to MDM by coexistence design, and CA301 only targets unmanaged devices at the CA layer.

## Placeholder inventory (must be replaced)

| Placeholder | File | Replace with |
|---|---|---|
| `US` country list | `Config/NamedLocations/VCIO-NL-AllowedCountries.json` | Customer's operating countries |
| `203.0.113.0/24` | `VCIO-NL-ServiceAccountIPs.json`, `VCIO-NL-TrustedEgress.json`, `Templates/NamedLocations/VCIO-NL-SA-SYSTEMNAME.json` | Real egress ranges (placeholders are RFC 5737 documentation space — they match nothing). The Ring 1 gate fails a named location still holding one |
| `REPLACE-WITH-APP-ID` | `Templates/ConditionalAccess/*` | Target app's application ID, per instantiation |
| `APPNAME` / `SYSTEMNAME` | `Templates/ConditionalAccess/*`, `Templates/Groups/*`, `Templates/NamedLocations/*` | Never edited in place — `build/generate.py --instance <nnn> <NAME>` creates an instance with its own GUIDs and its own exclusion group. `Templates/` is never bulk-imported |
| `00000000-0000-0000-0000-000000000000` TenantId | `Config/MigrationTable.json` | Populated by IntuneManagement at export/import |
