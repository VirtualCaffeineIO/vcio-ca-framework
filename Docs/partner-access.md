# Partner Access (GDAP)

A managed-services partner reaching the customer tenant through GDAP is the delivery model, not an intrusion. The framework has to admit them without pretending they are ordinary guests and without handing them a bypass. This document is what CA403's `serviceProvider` exclusion (A5) buys and what it costs.

## What is already true before any VCIO policy runs

**GDAP MFA is home-tenant enforced and always trusted.** A partner technician signing into a customer tenant through GDAP authenticates against the *partner's* tenant, with the partner's MFA, and Microsoft requires MFA for partner access as a condition of the program. The customer tenant does not get to re-challenge that; there is nothing to re-challenge, because the MFA already happened somewhere the customer's CA cannot reach.

Microsoft states this directly in the GDAP documentation — see [Partner security requirements](https://learn.microsoft.com/partner-center/security/partner-security-requirements) and the [GDAP overview](https://learn.microsoft.com/partner-center/customers/gdap-introduction). Treat a customer's "but do they have MFA?" as answered by the program, and put the evidence in the engagement record rather than trying to enforce it locally.

**Compliant-device trust is a separate, non-default setting.** Whether a partner technician's device being compliant *in the partner tenant* counts as compliant *in the customer tenant* is the inbound cross-tenant access setting, and it is off unless someone turned it on. This is worksheet item 14a. Without it, CA103's compliant-device half can never be satisfied by a partner device, no matter how well managed that device is — the customer tenant simply has no compliance signal for it.

## What the framework does

| Policy | Applies to service providers? | Why |
|---|---|---|
| CA400 Guests-MFA | **Yes** | Cheap, and harmless given home-tenant MFA already satisfied it |
| CA402 Guests-SessionHygiene | **Yes** | 12h sign-in frequency, no persistent browser — a partner session should not outlive the work |
| CA403 Guests-BlockAdminPortals | **No** (A5) | Blocking the admin portals breaks the engagement and pushes the customer toward a standing local admin account for the partner, which is strictly worse than a governed GDAP relationship |
| CA401 Guests-DefaultDenyApps | **No** (already excluded) | — |
| CA103 Tier0-ControlPlane-AllUsers | **Yes** | Phishing-resistant MFA **and** compliant device on Azure Resource Manager and the admin portals, for everyone, partner included |

So the exclusion is narrow: service providers are not blocked from admin portals *by CA403*, and are still held to CA103's Tier 0 requirements on the same portals. That is the design. A bare CA103 exclusion would drop both the strength requirement and the device requirement in one move and is never the answer.

## The open question

**Is the phishing-resistant authentication strength satisfiable over GDAP?**

We do not know, and we are not guessing. The partner authenticates at home; the customer tenant evaluates an authentication strength against claims that arrived cross-tenant. Whether a partner's FIDO2 sign-in surfaces to the customer tenant as satisfying `Phishing-resistant MFA` is exactly the kind of thing that is documented one way and behaves another. **The Ring 3 test decides it.** Nothing in this framework is written as though the answer is known.

## Tests

### Ring 2 — reachability

One test, before CA103 enforces: a partner technician signs in through GDAP and reaches **Microsoft Admin Portals**. This confirms the CA403 exclusion works and the relationship is live. Record the result in the manifest (`partnerAccessTests.Ring2`); the Ring 2 gate reads it, because no script can perform a partner sign-in on its own.

### Ring 3 — the four cases

Run all four before enabling CA103. Record the sign-in log outcome for each, not just pass/fail.

| # | Partner technician's credential | Partner device state | Expected |
|---|---|---|---|
| 1 | Phishing-resistant method | Compliant (with inbound trust on) | **Success** |
| 2 | Phishing-resistant method | Not compliant | **Block** |
| 3 | Non-phishing-resistant MFA | Compliant | **Block** |
| 4 | — | — | Case 1's sign-in log shows **CA103 applied** with result success |

Case 4 is not optional. A success with CA103 showing `notApplied` is not a pass — it means the policy never evaluated and case 2 and case 3 proved nothing either. Record the result in `partnerAccessTests.Ring3`.

## Fallbacks — written down, not chosen

These are recorded here so that the decision, if it is ever needed, is made from a written option set rather than invented under pressure. **Neither is selected. The test selects.**

**(a) If only the strength fails** — cases 2 and 3 behave, but case 1 blocks because the phishing-resistant strength cannot be satisfied cross-tenant:

Exclude `serviceProvider` from CA103 *and* add `CA104-VCIO-Tier0-ControlPlane-ServiceProviders`, targeting service providers on the same resources (Azure Resource Manager, Microsoft Admin Portals) and requiring `compliantDevice` only. The customer-side device requirement survives; only the strength requirement, which the customer cannot evaluate anyway, is dropped. The partner's own home-tenant strength policy is what carries that half, and the engagement record says so.

**(b) If compliant-device trust also fails** — case 1 blocks even with inbound trust configured, so neither half of CA103 is satisfiable over GDAP:

This is a customer decision, not ours, and it is a real one: either a documented partner exception to Tier 0 (named, owned, time-boxed, reviewed quarterly like any other exception under the runbook rules), or no GDAP — the partner works through a customer-issued, customer-managed, customer-compliant device instead. Present both. Do not pick one for them.

**Never a bare CA103 exclusion.** Excluding service providers from CA103 without a replacement policy drops the compliant-device requirement *and* the strength requirement simultaneously, and leaves the customer's control plane reachable from a partner technician's unmanaged laptop. Option (a) exists precisely so that "the strength does not work over GDAP" never becomes "so we turned Tier 0 off for the partner".

## Where this is referenced

* CA403 (A5) — the `serviceProvider` exclusion this document justifies.
* [deployment-parameters.md](deployment-parameters.md) item 12 (home-tenant MFA trust) and item 14a (inbound compliant-device trust).
* Ring 2 and Ring 3 gates — `PartnerSignInTest` in `Prereqs/Invoke-VcioCaPrereqs.ps1`.
* `Deploy/manifest.example.json` — `partnerTenants`, `partnerAccessTests`.
