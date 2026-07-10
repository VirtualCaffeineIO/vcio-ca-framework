# Identity and Device Onboarding

The framework keeps MFA on Intune enrollment (CA203) and on security-info registration (CA004), because both are privileged acts: a compliant device is a credential that satisfies CA200/CA201 forever after, and a registered MFA method is the key to everything. What makes these policies livable is the method below — not exclusion groups.

## The recommendation hierarchy

**1. User-driven Autopilot + Temporary Access Pass — the default for new hires.**
IT issues a time-boxed TAP with the new hire's credentials at onboarding. During OOBE the TAP satisfies CA203's every-time MFA and CA004's registration protection in one motion, and bootstraps Windows Hello for Business — the user lands passwordless on day one, with their phishing-resistant method already established. SOP: TAP lifetime 8 hours, one-time use, issued the morning of start date, never emailed to a personal address alongside the password (split channels).

**2. Pre-provisioning — the default for bulk and technician staging.**
The technician phase of Autopilot pre-provisioning authenticates with nothing; a tech staging fifty laptops sees zero MFA prompts. The single MFA moment happens at the user's first sign-in, where it belongs. If your process has technicians completing full user-driven enrollment on behalf of users, that process — not the CA policy — is what needs fixing.

**3. Self-deploying mode — kiosks and shared devices.**
TPM attestation, device-based join, no user MFA involved. CA203 targets users and never fires.

**4. Autopilot Device Preparation (v2) — least preferred, handled honestly.**
Its automated enrollment cannot complete MFA and devices hang in OOBE under CA203. If a customer requires v2: either a provisioning exclusion group on CA203 that is *emptied after each onboarding wave* (calendared, owned, reviewed — an exception under the runbook rules, not a standing hole), or a trusted named location fenced to the staging bench's egress IP. Never a permanent exclusion.

## Day-one identity flow (no device involved)

New user, no MFA methods registered: CA004 requires MFA to register security info, and the TAP satisfies it. Without the framework's TAP SOP, the first person to present that user's password gets to choose their MFA — which is exactly the race the attacker wants to win. The TAP closes the race: methods get registered under a credential IT controls the distribution of.

Frontline and phoneless workers: hardware OATH tokens or FIDO2 keys instead of Authenticator; TAP still bootstraps. Shared-device workers: pair with shared device mode; the 12-hour sign-in frequency (CA204) applies per-user on shared browsers.

## Known interactions

* **Windows first sign-in animation / restore**: if CA200 blocks Microsoft Activity Feed Service during OOBE, add the documented exclusion (app `d32c68ad-72d2-4acb-a0c7-46bb2cf93873`) to CA200 — a known first-party quirk.
* **WHfB enrollment requires MFA**: satisfied by the TAP during OOBE. If a user skips WHfB setup, their next opportunity prompts classic MFA — which they registered under the TAP session.
* **Autopilot + CA003 (register/join MFA)**: user-driven Autopilot presents the user's credentials during OOBE; the TAP covers this too. Disable the legacy tenant-wide "require MFA to register devices" toggle so CA003 is the single control.
