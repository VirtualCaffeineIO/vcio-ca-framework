# Upgrading an Existing Deployment

Applies when a tenant already holds a previous version of the framework. A fresh tenant does not need this document — follow [implementation-guide.md](implementation-guide.md) instead.

> **Status: the upgrade path for 2026.9.1 is not yet lab-validated.** The F2 upgrade test has not been run. Until its result is recorded in this document, an existing 2026.7.1 tenant should stay on 2026.7.1. Note that **2026.9.1 is for lab evaluation only** in any case: a fresh deployment is no more validated than an upgrade, because no live-tenant test has been run.

## Before anything

1. **Export.** IntuneManagement bulk export of the whole tenant, kept somewhere you can find it. This is the rollback: re-importing the previous export is how you undo the upgrade.
2. **Record current enforcement states.** Which policies are On, which are report-only, which are off. An upgrade that silently returns an enforced policy to report-only is a security regression that nobody notices for a month.
3. **Record customer edits.** Populated exclusion groups, real IP ranges in the named locations, added app IDs, any policy the customer edited in the portal.

## 2026.7.1 → 2026.9.1

### Retirement step: the old CA801 (required, do this first)

2026.9.1 reuses the CA801 slot. In 2026.7.1, `CA801-VCIO-Ext-StepUp-APPNAME` was the Step-Up posture (compliant device **or** MFA). That posture was removed — for anyone inside CA002's scope, MFA alone already satisfied it, so it enforced nothing CA002 did not. In 2026.9.1, CA801 is `Ext-Tier0-APPNAME`: compliant device **and** phishing-resistant MFA.

**The two are not the same policy and one must not become the other by import.** Before importing 2026.9.1 into a tenant that holds 2026.7.1:

1. Find every instantiated Step-Up policy:
   ```powershell
   Get-MgIdentityConditionalAccessPolicy -All |
       Where-Object DisplayName -like 'CA801-VCIO-Ext-StepUp-*' |
       Select-Object DisplayName, State, Id
   ```
2. Export each one, and note its exclusion group and that group's membership.
3. Delete each one, and delete its instance exclusion group (`SG-CA-Excl-CA801-<App>`) once you have the membership recorded.
4. Decide, per app, what replaces it. A Step-Up app is usually either Restricted (CA800) or genuinely Tier 0 (the new CA801) — that is a classification decision with the business owner, not a mechanical substitution. Instantiate the replacement afterwards:
   ```powershell
   python3 build/generate.py --instance 800 <AppName>   # or 801, for real Tier 0
   ```

Skipping this leaves an orphaned Step-Up policy that the 2026.9.1 validators do not recognise and that no longer matches any shipped template.

### What the import should do

| Object | Expected |
|---|---|
| Existing policies | Updated **in place**, not duplicated |
| CA001 | Renamed to `CA001-VCIO-Global-BlockDeviceCodeFlow`, still blocking device code flow only |
| CA007 | **Created** — `Global-BlockAuthTransfer`, with a new `SG-CA-Excl-CA007` |
| CA204-T, CA300-T, CA301-T | Created in `Transition/` |
| `SG-CA-Privileged`, `SG-CA-Transition-Hybrid` | Created, empty |
| MigrationTable | Remaps to the **existing** groups and named locations, not new copies |
| Customer group membership | Preserved |
| Named location IP ranges | Preserved |
| Enforcement states | Preserved — an On policy must not return to report-only |

### After the import

1. Populate `SG-CA-Privileged` from `Tools/Compare-VcioPrivilegedScope.ps1`, and `SG-CA-Transition-Hybrid` if the tenant has a hybrid population (worksheet item 16, with an EXIT date).
2. Add the transition exit date and the fencing mode to the deployment manifest — the manifest is new in 2026.9.1 and several checks now need it.
3. Re-run the gate for the tenant's current ring: `Prereqs/Invoke-VcioCaPrereqs.ps1 -Gate RingN -Manifest <path>`.
4. Run the drift validator against a fresh export: `Tools/Test-VcioCaBaseline.ps1 -Path <export> -Manifest <path>`.

### Rollback

Re-import the 2026.7.1 export taken before the upgrade. Because rollback is a re-import rather than a reversal, the pre-upgrade export is not optional.

## F2 — upgrade test result

**NOT RUN.** This section is where the result goes.

The test requires a lab tenant holding 2026.7.1 as deployed — with customer-shaped edits: populated groups, real IP ranges, at least one exclusion-group member, two policies set to On, and one instantiated `CA801-VCIO-Ext-StepUp-TESTAPP` with its instance exclusion group holding a member — and Windows PowerShell 5.1 to run IntuneManagement. Neither was available when 2026.9.1 was prepared.

When it runs, record:

- [ ] Policies updated in place versus duplicated
- [ ] CA001 renamed; CA007 created
- [ ] MigrationTable remapped to existing groups and locations
- [ ] Customer group membership preserved
- [ ] Named location IP ranges preserved
- [ ] Enforcement states preserved (no On policy silently returned to report-only)
- [ ] Old CA801 instance and its instance group retired per the steps above
- [ ] New Tier 0 instance created with a distinct exclusion group whose ID resolves through the MigrationTable to a real, separate tenant group — not a renamed one, not shared with any other policy
- [ ] Rollback by re-importing the 2026.7.1 export

Until every box is ticked here, the README says lab evaluation only.
