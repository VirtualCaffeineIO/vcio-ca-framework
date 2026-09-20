# App-Enforced Restrictions

CA300 grants access and then hands the session a session control: *use app-enforced restrictions*. That control does nothing on its own. It sets a flag on the token and asks the resource to honour it, and only two resources ever do.

**The boundary, stated plainly: app-enforced restrictions are Exchange Online and SharePoint Online, and nothing else.** Teams file experiences ride on SharePoint Online and inherit it that way. Every other application in the tenant — every SaaS app behind Entra SSO, every line-of-business app, Power BI, Dynamics, third-party anything — ignores the flag completely. If a customer's unmanaged-browser story depends on a control the app has never heard of, they do not have an unmanaged-browser story for that app; they need the Restricted posture (CA800) or no browser access at all.

Both services must be switched on service-side. Until you do, CA300 is enabled, its report-only data looks healthy, and users download whatever they like.

## SharePoint Online

Organization-level, one setting:

```powershell
Connect-SPOService -Url https://<tenant>-admin.sharepoint.com
Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess
```

Admin-center equivalent: **SharePoint admin center → Policies → Access control → Unmanaged devices → "Allow limited, web-only access"**.

Verify:

```powershell
Get-SPOTenant | Select-Object ConditionalAccessPolicy
# ConditionalAccessPolicy : AllowLimitedAccess
```

That is exactly what the Ring 4 gate reads (B4). `AllowFullAccess` means the session control is inert.

**Site-level override.** Individual sites can be set independently, and a site set looser than the tenant wins for that site:

```powershell
Set-SPOSite -Identity https://<tenant>.sharepoint.com/sites/Finance `
    -ConditionalAccessPolicy AllowLimitedAccess
```

A tenant-level `AllowLimitedAccess` with a handful of sites overridden to `AllowFullAccess` is a common and easily missed configuration. Enumerate the overrides before you claim the control is in place:

```powershell
Get-SPOSite -Limit All | Where-Object { $_.ConditionalAccessPolicy -ne 'AllowLimitedAccess' } |
    Select-Object Url, ConditionalAccessPolicy
```

## Exchange Online

**There is no organization-level switch.** This is the part that gets missed. App-enforced restrictions in Exchange are a property of an *OWA mailbox policy*, so the control exists only for users mapped to a policy that carries it.

```powershell
Connect-ExchangeOnline
Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -ConditionalAccessPolicy ReadOnly
```

Values: `ReadOnly` (no download, no attachment open in a local app, no print), `ReadOnlyPlusAttachmentsBlocked` (also blocks attachment preview), `Off`.

Setting the default policy is not enough. Any tenant that has ever created a second OWA mailbox policy — for executives, for a business unit, for a migration — has users mapped elsewhere. Every policy that any in-scope user is mapped to needs the setting. Prove the mapping:

```powershell
Get-CasMailbox -ResultSize unlimited | Format-Table Name, OwaMailboxPolicy
Get-OwaMailboxPolicy | Format-Table Name, ConditionalAccessPolicy
```

A user mapped to an unrestricted OWA mailbox policy is a Ring 4 FAIL by name (B4), not a warning. One executive on a bespoke policy is exactly the gap worth failing the gate over.

## The third consumer: idle session timeout

Idle session sign-out in the Microsoft 365 admin center is the other control that reads this flag, and it is worth turning on alongside: an unmanaged browser session that cannot download anything but stays signed in on a shared machine has moved the risk, not removed it. **Microsoft 365 admin center → Settings → Org settings → Security & privacy → Idle session timeout.** It applies to the same web surfaces.

## Test matrix

Run every row from a genuinely unmanaged browser — a clean profile on a device that is not Entra-joined and not compliant — signed in as a member of `SG-CA-Users`. A managed device is excluded from CA300 by design and will show you nothing.

| # | Action | Expected with AER on |
|---|---|---|
| 1 | Download a file from a SharePoint document library | Blocked; the download control is unavailable |
| 2 | Download an attachment from OWA | Blocked |
| 3 | Open an attachment in the desktop app from OWA | Blocked; web preview only |
| 4 | Print a document from the SharePoint web viewer | Blocked |
| 5 | Print an email from OWA | Blocked |
| 6 | Open the Files tab in a Teams channel and download | Blocked — this is SPO, so it inherits |
| 7 | Sync a library with the OneDrive client | Blocked |
| 8 | Open a file in the web viewer and edit it | **Allowed** — this is the contained path working, not a failure |
| 9 | Reach a non-EXO/SPO SaaS app in the same browser | **Unrestricted** — outside the boundary; this row exists to make the limit visible |

Record row 9's result for the customer explicitly. It is the row that changes what people believe the control does.

## Where this is referenced

* CA300 (`BYOD-BrowserSessionControls`) — the policy that carries the session control.
* CA300-T, its transition variant, which carries the same one.
* Ring 4 gate, B4 — `SharePointAER` and `ExchangeAER` in `Prereqs/Invoke-VcioCaPrereqs.ps1`.
* [deployment-parameters.md](deployment-parameters.md) item 10, the BYOD mode decision.
