<#
.SYNOPSIS
    E2. Execute the hybrid transition exit, in the only order that is safe.
.DESCRIPTION
    SG-CA-Transition-Hybrid is the hybrid population's coverage while it
    exists. Standard CA200/CA204/CA300/CA301 exclude the group; the Transition/
    variants include it. Emptying the group is therefore the exit: a removed
    user falls back under the standard policies on their next sign-in.

    That only holds if the fallback is real, so the order is fixed:

      1. For every member, verify they are in SG-CA-Users AND that CA200,
         CA204, CA300 and CA301 are 'enabled'. Any miss is reported by name
         and STOPS the run with the transition policies untouched. Removing a
         user whose fallback is a disabled policy or a group they are not in
         does not move them to the standard path — it moves them to nothing.
      2. Export the member list to the run log, then remove all members.
      3. On subsequent runs, verify a post-removal sign-in per removed user
         shows the standard policies applied.
      4. Only when every removed user is verified, set the transition
         policies to 'disabled'.

    Elapsed time never substitutes for verification. An unverified user is
    reported UNVERIFIED and the transition policies stay enabled — which is
    safe, because the group is already empty and an enabled policy over an
    empty group affects nobody.

    Disabling the transition policies BEFORE the group is empty is the one
    genuinely dangerous move available here: the standard policies' exclusions
    are still active, so those users would be covered by nothing. This script
    will not do it.

    Idempotent across runs. -WhatIf supported.

    Runbook: schedule daily (Azure Automation or the MSP's job host). Where
    Entra ID Governance is licensed, a recurring access review with auto-remove
    on the group is the supported alternative to scheduling this.
.PARAMETER Manifest
    Deploy/<tenant>/manifest.json. Reads transition.exitDate; writes
    transition.verifiedRemovals and transition.groupEmptiedDate.
.EXAMPLE
    .\Invoke-VcioTransitionExit.ps1 -Manifest ..\Deploy\contoso\manifest.json -WhatIf
.NOTES
    Requires Microsoft.Graph.Authentication, Microsoft.Graph.Groups,
    Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns,
    Microsoft.Graph.Reports.
    Version 2026.9.1.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$Manifest,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Manifest)) { throw "Manifest not found: $Manifest" }
$mf = Get-Content -Raw $Manifest | ConvertFrom-Json

$TRANSITION_GROUP = 'SG-CA-Transition-Hybrid'
$USERS_GROUP      = 'SG-CA-Users'
$STANDARD_POLICIES = @(
    'CA200-VCIO-Users-Windows-CompliantDevice',
    'CA204-VCIO-Users-SessionHygiene-Unmanaged',
    'CA300-VCIO-BYOD-BrowserSessionControls',
    'CA301-VCIO-BYOD-Windows-RequireAppProtection'
)
$TRANSITION_POLICIES = @(
    'CA200-VCIO-Users-Windows-CompliantOrHybrid-TRANSITION',
    'CA204-VCIO-Users-SessionHygiene-Unmanaged-TRANSITION',
    'CA300-VCIO-BYOD-BrowserSessionControls-TRANSITION',
    'CA301-VCIO-BYOD-Windows-RequireAppProtection-TRANSITION'
)

if (-not $LogPath) {
    $LogPath = Join-Path (Split-Path $Manifest -Parent) 'transition-exit.log'
}
function Write-Log([string]$Message) {
    $line = "{0}  {1}" -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK'), $Message
    Write-Host $line
    if ($PSCmdlet.ShouldProcess($LogPath, 'append to run log')) {
        Add-Content -Path $LogPath -Value $line -Encoding utf8
    }
}

Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
Connect-MgGraph -Scopes @(
    'Group.ReadWrite.All','User.Read.All','Policy.ReadWrite.ConditionalAccess',
    'Policy.Read.All','AuditLog.Read.All'
) -NoWelcome

$policies = @(Get-MgIdentityConditionalAccessPolicy -All)
function Get-Policy([string]$Name) { $policies | Where-Object { $_.DisplayName -eq $Name } | Select-Object -First 1 }

$group = Get-MgGroup -Filter "displayName eq '$TRANSITION_GROUP'" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $group) { throw "$TRANSITION_GROUP not found in the tenant." }
$usersGroup = Get-MgGroup -Filter "displayName eq '$USERS_GROUP'" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $usersGroup) { throw "$USERS_GROUP not found in the tenant." }

$members = @(Get-MgGroupMember -GroupId $group.Id -All)
$exitDate = if ($mf.transition.exitDate) { [datetime]::Parse($mf.transition.exitDate) } else { $null }
if (-not $exitDate) { throw 'Manifest has no transition.exitDate. The exit date lives in the manifest, not the policy JSON.' }

Write-Log ("Transition exit run. Group '{0}' has {1} member(s). exitDate {2}." -f `
    $TRANSITION_GROUP, $members.Count, $exitDate.ToString('yyyy-MM-dd'))

# ---------------------------------------------------------------- phase 1+2
if ($members.Count -gt 0) {
    if ((Get-Date) -lt $exitDate) {
        $days = [int]($exitDate - (Get-Date)).TotalDays
        Write-Log "Before exitDate ($days day(s) remaining) with $($members.Count) member(s). Nothing removed."
        Write-Log 'Transition policies must stay enabled while the group is populated.'
        exit 0
    }

    # Verify the fallback is real BEFORE removing anyone.
    Write-Log 'On or after exitDate. Verifying the fallback before removing anyone.'
    $blocking = New-Object System.Collections.Generic.List[string]

    foreach ($n in $STANDARD_POLICIES) {
        $p = Get-Policy $n
        if (-not $p) { $blocking.Add("$n is absent from the tenant") }
        elseif ($p.State -ne 'enabled') { $blocking.Add("$n is '$($p.State)', not 'enabled'") }
    }

    $usersMembers = @(Get-MgGroupMember -GroupId $usersGroup.Id -All | ForEach-Object { $_.Id })
    $roster = @()
    foreach ($m in $members) {
        $u = Get-MgUser -UserId $m.Id -Property userPrincipalName -ErrorAction SilentlyContinue
        $upn = if ($u) { $u.UserPrincipalName } else { $m.Id }
        $roster += [pscustomobject]@{ Id = $m.Id; Upn = $upn }
        if ($m.Id -notin $usersMembers) {
            $blocking.Add("$upn is not a member of $USERS_GROUP — removing them from the transition group would leave them covered by neither path")
        }
    }

    if ($blocking.Count) {
        Write-Log "STOPPED. $($blocking.Count) blocking condition(s); transition policies untouched, no members removed:"
        $blocking | ForEach-Object { Write-Log "  - $_" }
        exit 1
    }

    Write-Log "Fallback verified for all $($members.Count) member(s). Exporting roster, then removing."
    foreach ($r in $roster) { Write-Log "  REMOVING $($r.Upn) ($($r.Id))" }

    foreach ($r in $roster) {
        if ($PSCmdlet.ShouldProcess($r.Upn, "remove from $TRANSITION_GROUP")) {
            Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $r.Id
        }
    }

    # Record who was removed and when, so later runs know whom to verify.
    $pending = @($roster | ForEach-Object {
        [pscustomobject]@{ upn = $_.Upn; id = $_.Id; removedDate = (Get-Date).ToString('yyyy-MM-dd'); verified = $false }
    })
    $existing = @($mf.transition.verifiedRemovals)
    $known = @($existing | ForEach-Object { $_.id })
    $mf.transition.verifiedRemovals = @($existing) + @($pending | Where-Object { $_.id -notin $known })
    $mf.transition.groupEmptiedDate = (Get-Date).ToString('yyyy-MM-dd')
    if ($PSCmdlet.ShouldProcess($Manifest, 'record removals')) {
        $mf | ConvertTo-Json -Depth 12 | Set-Content -Path $Manifest -Encoding utf8
    }
    Write-Log 'Members removed. Transition policies stay ENABLED until every removed user is verified on the standard path.'
    exit 0
}

# ---------------------------------------------------------------- phase 3+4
Write-Log 'Group is empty. Verifying post-removal sign-ins for every removed user.'
$removals = @($mf.transition.verifiedRemovals)
if (-not $removals.Count) {
    Write-Log 'No recorded removals to verify. Nothing to do.'
    exit 0
}

$standardIds = @{}
foreach ($n in $STANDARD_POLICIES) {
    $p = Get-Policy $n
    if ($p) { $standardIds[$p.Id] = $n }
}

$unverified = New-Object System.Collections.Generic.List[string]
foreach ($r in $removals) {
    if ($r.verified) { continue }
    $since = ([datetime]::Parse($r.removedDate)).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $signIns = @()
    try {
        $signIns = @(Get-MgAuditLogSignIn -Filter "userId eq '$($r.id)' and createdDateTime ge $since" -All -ErrorAction Stop)
    } catch {
        $unverified.Add("$($r.upn) — could not read sign-in logs: $($_.Exception.Message)")
        continue
    }
    $applied = @($signIns | Where-Object {
        @($_.AppliedConditionalAccessPolicies | Where-Object { $standardIds.ContainsKey($_.Id) -and $_.Result -ne 'notApplied' }).Count -gt 0
    })
    if ($applied.Count) {
        $r.verified = $true
        Write-Log "  VERIFIED $($r.upn) — standard policies applied on a post-removal sign-in."
    } else {
        # Time passing is not evidence. Until this user actually signs in and
        # the log shows a standard policy applied, nothing proves the fallback
        # took effect for them.
        $unverified.Add("$($r.upn) — no post-removal sign-in shows a standard policy applied (removed $($r.removedDate))")
    }
}

if ($PSCmdlet.ShouldProcess($Manifest, 'record verification results')) {
    $mf | ConvertTo-Json -Depth 12 | Set-Content -Path $Manifest -Encoding utf8
}

if ($unverified.Count) {
    Write-Log "UNVERIFIED: $($unverified.Count) removed user(s) not yet confirmed on the standard path."
    $unverified | ForEach-Object { Write-Log "  - $_" }
    Write-Log 'Transition policies stay ENABLED. This is safe — the group is empty, so they affect nobody. Re-run after these users have signed in.'
    exit 0
}

Write-Log 'Every removed user verified on the standard path. Disabling the transition policies.'
foreach ($n in $TRANSITION_POLICIES) {
    $p = Get-Policy $n
    if (-not $p) { Write-Log "  $n absent — nothing to disable."; continue }
    if ($p.State -eq 'disabled') { Write-Log "  $n already disabled."; continue }
    if ($PSCmdlet.ShouldProcess($n, "set state to 'disabled'")) {
        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $p.Id -State 'disabled'
        Write-Log "  $n -> disabled."
    }
}
Write-Log 'Transition exit complete.'
exit 0
