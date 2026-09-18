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

    SCHEDULING: this cmdlet is ConfirmImpact='High', so every removal prompts
    when run interactively. A scheduled run MUST pass -Confirm:$false or it
    will block on the first prompt and the exit will never progress — a daily
    job that silently waits forever looks exactly like a daily job that has
    nothing to do.

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
    [string]$LogPath,
    # Group membership changes are not instantaneous. A sign-in inside this
    # window after the removal may still have been evaluated against the old
    # membership, so it is not evidence either way and is ignored.
    [ValidateRange(0,1440)][int]$PropagationMinutes = 30
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
Import-Module (Join-Path $PSScriptRoot 'VcioCaCommon.psm1') -Force

function Write-Log([string]$Message) {
    $line = "{0}  {1}" -f [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $Message
    Write-Host $line
    if ($PSCmdlet.ShouldProcess($LogPath, 'append to run log')) {
        Add-Content -Path $LogPath -Value $line -Encoding utf8
    }
}

# Finding 7 — connect to the tenant the MANIFEST names, and prove it before
# anything is written. This script removes group members and disables
# policies; the first write is actually Write-Log's Add-Content, so the
# assertion goes above it, not merely above the Graph writes.
Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
Connect-MgGraph -TenantId $mf.tenantId -Scopes @(
    'Group.ReadWrite.All','User.Read.All','Policy.ReadWrite.ConditionalAccess',
    'Policy.Read.All','AuditLog.Read.All'
) -NoWelcome
$connectedTenant = Assert-VcioTenantContext -ExpectedTenantId $mf.tenantId
Write-Host "Tenant verified: $connectedTenant" -ForegroundColor Cyan

$policies = @(Get-MgIdentityConditionalAccessPolicy -All)

# Finding 7 — resolve by the object ids the manifest recorded at import.
# displayName is a fallback only, and is logged as one: the shipped GUIDs are
# uuid5 build ids that IntuneManagement remaps, and a displayName lookup will
# cheerfully match a policy someone renamed or duplicated.
function Resolve-Policy([string]$Name) {
    $ref = Resolve-VcioObjectId -Manifest $mf -Kind 'policies' -Name $Name -Fallback {
        param($n) ($policies | Where-Object { $_.DisplayName -eq $n } | Select-Object -First 1).Id
    }
    if ($ref.Source -eq 'displayName-fallback') {
        Write-Log "  NOTE: '$Name' resolved by displayName FALLBACK — no object id in the manifest. Record it."
    }
    if (-not $ref.Id) { return $null }
    $policies | Where-Object { $_.Id -eq $ref.Id } | Select-Object -First 1
}
function Resolve-Group([string]$Name) {
    $ref = Resolve-VcioObjectId -Manifest $mf -Kind 'groups' -Name $Name -Fallback {
        param($n) (Get-MgGroup -Filter "displayName eq '$n'" -ErrorAction SilentlyContinue | Select-Object -First 1).Id
    }
    if ($ref.Source -eq 'displayName-fallback') {
        Write-Log "  NOTE: '$Name' resolved by displayName FALLBACK — no object id in the manifest. Record it."
    }
    $ref
}

$groupRef = Resolve-Group $TRANSITION_GROUP
if (-not $groupRef.Id) { throw "$TRANSITION_GROUP could not be resolved from the manifest or by displayName." }
$group = [pscustomobject]@{ Id = $groupRef.Id }
$usersRef = Resolve-Group $USERS_GROUP
if (-not $usersRef.Id) { throw "$USERS_GROUP could not be resolved from the manifest or by displayName." }
$usersGroup = [pscustomobject]@{ Id = $usersRef.Id }

$members = @(Get-MgGroupMember -GroupId $group.Id -All)
$exitDate = if ($mf.transition.exitDate) { [datetime]::Parse($mf.transition.exitDate) } else { $null }
if (-not $exitDate) { throw 'Manifest has no transition.exitDate. The exit date lives in the manifest, not the policy JSON.' }

Write-Log ("Transition exit run. Group '{0}' has {1} member(s). exitDate {2}." -f `
    $TRANSITION_GROUP, $members.Count, $exitDate.ToString('yyyy-MM-dd'))

# ---------------------------------------------------------------- state machine
# Finding 6B. Each recorded user carries state pending|removed|verified.
#
#   pending   attemptedAt written BEFORE the API call. If the call throws, the
#             entry stays pending and the next run RETRIES it. The previous
#             version wrote the id before the call and skipped any recorded id
#             on the next run, so a throw under $ErrorActionPreference='Stop'
#             left the user in the group, recorded as done, forever.
#   removed   removedAt written AFTER the call returns. Stamping it before the
#             call made the window between stamp and actual removal count as
#             post-removal evidence.
#   verified  a post-removal sign-in satisfied Test-VcioStandardCoverage.
function Save-Manifest([string]$What) {
    if ($PSCmdlet.ShouldProcess($Manifest, $What)) {
        $mf | ConvertTo-Json -Depth 12 | Set-Content -Path $Manifest -Encoding utf8
    }
}
# Emits the entries; every CALLER wraps in @(). The comma-return trick would
# make an empty result a one-element array containing an empty array.
function Get-Entries { @($mf.transition.verifiedRemovals) | Where-Object { $_ } }
function Set-Entries($Entries) { $mf.transition.verifiedRemovals = @($Entries) }
function Get-EntryState($Entry) {
    if ((Test-VcioHasProperty $Entry 'state') -and $Entry.state) { return [string]$Entry.state }
    # Migrate an entry written by an earlier version.
    if ((Test-VcioHasProperty $Entry 'verified') -and $Entry.verified) { return 'verified' }
    'removed'
}
function Set-EntryProperty($Entry, [string]$Name, $Value) {
    if ((Test-VcioHasProperty $Entry $Name)) { $Entry.$Name = $Value }
    else { $Entry | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force }
}

# Reconcile before doing anything else, against the membership just read.
$memberIds = @($members | ForEach-Object { $_.Id })
$entries = @(Get-Entries)
$reconciled = 0
foreach ($e in $entries) {
    if ((Get-EntryState $e) -ne 'pending') { continue }
    if ($e.id -in $memberIds) {
        Write-Log "  PENDING $($e.upn) is still a member — the previous removal did not take. Will retry."
        continue
    }
    # No longer a member, but we never recorded a completion. The removal did
    # happen; we just did not see it return. Stamp conservatively LATE — a
    # removedAt that is later than the truth only delays verification, while
    # one that is early would admit a pre-removal sign-in as evidence.
    Set-EntryProperty $e 'removedAt' ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))
    Set-EntryProperty $e 'state' 'removed'
    $reconciled++
    Write-Log "  RECONCILED $($e.upn) — no longer a member; recorded as removed at $($e.removedAt) (conservatively late)."
}
if ($reconciled) { Set-Entries $entries; Save-Manifest "reconcile $reconciled pending removal(s)" }

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
        $p = Resolve-Policy $n
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

    $entries = @(Get-Entries)
    $failed = 0
    foreach ($r in $roster) {
        $e = @($entries | Where-Object { $_.id -eq $r.Id }) | Select-Object -First 1
        # A 'removed' or 'verified' entry whose user is somehow a member again
        # is a re-add, not a completed removal; treat it as pending and retry.
        if ($e -and (Get-EntryState $e) -ne 'pending') {
            Write-Log "  RE-ADDED $($r.Upn) is a member again despite a recorded removal — removing again."
        }
        if (-not $e) {
            $e = [pscustomobject]@{ upn = $r.Upn; id = $r.Id; state = 'pending'; attemptedAt = $null; removedAt = $null }
            $entries = @($entries) + @($e)
        }
        Set-EntryProperty $e 'upn'         $r.Upn
        Set-EntryProperty $e 'state'       'pending'
        Set-EntryProperty $e 'attemptedAt' ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))
        Set-EntryProperty $e 'removedAt'   $null
        Set-Entries $entries
        # Durable BEFORE the call, so a crash leaves a pending entry to retry.
        Save-Manifest "mark $($r.Upn) pending at $($e.attemptedAt)"

        if ($PSCmdlet.ShouldProcess($r.Upn, "remove from $TRANSITION_GROUP")) {
            try {
                Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $r.Id -ErrorAction Stop
            } catch {
                # Stays pending. The next run re-reads membership and retries.
                $failed++
                Write-Log "  FAILED to remove $($r.Upn): $($_.Exception.Message). Left PENDING for the next run."
                continue
            }
        }
        # Only now, after the call returned.
        Set-EntryProperty $e 'removedAt' ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))
        Set-EntryProperty $e 'state'     'removed'
        Set-Entries $entries
        Save-Manifest "mark $($r.Upn) removed at $($e.removedAt)"
    }

    # groupEmptiedDate is written ONLY from a fresh membership read, never from
    # the roster we just walked. The roster says what we tried; only Graph says
    # what is actually in the group.
    $after = @(Get-MgGroupMember -GroupId $group.Id -All)
    if ($after.Count -eq 0) {
        $mf.transition.groupEmptiedDate = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        Save-Manifest 'record group-emptied timestamp'
        Write-Log 'Group confirmed empty by a fresh membership read. Transition policies stay ENABLED until every removed user is verified on the standard path.'
    } else {
        Write-Log "Group still has $($after.Count) member(s) after this run ($failed removal failure(s)). groupEmptiedDate NOT written. Re-run to retry the pending entries."
        exit 1
    }
    exit 0
}

# ---------------------------------------------------------------- phase 3+4
Write-Log 'Group is empty. Verifying post-removal sign-ins for every removed user.'
$removals = @($mf.transition.verifiedRemovals)
if (-not $removals.Count) {
    Write-Log 'No recorded removals to verify. Nothing to do.'
    exit 0
}

# Finding 6A — accepting notApplied as evidence of coverage rests on three
# facts. None of them can be taken from phase 1, which may have run days ago
# and against a tenant that has since drifted. All three are established HERE,
# from live state, at verification time.
#
#   1. each policy's filter is EXACTLY the framework's compliant-device
#      exclude filter (not merely a rule mentioning the attribute),
#   2. all four are 'enabled' right now,
#   3. the removed user is actually inside all four's scope.
#
# Re-read the policies rather than reuse the collection fetched at startup.
$policies = @(Get-MgIdentityConditionalAccessPolicy -All)

$standardPolicies = @()
$stateDefects = New-Object System.Collections.Generic.List[string]
foreach ($n in $STANDARD_POLICIES) {
    $p = Resolve-Policy $n
    if (-not $p) {
        $stateDefects.Add("$n is absent from the tenant.")
        continue
    }
    # Precondition 2 — state at VERIFICATION time.
    if ($p.State -ne 'enabled') {
        $stateDefects.Add("$($p.DisplayName) is '$($p.State)', not 'enabled'. A notApplied result from a policy that is not enforcing proves nothing.")
    }
    $devFilter = $null
    if ($p.Conditions.Devices) { $devFilter = $p.Conditions.Devices.DeviceFilter }
    $standardPolicies += [pscustomobject]@{
        Id                       = $p.Id
        DisplayName              = $p.DisplayName
        ClientAppTypes           = @($p.Conditions.ClientAppTypes)
        IncludePlatforms         = @(if ($p.Conditions.Platforms) { $p.Conditions.Platforms.IncludePlatforms } else { @() })
        ExcludeGroups            = @(if ($p.Conditions.Users) { $p.Conditions.Users.ExcludeGroups } else { @() })
        ExcludeUsers             = @(if ($p.Conditions.Users) { $p.Conditions.Users.ExcludeUsers }  else { @() })
        # Precondition 1 — exact semantics, not a name match.
        HasCompliantDeviceFilter = Test-VcioCompliantDeviceExcludeFilter -DeviceFilter $devFilter
        FilterMode               = $(if ($devFilter) { [string]$devFilter.Mode } else { '(none)' })
        FilterRule               = $(if ($devFilter) { [string]$devFilter.Rule } else { '(none)' })
    }
}
if ($standardPolicies.Count -ne $STANDARD_POLICIES.Count -or $stateDefects.Count) {
    Write-Log 'STOPPED. Standard-policy preconditions are not met; NO user is marked verified in this run:'
    foreach ($d in $stateDefects) { Write-Log "  - CONFIGURATION DEFECT: $d" }
    if ($standardPolicies.Count -ne $STANDARD_POLICIES.Count) {
        Write-Log "  - only $($standardPolicies.Count) of $($STANDARD_POLICIES.Count) standard policies resolved."
    }
    Write-Log 'Transition policies stay ENABLED. Fix the above and re-run.'
    exit 1
}

# Report the filter facts, because they decide what notApplied means and a
# silent change here would otherwise be invisible in the run log.
foreach ($sp in $standardPolicies) {
    if ($sp.HasCompliantDeviceFilter) {
        Write-Log "  $($sp.DisplayName): compliant-device exclude filter present — notApplied is acceptable for a compliant device."
    } else {
        Write-Log "  $($sp.DisplayName): no compliant-device exclude filter (mode '$($sp.FilterMode)', rule '$($sp.FilterRule)') — notApplied on it never passes."
    }
}

$unverified = New-Object System.Collections.Generic.List[string]
$configDefects = New-Object System.Collections.Generic.List[string]
foreach ($r in $removals) {
    $state = Get-EntryState $r
    if ($state -eq 'verified') { continue }
    if ($state -eq 'pending') {
        $unverified.Add("$($r.upn) — still PENDING removal; nothing to verify until the removal succeeds.")
        continue
    }
    # Tolerate a manifest written by an older version (removedDate, date-only).
    $stampText = if ((Test-VcioHasProperty $r 'removedAt') -and $r.removedAt) { $r.removedAt }
                 elseif ((Test-VcioHasProperty $r 'removedDate') -and $r.removedDate) { $r.removedDate }
                 else { $null }
    if (-not $stampText) {
        $unverified.Add("$($r.upn) — no removal timestamp recorded; cannot establish what counts as post-removal.")
        continue
    }
    $removedAt = [datetime]::Parse($stampText, $null,
        [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)

    # Precondition 3 — effective scope, BEFORE any sign-in is read. A user who
    # is not in SG-CA-Users, or who sits in one of the exclusion groups, gets
    # notApplied on every standard policy for a reason that has nothing to do
    # with their device. Verifying them would disable the transition policies
    # over a user no policy covers.
    $userGroups = @()
    try {
        $userGroups = @(Get-MgUserTransitiveMemberOf -UserId $r.id -All -ErrorAction Stop | ForEach-Object { $_.Id })
    } catch {
        $unverified.Add("$($r.upn) — could not read transitive group membership: $($_.Exception.Message)")
        continue
    }
    $scope = Test-VcioUserInStandardScope -PrincipalId $r.id -TransitiveGroupIds $userGroups `
        -UsersGroupId $usersGroup.Id -Policies $standardPolicies
    if (-not $scope.InScope) {
        $unverified.Add("$($r.upn) — OUT OF SCOPE: $($scope.Reason) Never verified, whatever the device state.")
        Write-Log "  OUT OF SCOPE $($r.upn) — $($scope.Reason)"
        continue
    }

    $since = $removedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $signIns = @()
    try {
        $signIns = @(Get-MgAuditLogSignIn -Filter "userId eq '$($r.id)' and createdDateTime ge $since" -All -ErrorAction Stop)
    } catch {
        $unverified.Add("$($r.upn) — could not read sign-in logs: $($_.Exception.Message)")
        continue
    }

    # Finding 6 — evidence is an ENFORCED result. 'notApplied' proves nothing,
    # and a reportOnly* result proves the policy evaluated but NOT that it was
    # enforcing, which is exactly the state this exit is supposed to leave
    # behind. The server-side filter is coarse (whole seconds), so
    # Test-VcioStandardCoverage re-filters strictly after the precise instant.
    #
    # Per policy, not per sign-in: the four cannot co-occur on one sign-in —
    # CA200 is mobileAppsAndDesktopClients while CA300/CA301 are browser, so
    # they are mutually exclusive on clientAppTypes. Requiring all four on a
    # single sign-in would never be satisfiable and the exit would never
    # complete. Each of the four must show an enforced result on SOME
    # post-removal sign-in.
    $cov = Test-VcioStandardCoverage -SignIns $signIns -Policies $standardPolicies `
        -RemovedAt $removedAt -PropagationMinutes $PropagationMinutes
    foreach ($d in $cov.ConfigurationDefects) { $configDefects.Add("$($r.upn): $d") }
    if ($cov.Verified) {
        Set-EntryProperty $r 'state' 'verified'
        Set-EntryProperty $r 'verified' $true
        Write-Log ("  VERIFIED $($r.upn) — $($cov.MatchingPairs) matching policy/sign-in pair(s) across " +
                   "$($cov.SignInsConsidered) sign-in(s) after the $($cov.PropagationMinutes)-minute margin, all passed.")
    } else {
        $detail = if ($cov.Failures.Count) { $cov.Failures -join ' | ' }
                  elseif ($cov.SignInsConsidered -eq 0) { "no sign-ins yet after the $($cov.PropagationMinutes)-minute propagation margin ($($cov.SignInsIgnoredInMargin) ignored inside it)" }
                  else { 'no standard policy matched any considered sign-in yet' }
        $unverified.Add("$($r.upn) — removed $stampText; $detail")
    }
}

Save-Manifest 'record verification results'

if ($configDefects.Count) {
    Write-Log "CONFIGURATION DEFECT — a standard policy is no longer enforcing:"
    $configDefects | ForEach-Object { Write-Log "  - $_" }
    Write-Log 'Phase 1 required all four to be enabled. Fix that before continuing the exit.'
}

if ($unverified.Count) {
    Write-Log "UNVERIFIED: $($unverified.Count) removed user(s) not yet confirmed on the standard path."
    $unverified | ForEach-Object { Write-Log "  - $_" }
    Write-Log 'Transition policies stay ENABLED. This is safe — the group is empty, so they affect nobody. Re-run after these users have signed in.'
    exit 0
}

Write-Log 'Every removed user verified on the standard path. Disabling the transition policies.'
foreach ($n in $TRANSITION_POLICIES) {
    $p = Resolve-Policy $n
    if (-not $p) { Write-Log "  $n absent — nothing to disable."; continue }
    if ($p.State -eq 'disabled') { Write-Log "  $n already disabled."; continue }
    if ($PSCmdlet.ShouldProcess($n, "set state to 'disabled'")) {
        Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $p.Id -State 'disabled'
        Write-Log "  $n -> disabled."
    }
}
Write-Log 'Transition exit complete.'
exit 0
