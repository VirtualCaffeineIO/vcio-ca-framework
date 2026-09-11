<#
.SYNOPSIS
    VCIO CA Framework — gate checks and prerequisite setup.
.DESCRIPTION
    B1. This script is a GATE, not a checklist. Every gate has a fixed list of
    checks that are FAIL at that gate; the script exits non-zero if any of them
    fails. Checks outside the gate's list still run and still print, but they
    report as INFO or WARN and never block. WARN is informational only and
    never appears in a gate's FAIL list — if something matters at a gate, it is
    a FAIL there, and if it does not, it does not get to half-block the run.

    Gates, in the order a deployment meets them:

      PreImport        Before the IntuneManagement import. Only what can pass
                       before the policies exist.
      SwitchReadiness  Tenants currently on Security Defaults. Runs while SD is
                       STILL ON — that is the point of splitting it from
                       PostSwitch (B5).
      PostSwitch       Immediately after SD is switched off and CA000/CA001/
                       CA002 are enabled, in the same working session.
      Ring1..Ring4     The enablement rings from Docs/runbook.md.

    Read-only except where -Fix is specified. -Fix never touches CA policies.
.NOTES
    Requires Microsoft.Graph.Authentication, Microsoft.Graph.Applications,
    Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups,
    Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance,
    Microsoft.Graph.Reports, Microsoft.Graph.Devices.CorporateManagement.
    Ring4 additionally needs Microsoft.Online.SharePoint.PowerShell and
    ExchangeOnlineManagement.
    Version 2026.9.1 — validate in a lab tenant before customer use.
.EXAMPLE
    .\Invoke-VcioCaPrereqs.ps1 -Gate PreImport -Fix
.EXAMPLE
    .\Invoke-VcioCaPrereqs.ps1 -Gate Ring1 -Manifest ..\Deploy\contoso\manifest.json
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('PreImport','SwitchReadiness','PostSwitch','Ring1','Ring2','Ring3','Ring4')]
    [string]$Gate = 'PreImport',
    [switch]$Fix,
    [string]$Manifest,
    [string]$BreakGlassGroupName = 'SG-CA-BreakGlass',
    # Registration-readiness exceptions, per the parameters worksheet. A user
    # listed here is a recorded exception, not a silent one.
    [string[]]$RegistrationExceptions = @()
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- gate model
# Each gate names the checks that are FAIL at that gate. Anything a check
# reports that is not in this list degrades to INFO.
$GateFailChecks = @{
    PreImport = @(
        'SecurityDefaults','IntuneEnrollSP','TAP'
    )
    # B5 — SD may still be enabled here. That is why 'SecurityDefaults' is
    # absent from this list and present in PostSwitch's.
    SwitchReadiness = @(
        'BreakGlassMembership','BreakGlassCloudOnly','BreakGlassGlobalAdminPermanent',
        'BreakGlassFido2','RegistrationReadiness','ServiceAccountCoverage',
        'FoundationPresentReportOnly','PreexistingEnforcedCA'
    )
    PostSwitch = @(
        'SecurityDefaults','FoundationEnabled','PilotCA002Applied','FoundationBlocksObserved'
    )
    # B2
    Ring1 = @(
        'SecurityDefaults','ServiceAccountCoverage','BreakGlassMembership',
        'BreakGlassCloudOnly','BreakGlassGlobalAdminPermanent','BreakGlassFido2',
        'RegistrationReadiness','SyncAccountInventory'
    )
    Ring2 = @(
        'SecurityDefaults','ServiceAccountCoverage','BreakGlassMembership',
        'BreakGlassCloudOnly','BreakGlassGlobalAdminPermanent','BreakGlassFido2',
        'RegistrationReadiness','SyncAccountInventory','PartnerSignInTest'
    )
    # B3
    Ring3 = @(
        'SecurityDefaults','ServiceAccountCoverage','BreakGlassMembership',
        'BreakGlassCloudOnly','BreakGlassGlobalAdminPermanent','BreakGlassFido2',
        'RegistrationReadiness','SyncAccountInventory','PartnerSignInTest',
        'PrivilegedPhishResistant','PrivilegedScopeClean'
    )
    # B4
    Ring4 = @(
        'SecurityDefaults','ServiceAccountCoverage','BreakGlassMembership',
        'BreakGlassCloudOnly','BreakGlassGlobalAdminPermanent','BreakGlassFido2',
        'RegistrationReadiness','SyncAccountInventory',
        'AppProtectionPresent','AppProtectionAssignment','AppProtectionFilter',
        'AppProtectionTargetedApps','SharePointAER','ExchangeAER'
    )
}
$gateList = $GateFailChecks[$Gate]

$script:Pass = 0; $script:Warn = 0; $script:Info = 0; $script:FailCount = 0
$script:Failures = New-Object System.Collections.Generic.List[string]

function Write-Check {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('PASS','WARN','FAIL')][string]$Result,
        [string]$Detail
    )
    # A check only fails the run if this gate says it matters. Elsewhere it is
    # information — never a WARN that pretends to be a gate.
    $effective = $Result
    if ($Result -eq 'FAIL' -and $Id -notin $gateList) { $effective = 'INFO' }
    if ($Result -eq 'WARN' -and $Id -in $gateList)    { $effective = 'WARN' }

    $color = @{PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='DarkGray'}[$effective]
    Write-Host ("[{0}] {1}" -f $effective.PadRight(4), $Name) -ForegroundColor $color
    if ($Detail) { Write-Host ("       {0}" -f $Detail) -ForegroundColor Gray }
    switch ($effective) {
        'PASS' { $script:Pass++ }
        'WARN' { $script:Warn++ }
        'INFO' { $script:Info++ }
        'FAIL' { $script:FailCount++; $script:Failures.Add($Name) }
    }
}

# ---------------------------------------------------------------- 0. modules
$requiredModules = @(
    'Microsoft.Graph.Authentication', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Users',
    'Microsoft.Graph.Applications', 'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.Governance', 'Microsoft.Graph.Reports',
    'Microsoft.Graph.Devices.CorporateManagement'
)
$missing = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
if ($missing) {
    Write-Host "Missing Graph SDK modules:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    $answer = Read-Host "Install to CurrentUser scope now? (Y/N)"
    if ($answer -match '^[Yy]') {
        Install-Module -Name $missing -Scope CurrentUser -Repository PSGallery -Force
    } else {
        Write-Host "Install manually, then re-run:" -ForegroundColor Red
        Write-Host ("  Install-Module {0} -Scope CurrentUser" -f ($missing -join ', '))
        exit 1
    }
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "Running on Windows PowerShell $($PSVersionTable.PSVersion). Works, but PowerShell 7 is recommended for the Graph SDK." -ForegroundColor Yellow
}

$manifestData = $null
if ($Manifest) {
    if (-not (Test-Path $Manifest)) { throw "Manifest not found: $Manifest" }
    $manifestData = Get-Content -Raw $Manifest | ConvertFrom-Json
}
$fencingMode = if ($manifestData -and $manifestData.fencingMode) { $manifestData.fencingMode } else { 'Shared' }

$scopes = @(
    'Policy.Read.All', 'Application.ReadWrite.All', 'Group.Read.All',
    'User.Read.All', 'UserAuthenticationMethod.Read.All',
    'Policy.ReadWrite.AuthenticationMethod',
    'RoleManagement.Read.Directory', 'RoleEligibilitySchedule.Read.Directory',
    'AuditLog.Read.All',
    'DeviceManagementApps.ReadWrite.All',
    'DeviceManagementConfiguration.ReadWrite.All'
)
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $scopes -NoWelcome
Write-Host ("Gate: {0}    Fencing mode: {1}" -f $Gate, $fencingMode) -ForegroundColor Cyan
Write-Host ""

$GLOBAL_ADMIN_ROLE = '62e90394-69f5-4237-9190-012177145e10'
# Verified 2026-09-11 against Microsoft Learn (permissions-reference).
$DIRSYNC_ROLE      = 'd29b2b05-8046-44ba-8758-1e26182fcf32'
# RFC 5737 documentation ranges. They match nothing real, so a named location
# still carrying one is an unfinished parameter, not a fence.
$RFC5737 = @('192.0.2.', '198.51.100.', '203.0.113.')

function Get-VcioGroup([string]$Name) {
    Get-MgGroup -Filter "displayName eq '$Name'" -ErrorAction SilentlyContinue | Select-Object -First 1
}
function Get-VcioPolicies {
    if (-not $script:caCache) {
        $script:caCache = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue)
    }
    $script:caCache
}
function Get-VcioPolicy([string]$Name) {
    Get-VcioPolicies | Where-Object { $_.DisplayName -eq $Name } | Select-Object -First 1
}

# ---------------------------------------------------------------- 1. security defaults
$sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
if ($sd.IsEnabled) {
    $d = if ($Gate -eq 'SwitchReadiness') {
        'Security defaults are ON — expected at this gate. Clear every FAIL below, then in ONE session: disable SD, set CA000/CA001/CA002 to On, re-run with -Gate PostSwitch.'
    } else {
        'Security defaults are ON. Disable before importing CA policies (Entra ID > Properties).'
    }
    Write-Check -Id 'SecurityDefaults' -Name 'Security defaults disabled' -Result 'FAIL' -Detail $d
} else {
    Write-Check -Id 'SecurityDefaults' -Name 'Security defaults disabled' -Result 'PASS'
}

# ---------------------------------------------------------------- 2. break-glass
$bgGroup = Get-VcioGroup $BreakGlassGroupName
$bgMembers = @()
if (-not $bgGroup) {
    Write-Check -Id 'BreakGlassMembership' -Name 'Break-glass group exists' -Result 'FAIL' `
        -Detail "Group '$BreakGlassGroupName' not found. IntuneManagement creates it during import."
} else {
    $bgMembers = @(Get-MgGroupMember -GroupId $bgGroup.Id -All)
    if ($bgMembers.Count -lt 2) {
        Write-Check -Id 'BreakGlassMembership' -Name 'Break-glass membership (>= 2 accounts)' -Result 'FAIL' `
            -Detail "Found $($bgMembers.Count). Framework requires two cloud-only break-glass accounts."
    } else {
        Write-Check -Id 'BreakGlassMembership' -Name 'Break-glass membership (>= 2 accounts)' -Result 'PASS' -Detail "$($bgMembers.Count) members"
    }

    # B2 — the Global Administrator assignment must be PERMANENT, and it must be
    # read through role management. Get-MgDirectoryRoleMember shows the role's
    # current members and does not distinguish an active PIM activation from a
    # standing assignment: a break-glass account whose GA is merely ELIGIBLE
    # cannot activate it during the outage that break-glass exists for.
    $gaAssignments = @()
    $gaEligible = @()
    try {
        $gaAssignments = @(Get-MgRoleManagementDirectoryRoleAssignment `
            -Filter "roleDefinitionId eq '$GLOBAL_ADMIN_ROLE'" -All -ErrorAction Stop)
        $gaEligible = @(Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
            -Filter "roleDefinitionId eq '$GLOBAL_ADMIN_ROLE'" -All -ErrorAction SilentlyContinue)
    } catch {
        Write-Check -Id 'BreakGlassGlobalAdminPermanent' -Name 'Break-glass permanent Global Administrator' -Result 'FAIL' `
            -Detail "Could not read role assignments: $($_.Exception.Message). Needs RoleManagement.Read.Directory."
    }

    foreach ($m in $bgMembers) {
        $u = Get-MgUser -UserId $m.Id -Property userPrincipalName,onPremisesSyncEnabled,accountEnabled
        $upn = $u.UserPrincipalName
        if ($u.OnPremisesSyncEnabled) {
            Write-Check -Id 'BreakGlassCloudOnly' -Name "Break-glass cloud-only: $upn" -Result 'FAIL' -Detail 'Account is AD-synced. Break-glass must be cloud-only.'
        } elseif (-not $u.AccountEnabled) {
            Write-Check -Id 'BreakGlassCloudOnly' -Name "Break-glass enabled: $upn" -Result 'FAIL' -Detail 'Account is disabled.'
        } else {
            Write-Check -Id 'BreakGlassCloudOnly' -Name "Break-glass cloud-only + enabled: $upn" -Result 'PASS'
        }

        if ($gaAssignments.Count) {
            $hasPermanent = @($gaAssignments | Where-Object { $_.PrincipalId -eq $m.Id }).Count -gt 0
            $onlyEligible = @($gaEligible | Where-Object { $_.PrincipalId -eq $m.Id }).Count -gt 0
            if ($hasPermanent) {
                Write-Check -Id 'BreakGlassGlobalAdminPermanent' -Name "Break-glass permanent Global Administrator: $upn" -Result 'PASS'
            } elseif ($onlyEligible) {
                Write-Check -Id 'BreakGlassGlobalAdminPermanent' -Name "Break-glass permanent Global Administrator: $upn" -Result 'FAIL' `
                    -Detail 'Global Administrator is PIM-ELIGIBLE, not permanent. Activation needs the very sign-in path that is broken when break-glass is used. Make it a standing assignment.'
            } else {
                Write-Check -Id 'BreakGlassGlobalAdminPermanent' -Name "Break-glass permanent Global Administrator: $upn" -Result 'FAIL' `
                    -Detail 'No Global Administrator assignment found for this account.'
            }
        }

        $fido = Get-MgUserAuthenticationFido2Method -UserId $m.Id -ErrorAction SilentlyContinue
        if ($fido) {
            Write-Check -Id 'BreakGlassFido2' -Name "Break-glass FIDO2 registered: $upn" -Result 'PASS'
        } else {
            Write-Check -Id 'BreakGlassFido2' -Name "Break-glass FIDO2 registered: $upn" -Result 'FAIL' `
                -Detail 'No FIDO2 credential. Framework standard is FIDO2-credentialed break-glass.'
        }
    }
}

# ---------------------------------------------------------------- 3. registration readiness
# B2 — a tenant cannot enforce CA002 over users who have no usable MFA method.
# Either that count is zero, or every remaining user is a recorded exception in
# the parameters worksheet (passed in with -RegistrationExceptions).
try {
    $regDetails = @(Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop)
    $noMethod = @($regDetails | Where-Object { -not $_.IsMfaCapable })
    $usersGroup = Get-VcioGroup 'SG-CA-Users'
    if ($usersGroup) {
        $memberIds = @(Get-MgGroupMember -GroupId $usersGroup.Id -All | ForEach-Object { $_.Id })
        $noMethod = @($noMethod | Where-Object { $_.Id -in $memberIds })
    }
    $unexcepted = @($noMethod | Where-Object { $_.UserPrincipalName -notin $RegistrationExceptions })
    if ($unexcepted.Count -eq 0) {
        Write-Check -Id 'RegistrationReadiness' -Name 'Registration readiness (every member user MFA-capable)' -Result 'PASS' `
            -Detail "$($noMethod.Count) user(s) without a usable method, all listed as worksheet exceptions."
    } else {
        Write-Check -Id 'RegistrationReadiness' -Name 'Registration readiness (every member user MFA-capable)' -Result 'FAIL' `
            -Detail ("$($unexcepted.Count) enabled member user(s) have no usable MFA method and are not recorded exceptions: " +
                     (($unexcepted | Select-Object -First 15 | ForEach-Object { $_.UserPrincipalName }) -join ', '))
    }
} catch {
    Write-Check -Id 'RegistrationReadiness' -Name 'Registration readiness' -Result 'FAIL' `
        -Detail "Could not read registration details: $($_.Exception.Message)"
}

# ---------------------------------------------------------------- 4. sync accounts (B2)
# Every holder of Directory Synchronization Accounts is inventoried by name, and
# none of them is in SG-CA-ServiceAccounts. The sync account is exempted from
# CA002 by ROLE (A4). Parking it in the service-account group instead would put
# it under the shared IP fence, whose location is the application servers'
# egress, not the Connect server's.
$saGroup = Get-VcioGroup 'SG-CA-ServiceAccounts'
$saMemberIds = @()
if ($saGroup) { $saMemberIds = @(Get-MgGroupMember -GroupId $saGroup.Id -All | ForEach-Object { $_.Id }) }
try {
    $syncHolders = @(Get-MgRoleManagementDirectoryRoleAssignment `
        -Filter "roleDefinitionId eq '$DIRSYNC_ROLE'" -All -ErrorAction Stop)
    $names = foreach ($h in $syncHolders) {
        $p = Get-MgUser -UserId $h.PrincipalId -Property userPrincipalName -ErrorAction SilentlyContinue
        if ($p) { $p.UserPrincipalName } else { "(service principal) $($h.PrincipalId)" }
    }
    $inGroup = @($syncHolders | Where-Object { $_.PrincipalId -in $saMemberIds })
    if ($inGroup.Count) {
        $bad = foreach ($h in $inGroup) {
            (Get-MgUser -UserId $h.PrincipalId -Property userPrincipalName -ErrorAction SilentlyContinue).UserPrincipalName
        }
        Write-Check -Id 'SyncAccountInventory' -Name 'Sync accounts inventoried and out of SG-CA-ServiceAccounts' -Result 'FAIL' `
            -Detail ("These Directory Synchronization Accounts holders are in SG-CA-ServiceAccounts and must be removed: " + ($bad -join ', ') +
                     ". CA002 already exempts them by role; optional fencing is CA500-VCIO-ServiceAccounts-IPFence-DirSync on SG-CA-SA-DirSync.")
    } else {
        Write-Check -Id 'SyncAccountInventory' -Name 'Sync accounts inventoried and out of SG-CA-ServiceAccounts' -Result 'PASS' `
            -Detail ("Holders: " + (($names | Sort-Object) -join ', '))
    }
} catch {
    Write-Check -Id 'SyncAccountInventory' -Name 'Sync accounts inventoried' -Result 'FAIL' `
        -Detail "Could not enumerate Directory Synchronization Accounts holders: $($_.Exception.Message)"
}

# ---------------------------------------------------------------- 5. B3a service-account coverage
# Checked at SwitchReadiness, Ring 1 and every later gate. Structure first
# (is a fence configured and enforced for this account?), then evidence from the
# last 30 days of sign-ins (does it actually apply, and does anything succeed
# from outside it?). An account with no sign-ins in the window is UNVERIFIED —
# reported by name, and the gate does not pass on UNVERIFIED, because "no data"
# is not "no problem".
function Test-ServiceAccountCoverage {
    if (-not $saGroup) {
        Write-Check -Id 'ServiceAccountCoverage' -Name 'B3a service-account coverage' -Result 'FAIL' `
            -Detail 'SG-CA-ServiceAccounts not found.'
        return
    }
    if (-not $saMemberIds.Count) {
        Write-Check -Id 'ServiceAccountCoverage' -Name 'B3a service-account coverage' -Result 'PASS' `
            -Detail 'SG-CA-ServiceAccounts is empty — nothing to fence.'
        return
    }

    $sharedFence = Get-VcioPolicy 'CA500-VCIO-ServiceAccounts-IPFence'
    $sharedRestrict = Get-VcioPolicy 'CA501-VCIO-ServiceAccounts-RestrictApps'

    if ($fencingMode -eq 'Shared') {
        if (-not $sharedFence -or $sharedFence.State -ne 'enabled') {
            Write-Check -Id 'ServiceAccountCoverage' -Name 'B3a: shared CA500 enforced' -Result 'FAIL' `
                -Detail "Mode Shared requires CA500-VCIO-ServiceAccounts-IPFence state 'enabled'; it is '$(if($sharedFence){$sharedFence.State}else{'absent'})'."
        } else {
            Write-Check -Id 'ServiceAccountCoverage' -Name 'B3a: shared CA500 enforced' -Result 'PASS'
        }
    } else {
        foreach ($p in @($sharedFence, $sharedRestrict)) {
            if ($p -and $p.State -ne 'disabled') {
                Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: shared $($p.DisplayName) disabled" -Result 'FAIL' `
                    -Detail "Mode Per-System requires this to be 'disabled', not '$($p.State)'. Report-only still evaluates and would impose the shared location on a per-system account."
            } elseif ($p) {
                Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: shared $($p.DisplayName) disabled" -Result 'PASS'
            }
        }
    }

    # Named locations in scope must not still hold a documentation range.
    $allLocations = @(Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction SilentlyContinue)
    foreach ($loc in $allLocations) {
        if ($loc.DisplayName -notlike 'VCIO-NL-SA-*' -and $loc.DisplayName -ne 'VCIO-NL-ServiceAccountIPs') { continue }
        $ranges = @($loc.AdditionalProperties.ipRanges | ForEach-Object { $_.cidrAddress })
        $placeholder = @($ranges | Where-Object { $r = $_; ($RFC5737 | Where-Object { $r -like "$_*" }) })
        if ($placeholder.Count) {
            Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: named location $($loc.DisplayName)" -Result 'FAIL' `
                -Detail "Still contains RFC 5737 documentation range(s): $($placeholder -join ', '). These match nothing real — the fence is not a fence."
        }
    }

    $since = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
    foreach ($id in $saMemberIds) {
        $u = Get-MgUser -UserId $id -Property userPrincipalName -ErrorAction SilentlyContinue
        $upn = if ($u) { $u.UserPrincipalName } else { $id }

        # Which CA500 governs this account?
        $governing = $null
        if ($fencingMode -eq 'Shared') {
            $governing = $sharedFence
        } else {
            $perSystem = @(Get-MgUserMemberOf -UserId $id -All -ErrorAction SilentlyContinue |
                Where-Object { $_.AdditionalProperties.displayName -like 'SG-CA-SA-*' })
            if ($perSystem.Count -ne 1) {
                Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: $upn per-system group" -Result 'FAIL' `
                    -Detail "Must be in exactly one SG-CA-SA-* group; found $($perSystem.Count)."
                continue
            }
            $system = ($perSystem[0].AdditionalProperties.displayName) -replace '^SG-CA-SA-',''
            $governing = Get-VcioPolicy "CA500-VCIO-ServiceAccounts-IPFence-$system"
            if (-not $governing -or $governing.State -ne 'enabled') {
                Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: $upn per-system fence" -Result 'FAIL' `
                    -Detail "CA500-VCIO-ServiceAccounts-IPFence-$system is '$(if($governing){$governing.State}else{'absent'})', not enabled."
                continue
            }
        }
        if (-not $governing -or $governing.State -ne 'enabled') {
            Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: $upn fenced" -Result 'FAIL' `
                -Detail 'Account is in the CA002 exemption group with no enforced fence. It is exempt from MFA and fenced by nothing.'
            continue
        }

        $signIns = @()
        try {
            $signIns = @(Get-MgAuditLogSignIn -Filter "userId eq '$id' and createdDateTime ge $since" -All -ErrorAction Stop)
        } catch {
            Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: $upn sign-in evidence" -Result 'FAIL' `
                -Detail "Could not read sign-in logs: $($_.Exception.Message)"
            continue
        }
        if (-not $signIns.Count) {
            Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: $upn sign-in evidence" -Result 'FAIL' `
                -Detail 'UNVERIFIED — no sign-ins in the last 30 days, so nothing proves the fence applies to this account. UNVERIFIED does not pass the gate.'
            continue
        }

        # (i) the governing fence must actually appear in the applied-policies list
        $applied = @($signIns | Where-Object {
            @($_.AppliedConditionalAccessPolicies | Where-Object {
                $_.Id -eq $governing.Id -and $_.Result -ne 'notApplied'
            }).Count -gt 0
        })
        # (ii) nothing may SUCCEED from outside the governing location
        $outsideSuccess = @($signIns | Where-Object {
            $_.Status.ErrorCode -eq 0 -and
            @($_.AppliedConditionalAccessPolicies | Where-Object {
                $_.Id -eq $governing.Id -and $_.Result -eq 'notApplied'
            }).Count -gt 0
        })
        $blockedOutside = @($signIns | Where-Object { $_.Status.ErrorCode -ne 0 }).Count

        if (-not $applied.Count) {
            Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: $upn fence applies" -Result 'FAIL' `
                -Detail "$($governing.DisplayName) never appears in this account's applied-policies list over $($signIns.Count) sign-in(s). The fence is configured but does not reach the account."
        } elseif ($outsideSuccess.Count) {
            Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: $upn fence holds" -Result 'FAIL' `
                -Detail "$($outsideSuccess.Count) successful sign-in(s) from outside the governing location."
        } else {
            Write-Check -Id 'ServiceAccountCoverage' -Name "B3a: $upn fenced and verified" -Result 'PASS' `
                -Detail "$($applied.Count) sign-in(s) with the fence applied; no success from outside. $blockedOutside blocked attempt(s) — desirable, reported not failed."
        }
    }
}
Test-ServiceAccountCoverage

# ---------------------------------------------------------------- 6. B5 switch checks
if ($Gate -eq 'SwitchReadiness') {
    foreach ($n in @('CA000-VCIO-Global-BlockLegacyAuth','CA001-VCIO-Global-BlockDeviceCodeFlow','CA002-VCIO-Global-MFA')) {
        $p = Get-VcioPolicy $n
        if (-not $p) {
            Write-Check -Id 'FoundationPresentReportOnly' -Name "$n present" -Result 'FAIL' -Detail 'Not found in tenant — import first.'
        } elseif ($p.State -ne 'enabledForReportingButNotEnforced') {
            Write-Check -Id 'FoundationPresentReportOnly' -Name "$n report-only" -Result 'FAIL' -Detail "State is '$($p.State)'; expected report-only before the switch."
        } else {
            Write-Check -Id 'FoundationPresentReportOnly' -Name "$n present and report-only" -Result 'PASS'
        }
    }
    # Any pre-existing enforced CA policy must be accounted for before SD comes
    # off, or the tenant switches into an overlap nobody mapped.
    $foreign = @(Get-VcioPolicies | Where-Object { $_.State -eq 'enabled' -and $_.DisplayName -notmatch '-VCIO-' })
    if (-not $foreign.Count) {
        Write-Check -Id 'PreexistingEnforcedCA' -Name 'Pre-existing enforced CA policies mapped' -Result 'PASS' -Detail 'None found.'
    } else {
        $mapped = @()
        if ($manifestData -and $manifestData.preexistingPolicies) {
            $mapped = @($manifestData.preexistingPolicies | ForEach-Object { $_.displayName })
        }
        $unmapped = @($foreign | Where-Object { $_.DisplayName -notin $mapped })
        if ($unmapped.Count) {
            Write-Check -Id 'PreexistingEnforcedCA' -Name 'Pre-existing enforced CA policies mapped' -Result 'FAIL' `
                -Detail ("Enforced and not listed in the manifest with a VCIO equivalent: " +
                         (($unmapped | ForEach-Object { $_.DisplayName }) -join ', ') +
                         ". Leave each On until the ring carrying its equivalent enforces, then report-only for one cycle, then delete.")
        } else {
            Write-Check -Id 'PreexistingEnforcedCA' -Name 'Pre-existing enforced CA policies mapped' -Result 'PASS' -Detail "$($foreign.Count) mapped in the manifest."
        }
    }
}

if ($Gate -eq 'PostSwitch') {
    foreach ($n in @('CA000-VCIO-Global-BlockLegacyAuth','CA001-VCIO-Global-BlockDeviceCodeFlow','CA002-VCIO-Global-MFA')) {
        $p = Get-VcioPolicy $n
        if ($p -and $p.State -eq 'enabled') {
            Write-Check -Id 'FoundationEnabled' -Name "$n enabled" -Result 'PASS'
        } else {
            Write-Check -Id 'FoundationEnabled' -Name "$n enabled" -Result 'FAIL' `
                -Detail "State is '$(if($p){$p.State}else{'absent'})'. SD is off; until these enforce the tenant has no legacy-auth block, no device-code block and no MFA."
        }
    }
    $hourAgo = (Get-Date).AddHours(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $ca002 = Get-VcioPolicy 'CA002-VCIO-Global-MFA'
    try {
        $recent = @(Get-MgAuditLogSignIn -Filter "createdDateTime ge $hourAgo" -All -ErrorAction Stop)
        $pilot = @($recent | Where-Object {
            $_.Status.ErrorCode -eq 0 -and $ca002 -and
            @($_.AppliedConditionalAccessPolicies | Where-Object { $_.Id -eq $ca002.Id -and $_.Result -eq 'success' }).Count -gt 0
        })
        if ($pilot.Count) {
            Write-Check -Id 'PilotCA002Applied' -Name 'CA002 applied with success for a pilot user in the last hour' -Result 'PASS' `
                -Detail "$($pilot.Count) sign-in(s), e.g. $($pilot[0].UserPrincipalName)."
        } else {
            Write-Check -Id 'PilotCA002Applied' -Name 'CA002 applied with success for a pilot user in the last hour' -Result 'FAIL' `
                -Detail 'No sign-in in the last hour shows CA002 applied with result success. Have a pilot user sign in, then re-run.'
        }
        $blockIds = @('CA000-VCIO-Global-BlockLegacyAuth','CA001-VCIO-Global-BlockDeviceCodeFlow') |
            ForEach-Object { (Get-VcioPolicy $_).Id } | Where-Object { $_ }
        $attempts = @($recent | Where-Object {
            @($_.AppliedConditionalAccessPolicies | Where-Object { $_.Id -in $blockIds -and $_.Result -ne 'notApplied' }).Count -gt 0
        })
        $failures = @($attempts | Where-Object {
            @($_.AppliedConditionalAccessPolicies | Where-Object { $_.Id -in $blockIds -and $_.Result -eq 'failure' }).Count -gt 0
        })
        if (-not $attempts.Count) {
            Write-Check -Id 'FoundationBlocksObserved' -Name 'Legacy-auth / device-code attempts in the last hour' -Result 'PASS' `
                -Detail 'None occurred — acceptable per the gate.'
        } elseif ($failures.Count -eq $attempts.Count) {
            Write-Check -Id 'FoundationBlocksObserved' -Name 'Legacy-auth / device-code attempts blocked' -Result 'PASS' `
                -Detail "$($failures.Count) attempt(s), all showing CA000/CA001 failure."
        } else {
            Write-Check -Id 'FoundationBlocksObserved' -Name 'Legacy-auth / device-code attempts blocked' -Result 'FAIL' `
                -Detail "$($attempts.Count) attempt(s) in scope but only $($failures.Count) show a CA000/CA001 failure result."
        }
    } catch {
        Write-Check -Id 'PilotCA002Applied' -Name 'PostSwitch sign-in evidence' -Result 'FAIL' -Detail "Could not read sign-in logs: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------- 7. Ring 2/3 partner test (D5)
if ($Gate -in @('Ring2','Ring3')) {
    $attest = $null
    if ($manifestData -and $manifestData.partnerAccessTests) {
        $attest = $manifestData.partnerAccessTests.$Gate
    }
    if ($attest -and $attest.verifiedDate) {
        Write-Check -Id 'PartnerSignInTest' -Name "GDAP partner sign-in test ($Gate)" -Result 'PASS' `
            -Detail "Recorded $($attest.verifiedDate): $($attest.result)"
    } else {
        Write-Check -Id 'PartnerSignInTest' -Name "GDAP partner sign-in test ($Gate)" -Result 'FAIL' `
            -Detail "No recorded result in manifest.partnerAccessTests.$Gate. This is a live test a script cannot perform — run it per Docs/partner-access.md and record the outcome."
    }
}

# ---------------------------------------------------------------- 8. Ring 3 privileged (B3)
if ($Gate -eq 'Ring3') {
    $privGroup = Get-VcioGroup 'SG-CA-Privileged'
    $principals = @{}
    # The same 23 built-in roles the 100s policies target (generate.py
    # ADMIN_ROLES), plus SG-CA-Privileged for everything role targeting
    # cannot see. Keep in step with generate.py: this is a hardcoded copy.
    $adminRoleIds = @(
        '62e90394-69f5-4237-9190-012177145e10','194ae4cb-b126-40b2-bd5b-6091b380977d',
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c','29232cdf-9323-42fd-ade2-1d097af3e4de',
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9','729827e3-9c14-49f7-bb1b-9608f156bbb8',
        'b0f54661-2d74-4c50-afa3-1ec803f12efe','fe930be7-5e62-47db-91af-98c3a49a38b1',
        'c4e39bd9-1100-46d3-8c65-fb160da0071f','9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
        '158c047a-c907-4556-b7ef-446551a6b5f7','966707d0-3269-4727-9be2-8c3a10f19b9d',
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13','e8611ab8-c189-46e8-94e1-60213ab1f814',
        'f2ef992c-3afb-46b9-b7cf-a126ee74c451','3a2c62db-5318-420d-8d74-23affee5d9d5',
        'd2562ede-74db-457e-a7b6-544e236ebb61','db506228-d27e-4b7d-95e5-295956d6615f',
        '6b942400-691f-4bf0-9d12-d8a254a2baf5','b6a27b2b-f905-4b2e-81b5-0d90e0ef1fdb',
        '1707125e-0aa2-4d4d-8655-a7c786c76a25',
        '69091246-20e8-4a56-aa4d-066075b2a7a8','11451d60-acb2-45eb-a7d6-43d0f0125c13'
    )
    foreach ($rid in $adminRoleIds) {
        foreach ($a in @(Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$rid'" -All -ErrorAction SilentlyContinue)) {
            $principals[$a.PrincipalId] = $true
        }
    }
    if ($privGroup) {
        foreach ($m in @(Get-MgGroupMember -GroupId $privGroup.Id -All)) { $principals[$m.Id] = $true }
    }
    $noPr = @()
    foreach ($pid in $principals.Keys) {
        $methods = @()
        try { $methods = @(Get-MgUserAuthenticationMethod -UserId $pid -ErrorAction Stop) } catch { continue }
        $types = @($methods | ForEach-Object { $_.AdditionalProperties.'@odata.type' })
        $isPr = @($types | Where-Object {
            $_ -in @('#microsoft.graph.fido2AuthenticationMethod',
                     '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
                     '#microsoft.graph.x509CertificateAuthenticationMethod')
        }).Count -gt 0
        if (-not $isPr) {
            $u = Get-MgUser -UserId $pid -Property userPrincipalName -ErrorAction SilentlyContinue
            $noPr += if ($u) { $u.UserPrincipalName } else { $pid }
        }
    }
    if ($noPr.Count) {
        Write-Check -Id 'PrivilegedPhishResistant' -Name 'Every privileged holder has a phishing-resistant method' -Result 'FAIL' `
            -Detail ("Missing for: " + ($noPr -join ', '))
    } else {
        Write-Check -Id 'PrivilegedPhishResistant' -Name 'Every privileged holder has a phishing-resistant method' -Result 'PASS' `
            -Detail "$($principals.Count) principal(s) checked (ADMIN_ROLES + SG-CA-Privileged)."
    }

    # E1's last run must be clean: no uncovered privileged user, no INCOMPLETE scope.
    $e1 = if ($manifestData) { $manifestData.privilegedScopeLastRun } else { $null }
    if ($e1 -and $e1.clean -eq $true -and $e1.date) {
        Write-Check -Id 'PrivilegedScopeClean' -Name 'Compare-VcioPrivilegedScope last run clean (E1)' -Result 'PASS' -Detail "Run $($e1.date)."
    } else {
        Write-Check -Id 'PrivilegedScopeClean' -Name 'Compare-VcioPrivilegedScope last run clean (E1)' -Result 'FAIL' `
            -Detail 'No clean run recorded in manifest.privilegedScopeLastRun. Run Tools/Compare-VcioPrivilegedScope.ps1 -Manifest <path>; an INCOMPLETE scope is not clean.'
    }
}

# ---------------------------------------------------------------- 9. App Protection (+ B4 at Ring 4)
$existingFilters = @()
try {
    $existingFilters = @((Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters?$top=100').value)
} catch { }
$expectedFilterRule = 'app.deviceManagementType -eq "Unmanaged"'
foreach ($flt in @(
    @{ Name = 'VCIO-FLT-iOS-UnmanagedDevices';     Platform = 'iOSMobileApplicationManagement' },
    @{ Name = 'VCIO-FLT-Android-UnmanagedDevices'; Platform = 'androidMobileApplicationManagement' }
)) {
    $found = $existingFilters | Where-Object { $_.displayName -eq $flt.Name } | Select-Object -First 1
    if ($found) {
        Write-Check -Id 'AppProtectionFilter' -Name "Assignment filter: $($flt.Name)" -Result 'PASS'
    } elseif ($Fix) {
        try {
            Invoke-MgGraphRequest -Method POST `
                -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters' `
                -Body (@{
                    displayName = $flt.Name
                    description = 'VCIO CA Framework: limits App Protection assignment to unmanaged devices.'
                    platform = $flt.Platform
                    rule = $expectedFilterRule
                    assignmentFilterManagementType = 'apps'
                } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
            Write-Check -Id 'AppProtectionFilter' -Name "Assignment filter: $($flt.Name)" -Result 'PASS' -Detail 'Created via Graph.'
        } catch {
            Write-Check -Id 'AppProtectionFilter' -Name "Assignment filter: $($flt.Name)" -Result 'FAIL' -Detail "Graph creation failed: $($_.Exception.Message)"
        }
    } else {
        Write-Check -Id 'AppProtectionFilter' -Name "Assignment filter: $($flt.Name)" -Result 'FAIL' -Detail 'Missing. Re-run with -Fix to create.'
    }
}

$appPolicies = @(Get-MgDeviceAppManagementManagedAppPolicy -All -ErrorAction SilentlyContinue)
$vcioAppPolicies = @(
    @{ Name = 'VCIO-APP-iOS-Baseline';          Endpoint = 'iosManagedAppProtections';     Blocking = 'CA202'; Filter = 'VCIO-FLT-iOS-UnmanagedDevices' },
    @{ Name = 'VCIO-APP-Android-Baseline';      Endpoint = 'androidManagedAppProtections'; Blocking = 'CA202'; Filter = 'VCIO-FLT-Android-UnmanagedDevices' },
    @{ Name = 'VCIO-APP-Windows-Edge-Baseline'; Endpoint = 'windowsManagedAppProtections'; Blocking = 'CA301'; Filter = $null }
)
$usersGroupForApp = Get-VcioGroup 'SG-CA-Users'
$usersGroupMembers = @()
if ($usersGroupForApp) { $usersGroupMembers = @(Get-MgGroupMember -GroupId $usersGroupForApp.Id -All | ForEach-Object { $_.Id }) }

foreach ($ap in $vcioAppPolicies) {
    $existing = $appPolicies | Where-Object { $_.DisplayName -eq $ap.Name } | Select-Object -First 1
    if (-not $existing) {
        if (-not $Fix) {
            Write-Check -Id 'AppProtectionPresent' -Name "App Protection: $($ap.Name)" -Result 'FAIL' -Detail "Missing. Re-run with -Fix to create via Graph. Required before $($ap.Blocking)."
            continue
        }
        try {
            $jsonPath = Join-Path (Split-Path $PSScriptRoot -Parent) "Config/AppProtection/$($ap.Name).json"
            if (-not (Test-Path $jsonPath)) {
                Write-Check -Id 'AppProtectionPresent' -Name "App Protection: $($ap.Name)" -Result 'FAIL' -Detail "JSON not found at $jsonPath."
                continue
            }
            $body = Get-Content -Raw $jsonPath | ConvertFrom-Json
            $apps = @($body.apps | ForEach-Object {
                @{ mobileAppIdentifier = @{
                    '@odata.type' = $_.mobileAppIdentifier.'@odata.type'
                } + ($_.mobileAppIdentifier.PSObject.Properties |
                     Where-Object Name -notmatch '^@' |
                     ForEach-Object -Begin { $h=@{} } -Process { $h[$_.Name]=$_.Value } -End { $h }) }
            })
            foreach ($prop in @('id','createdDateTime','lastModifiedDateTime','version','apps','isAssigned','roleScopeTagIds','deployedAppCount')) {
                $body.PSObject.Properties.Remove($prop)
            }
            $created = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$($ap.Endpoint)" `
                -Body ($body | ConvertTo-Json -Depth 10) -ContentType 'application/json'
            Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$($ap.Endpoint)('$($created.id)')/targetApps" `
                -Body (@{ apps = $apps } | ConvertTo-Json -Depth 10) -ContentType 'application/json'
            Write-Check -Id 'AppProtectionPresent' -Name "App Protection: $($ap.Name)" -Result 'PASS' -Detail "Created via Graph. Assign before its ring enables."
            $existing = $created
        } catch {
            Write-Check -Id 'AppProtectionPresent' -Name "App Protection: $($ap.Name)" -Result 'FAIL' -Detail "Graph creation failed: $($_.Exception.Message)"
            continue
        }
    } else {
        Write-Check -Id 'AppProtectionPresent' -Name "App Protection: $($ap.Name)" -Result 'PASS'
    }

    if ($Gate -ne 'Ring4') { continue }

    # B4 — read the assignment COLLECTION. isAssigned is a boolean that says
    # "something is assigned somewhere"; it cannot tell you the assignment
    # reaches SG-CA-Users, or that an exclusion assignment takes them back out.
    $policyId = if ($existing.Id) { $existing.Id } else { $existing.id }
    $assignments = @()
    try {
        $assignments = @((Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$($ap.Endpoint)('$policyId')/assignments").value)
    } catch {
        Write-Check -Id 'AppProtectionAssignment' -Name "$($ap.Name) assignments readable" -Result 'FAIL' -Detail $_.Exception.Message
        continue
    }
    $includes = @($assignments | Where-Object { $_.target.'@odata.type' -notlike '*exclusionGroupAssignmentTarget' })
    $excludes = @($assignments | Where-Object { $_.target.'@odata.type' -like '*exclusionGroupAssignmentTarget' })
    $allUsers = @($includes | Where-Object { $_.target.'@odata.type' -like '*allLicensedUsersAssignmentTarget' })

    if (-not $allUsers.Count) {
        Write-Check -Id 'AppProtectionAssignment' -Name "$($ap.Name) assigned to All Users" -Result 'FAIL' `
            -Detail 'No allLicensedUsersAssignmentTarget in the assignment collection.'
    } else {
        # An exclusion assignment that removes any member of SG-CA-Users takes
        # that user out of APP coverage while CA202 still demands it.
        $removed = @()
        foreach ($ex in $excludes) {
            $gid = $ex.target.groupId
            if (-not $gid) { continue }
            $exMembers = @(Get-MgGroupMember -GroupId $gid -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
            $overlap = @($exMembers | Where-Object { $_ -in $usersGroupMembers })
            if ($overlap.Count) { $removed += "$gid ($($overlap.Count) SG-CA-Users member(s))" }
        }
        if ($removed.Count) {
            Write-Check -Id 'AppProtectionAssignment' -Name "$($ap.Name) exclusion assignments" -Result 'FAIL' `
                -Detail ("Exclusion assignment(s) remove SG-CA-Users members from APP coverage: " + ($removed -join '; '))
        } else {
            Write-Check -Id 'AppProtectionAssignment' -Name "$($ap.Name) assigned to All Users, no SG-CA-Users exclusions" -Result 'PASS'
        }

        if ($ap.Filter) {
            # Compare the filter's RULE TEXT, not its name. A filter renamed to
            # look right whose rule was edited is the failure this catches.
            $fid = $allUsers[0].target.deviceAndAppManagementAssignmentFilterId
            $ftype = $allUsers[0].target.deviceAndAppManagementAssignmentFilterType
            if (-not $fid) {
                Write-Check -Id 'AppProtectionFilter' -Name "$($ap.Name) assignment filter" -Result 'FAIL' -Detail "No filter on the All Users assignment; expected $($ap.Filter) in include mode."
            } else {
                $resolved = $null
                try {
                    $resolved = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters('$fid')"
                } catch { }
                if (-not $resolved) {
                    Write-Check -Id 'AppProtectionFilter' -Name "$($ap.Name) assignment filter" -Result 'FAIL' -Detail "Filter id $fid does not resolve."
                } elseif ($resolved.rule -ne $expectedFilterRule) {
                    Write-Check -Id 'AppProtectionFilter' -Name "$($ap.Name) assignment filter rule" -Result 'FAIL' `
                        -Detail "Filter '$($resolved.displayName)' rule is '$($resolved.rule)'; expected exactly '$expectedFilterRule'."
                } elseif ($ftype -ne 'include') {
                    Write-Check -Id 'AppProtectionFilter' -Name "$($ap.Name) assignment filter mode" -Result 'FAIL' -Detail "Filter mode is '$ftype'; expected 'include'."
                } else {
                    Write-Check -Id 'AppProtectionFilter' -Name "$($ap.Name) assignment filter rule + include mode" -Result 'PASS'
                }
            }
        }
    }

    # The targeted app list must equal the shipped JSON's list.
    $jsonPath = Join-Path (Split-Path $PSScriptRoot -Parent) "Config/AppProtection/$($ap.Name).json"
    if (Test-Path $jsonPath) {
        $want = @((Get-Content -Raw $jsonPath | ConvertFrom-Json).apps |
            ForEach-Object { $_.mobileAppIdentifier.bundleId, $_.mobileAppIdentifier.packageId, $_.mobileAppIdentifier.windowsAppId } |
            Where-Object { $_ }) | Sort-Object
        $live = @()
        try {
            $live = @((Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$($ap.Endpoint)('$policyId')?`$expand=apps").apps |
                ForEach-Object { $_.mobileAppIdentifier.bundleId, $_.mobileAppIdentifier.packageId, $_.mobileAppIdentifier.windowsAppId } |
                Where-Object { $_ }) | Sort-Object
        } catch { }
        if (Compare-Object $want $live) {
            Write-Check -Id 'AppProtectionTargetedApps' -Name "$($ap.Name) targeted app list" -Result 'FAIL' `
                -Detail ("Differs from the shipped JSON. Missing: " + ((@($want | Where-Object { $_ -notin $live })) -join ', ') +
                         " | Extra: " + ((@($live | Where-Object { $_ -notin $want })) -join ', '))
        } else {
            Write-Check -Id 'AppProtectionTargetedApps' -Name "$($ap.Name) targeted app list matches JSON" -Result 'PASS'
        }
    }
}

# ---------------------------------------------------------------- 10. Ring 4 AER (B4)
if ($Gate -eq 'Ring4') {
    # CA300's session control does nothing unless the service honours it.
    if (Get-Command Get-SPOTenant -ErrorAction SilentlyContinue) {
        try {
            $spo = Get-SPOTenant
            if ($spo.ConditionalAccessPolicy -eq 'AllowLimitedAccess') {
                Write-Check -Id 'SharePointAER' -Name 'SharePoint app-enforced restrictions' -Result 'PASS'
            } else {
                Write-Check -Id 'SharePointAER' -Name 'SharePoint app-enforced restrictions' -Result 'FAIL' `
                    -Detail "Get-SPOTenant ConditionalAccessPolicy is '$($spo.ConditionalAccessPolicy)'; expected 'AllowLimitedAccess'. Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess. See Docs/app-enforced-restrictions.md."
            }
        } catch {
            Write-Check -Id 'SharePointAER' -Name 'SharePoint app-enforced restrictions' -Result 'FAIL' -Detail "Get-SPOTenant failed: $($_.Exception.Message)"
        }
    } else {
        Write-Check -Id 'SharePointAER' -Name 'SharePoint app-enforced restrictions' -Result 'FAIL' `
            -Detail 'Microsoft.Online.SharePoint.PowerShell not loaded. Connect-SPOService first — this gate cannot be assumed.'
    }

    # There is no organization-level Exchange switch: AER is per OWA mailbox
    # policy, so every policy an in-scope user is MAPPED to must carry it.
    if ((Get-Command Get-CasMailbox -ErrorAction SilentlyContinue) -and (Get-Command Get-OwaMailboxPolicy -ErrorAction SilentlyContinue)) {
        try {
            $owaPolicies = @{}
            foreach ($op in Get-OwaMailboxPolicy) { $owaPolicies[$op.Name] = $op.ConditionalAccessPolicy }
            $bad = @()
            foreach ($id in $usersGroupMembers) {
                $u = Get-MgUser -UserId $id -Property userPrincipalName -ErrorAction SilentlyContinue
                if (-not $u) { continue }
                $cas = Get-CasMailbox -Identity $u.UserPrincipalName -ErrorAction SilentlyContinue
                if (-not $cas) { continue }
                $polName = if ($cas.OwaMailboxPolicy) { $cas.OwaMailboxPolicy } else { 'Default' }
                $val = $owaPolicies[$polName]
                if ($val -notin @('ReadOnly','ReadOnlyPlusAttachmentsBlocked')) {
                    $bad += "$($u.UserPrincipalName) -> $polName ($val)"
                }
            }
            if ($bad.Count) {
                Write-Check -Id 'ExchangeAER' -Name 'Exchange app-enforced restrictions on every mapped OWA policy' -Result 'FAIL' `
                    -Detail ("Users mapped to an unrestricted OWA mailbox policy: " + (($bad | Select-Object -First 20) -join '; '))
            } else {
                Write-Check -Id 'ExchangeAER' -Name 'Exchange app-enforced restrictions on every mapped OWA policy' -Result 'PASS'
            }
        } catch {
            Write-Check -Id 'ExchangeAER' -Name 'Exchange app-enforced restrictions' -Result 'FAIL' -Detail "Exchange check failed: $($_.Exception.Message)"
        }
    } else {
        Write-Check -Id 'ExchangeAER' -Name 'Exchange app-enforced restrictions' -Result 'FAIL' `
            -Detail 'ExchangeOnlineManagement not connected. Connect-ExchangeOnline first — this gate cannot be assumed.'
    }
}

# ---------------------------------------------------------------- 11. Intune enrollment SP + TAP
$enrollAppId = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'
$sp = Get-MgServicePrincipal -Filter "appId eq '$enrollAppId'" -ErrorAction SilentlyContinue
if ($sp) {
    Write-Check -Id 'IntuneEnrollSP' -Name 'Microsoft Intune Enrollment service principal' -Result 'PASS'
} elseif ($Fix) {
    New-MgServicePrincipal -AppId $enrollAppId | Out-Null
    Write-Check -Id 'IntuneEnrollSP' -Name 'Microsoft Intune Enrollment service principal' -Result 'PASS' -Detail 'Created.'
} else {
    Write-Check -Id 'IntuneEnrollSP' -Name 'Microsoft Intune Enrollment service principal' -Result 'FAIL' -Detail "Missing. Re-run with -Fix, or: New-MgServicePrincipal -AppId $enrollAppId"
}

$tap = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId 'TemporaryAccessPass'
if ($tap.State -eq 'enabled') {
    Write-Check -Id 'TAP' -Name 'Temporary Access Pass method enabled' -Result 'PASS'
} elseif ($Fix) {
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
        -AuthenticationMethodConfigurationId 'TemporaryAccessPass' `
        -BodyParameter @{ '@odata.type' = '#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration'; state = 'enabled' }
    Write-Check -Id 'TAP' -Name 'Temporary Access Pass method enabled' -Result 'PASS' -Detail 'Enabled. Review include/exclude targets in the auth methods policy.'
} else {
    Write-Check -Id 'TAP' -Name 'Temporary Access Pass method enabled' -Result 'FAIL' -Detail 'TAP is the onboarding spine (CA004/CA203). Re-run with -Fix to enable, then scope targets.'
}

# ---------------------------------------------------------------- summary
Write-Host ""
Write-Host ("Gate {0}: {1} pass, {2} warn, {3} info (not gating here), {4} fail" -f `
    $Gate, $script:Pass, $script:Warn, $script:Info, $script:FailCount) -ForegroundColor Cyan
if ($script:FailCount -gt 0) {
    Write-Host "`nGate $Gate NOT PASSED. Blocking:" -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "Gate $Gate PASSED." -ForegroundColor Green
exit 0
