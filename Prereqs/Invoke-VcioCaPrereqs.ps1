<#
.SYNOPSIS
    VCIO CA Framework — prerequisite checks and setup.
.DESCRIPTION
    Verifies (and where safe, creates) everything the framework assumes before import:
      1. Security defaults disabled
      2. Break-glass accounts exist, are cloud-only, and sit in SG-CA-BreakGlass
      3. Microsoft Intune Enrollment service principal exists (creates if missing)
      4. Temporary Access Pass authentication method enabled (TAP is the onboarding spine)
      5. App Protection policies exist and are assigned (required before Ring 4)
    Read-only except where -Fix is specified. Nothing here touches CA policies.
.NOTES
    Requires Microsoft.Graph.Authentication, Microsoft.Graph.Applications,
    Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups, Microsoft.Graph.Users,
    Microsoft.Graph.Devices.CorporateManagement
    Version 2026.7.1 — validate in a lab tenant before customer use.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Fix,
    [switch]$PreImport,   # first run, before IntuneManagement import: checks that can only pass post-import report as informational
    [string]$BreakGlassGroupName = 'SG-CA-BreakGlass'
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- 0. module check
# PowerShell 7 recommended (5.1 supported). Installs missing Graph SDK modules
# to CurrentUser scope after confirmation — no admin rights required.
$requiredModules = @(
    'Microsoft.Graph.Authentication', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Users',
    'Microsoft.Graph.Applications', 'Microsoft.Graph.Identity.SignIns',
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
$script:Pass = 0; $script:Warn = 0; $script:FailCount = 0

function Write-Check {
    param([string]$Name, [ValidateSet('PASS','WARN','FAIL')][string]$Result, [string]$Detail)
    $color = @{PASS='Green'; WARN='Yellow'; FAIL='Red'}[$Result]
    Write-Host ("[{0}] {1}" -f $Result, $Name) -ForegroundColor $color
    if ($Detail) { Write-Host ("       {0}" -f $Detail) -ForegroundColor Gray }
    switch ($Result) {
        'PASS' { $script:Pass++ } 'WARN' { $script:Warn++ } 'FAIL' { $script:FailCount++ }
    }
}

$scopes = @(
    'Policy.Read.All', 'Application.ReadWrite.All', 'Group.Read.All',
    'User.Read.All', 'Policy.ReadWrite.AuthenticationMethod',
    'DeviceManagementApps.ReadWrite.All',      # -Fix creates missing APP policies via Graph
    'DeviceManagementConfiguration.ReadWrite.All'  # -Fix creates managed-app assignment filters via Graph
)
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $scopes -NoWelcome

# ---------------------------------------------------------------- stage detection
# If the tenant has no VCIO CA policies yet, this is a pre-import run — treat
# post-import-only checks as informational without requiring the -PreImport switch.
if (-not $PreImport) {
    $vcioPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match '-VCIO-' }
    if (-not $vcioPolicies) {
        $PreImport = $true
        Write-Host "No VCIO CA policies found in tenant — running in PRE-IMPORT mode automatically." -ForegroundColor Cyan
        Write-Host "(After import + group population, re-run for the full Ring 1 gate.)" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------- 1. security defaults
$sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
if ($sd.IsEnabled) {
    Write-Check 'Security defaults disabled' 'FAIL' 'Security defaults are ON. Disable before importing CA policies (Entra ID > Properties).'
} else {
    Write-Check 'Security defaults disabled' 'PASS'
}

# ---------------------------------------------------------------- 2. break-glass
$bgGroup = Get-MgGroup -Filter "displayName eq '$BreakGlassGroupName'" -ErrorAction SilentlyContinue
if (-not $bgGroup) {
    if ($PreImport) {
        Write-Check 'Break-glass group exists' 'WARN' "Not found — expected before import. IntuneManagement creates it; populate members, then re-run WITHOUT -PreImport as the Ring 1 gate."
    } else {
        Write-Check 'Break-glass group exists' 'FAIL' "Group '$BreakGlassGroupName' not found. Import the Groups folder first, or create it."
    }
} else {
    Write-Check 'Break-glass group exists' 'PASS' $bgGroup.Id
    $members = Get-MgGroupMember -GroupId $bgGroup.Id -All
    if ($members.Count -lt 2) {
        Write-Check 'Break-glass membership (>= 2 accounts)' 'FAIL' "Found $($members.Count). Framework requires two cloud-only break-glass accounts."
    } else {
        Write-Check 'Break-glass membership (>= 2 accounts)' 'PASS' "$($members.Count) members"
        foreach ($m in $members) {
            $u = Get-MgUser -UserId $m.Id -Property userPrincipalName,onPremisesSyncEnabled,accountEnabled
            if ($u.OnPremisesSyncEnabled) {
                Write-Check "Break-glass cloud-only: $($u.UserPrincipalName)" 'FAIL' 'Account is AD-synced. Break-glass must be cloud-only.'
            } elseif (-not $u.AccountEnabled) {
                Write-Check "Break-glass enabled: $($u.UserPrincipalName)" 'FAIL' 'Account is disabled.'
            } else {
                Write-Check "Break-glass cloud-only + enabled: $($u.UserPrincipalName)" 'PASS'
            }
            # FIDO2 registration check
            $methods = Get-MgUserAuthenticationFido2Method -UserId $m.Id -ErrorAction SilentlyContinue
            if (-not $methods) {
                Write-Check "Break-glass FIDO2 registered: $($u.UserPrincipalName)" 'WARN' 'No FIDO2 credential found. Framework standard is FIDO2-credentialed break-glass.'
            } else {
                Write-Check "Break-glass FIDO2 registered: $($u.UserPrincipalName)" 'PASS'
            }
        }
    }
}

# ---------------------------------------------------------------- 3. Intune Enrollment SP
$enrollAppId = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'
$sp = Get-MgServicePrincipal -Filter "appId eq '$enrollAppId'" -ErrorAction SilentlyContinue
if ($sp) {
    Write-Check 'Microsoft Intune Enrollment service principal' 'PASS'
} elseif ($Fix) {
    New-MgServicePrincipal -AppId $enrollAppId | Out-Null
    Write-Check 'Microsoft Intune Enrollment service principal' 'PASS' 'Created.'
} else {
    Write-Check 'Microsoft Intune Enrollment service principal' 'FAIL' "Missing. Re-run with -Fix, or: New-MgServicePrincipal -AppId $enrollAppId"
}

# ---------------------------------------------------------------- 4. TAP method enabled
$tap = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId 'TemporaryAccessPass'
if ($tap.State -eq 'enabled') {
    Write-Check 'Temporary Access Pass method enabled' 'PASS'
} elseif ($Fix) {
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
        -AuthenticationMethodConfigurationId 'TemporaryAccessPass' `
        -BodyParameter @{ '@odata.type' = '#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration'; state = 'enabled' }
    Write-Check 'Temporary Access Pass method enabled' 'PASS' 'Enabled. Review include/exclude targets in the auth methods policy.'
} else {
    Write-Check 'Temporary Access Pass method enabled' 'FAIL' 'TAP is the onboarding spine (CA004/CA203). Re-run with -Fix to enable, then scope targets.'
}

# ---------------------------------------------------------------- 5. App Protection policies
# Managed-app assignment filters — APP policies target ONLY unmanaged devices
# through these (assign APP to All Users + filter, include mode).
$existingFilters = (Invoke-MgGraphRequest -Method GET `
    -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters?$top=100' -ErrorAction SilentlyContinue).value
# NOTE: iOS/Android only — managed-app filters do not exist for Windows.
# Windows MAM assigns unfiltered (MDM coexistence + CA301's unmanaged scope handle it).
foreach ($flt in @(
    @{ Name = 'VCIO-FLT-iOS-UnmanagedDevices';     Platform = 'iOSMobileApplicationManagement' },
    @{ Name = 'VCIO-FLT-Android-UnmanagedDevices'; Platform = 'androidMobileApplicationManagement' }
)) {
    if ($existingFilters | Where-Object { $_.displayName -eq $flt.Name }) {
        Write-Check "Assignment filter: $($flt.Name)" 'PASS'
    } elseif ($Fix) {
        try {
            Invoke-MgGraphRequest -Method POST `
                -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters' `
                -Body (@{
                    displayName = $flt.Name
                    description = 'VCIO CA Framework: limits App Protection assignment to unmanaged devices.'
                    platform = $flt.Platform
                    rule = 'app.deviceManagementType -eq "Unmanaged"'
                    assignmentFilterManagementType = 'apps'
                } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
            Write-Check "Assignment filter: $($flt.Name)" 'PASS' 'Created via Graph.'
        } catch {
            Write-Check "Assignment filter: $($flt.Name)" 'WARN' "Graph creation failed: $($_.Exception.Message)"
        }
    } else {
        Write-Check "Assignment filter: $($flt.Name)" 'WARN' 'Missing. Re-run with -Fix to create.'
    }
}

$appPolicies = Get-MgDeviceAppManagementManagedAppPolicy -All -ErrorAction SilentlyContinue

# VCIO companion APP policies — created via Graph when missing, because
# IntuneManagement's App Protection import support varies by object type.
$vcioAppPolicies = @(
    @{ Name = 'VCIO-APP-iOS-Baseline';          Endpoint = 'iosManagedAppProtections';     Blocking = 'CA202' },
    @{ Name = 'VCIO-APP-Android-Baseline';      Endpoint = 'androidManagedAppProtections'; Blocking = 'CA202' },
    @{ Name = 'VCIO-APP-Windows-Edge-Baseline'; Endpoint = 'windowsManagedAppProtections'; Blocking = 'CA301' }
)
foreach ($ap in $vcioAppPolicies) {
    $existing = $appPolicies | Where-Object { $_.DisplayName -eq $ap.Name }
    if ($existing) {
        Write-Check "App Protection: $($ap.Name)" 'PASS'
        continue
    }
    if (-not $Fix) {
        Write-Check "App Protection: $($ap.Name)" 'WARN' "Missing. Re-run with -Fix to create via Graph. Required before $($ap.Blocking)."
        continue
    }
    try {
        $jsonPath = Join-Path (Split-Path $PSScriptRoot -Parent) "Config\AppProtection\$($ap.Name).json"
        if (-not (Test-Path $jsonPath)) {
            Write-Check "App Protection: $($ap.Name)" 'WARN' "JSON not found at $jsonPath — create manually."
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
        # Target apps via the dedicated action (apps cannot be set inline on create)
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/deviceAppManagement/$($ap.Endpoint)('$($created.id)')/targetApps" `
            -Body (@{ apps = $apps } | ConvertTo-Json -Depth 10) -ContentType 'application/json'
        Write-Check "App Protection: $($ap.Name)" 'PASS' "Created via Graph. Assign to All Users with the platform's VCIO-FLT-*-UnmanagedDevices filter (include) before its ring enables."
    } catch {
        Write-Check "App Protection: $($ap.Name)" 'WARN' "Graph creation failed: $($_.Exception.Message). Create manually per Docs/deployment-parameters.md."
    }
}

# ---------------------------------------------------------------- summary
Write-Host ""
Write-Host ("Prereq summary: {0} pass, {1} warn, {2} fail" -f $script:Pass, $script:Warn, $script:FailCount) -ForegroundColor Cyan
if ($script:FailCount -gt 0) {
    Write-Host "Resolve FAIL items before proceeding." -ForegroundColor Red
    exit 1
}
if ($PreImport) {
    Write-Host "Pre-import gate PASSED. Next: IntuneManagement bulk import (Config/, then Config-Overlay-P2/), populate groups, then re-run this script without -PreImport." -ForegroundColor Green
} else {
    Write-Host "Post-import gate PASSED. Framework is ready for Ring 1 enablement per Docs/runbook.md." -ForegroundColor Green
}
exit 0
