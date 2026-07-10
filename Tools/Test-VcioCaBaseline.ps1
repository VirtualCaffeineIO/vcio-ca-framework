<#
.SYNOPSIS
    VCIO CA Framework — release/deployment validator (PowerShell port).
.DESCRIPTION
    Lints the framework JSON for the defect classes that JSON-only baselines ship:
      - Inert policies (application scope 'None' with no user action or agent scope)
      - Dangling group / named-location GUID references
      - Exclusion-group reuse across policies (the chaining defect)
      - Missing break-glass exclusions
      - Encoding drift (UTF-16 / BOM)
      - Placeholder app IDs outside Templates/
    Run against the repo before every release, and against an export of the
    customer tenant (IntuneManagement bulk export) to detect drift after deployment.
.EXAMPLE
    .\Test-VcioCaBaseline.ps1 -Path ..\
#>
[CmdletBinding()]
param([string]$Path = (Join-Path $PSScriptRoot '..'))

$findings = New-Object System.Collections.Generic.List[string]
$wellKnownApps = @(
    'All','None','Office365','MicrosoftAdminPortals','AllAgentIdResources',
    '797f4846-ba00-4fd7-ba43-dac1f8f63013','0000000a-0000-0000-c000-000000000000',
    'd4ebce55-015a-49b5-a083-c84d1797ae8c','2793995e-0a7d-40d7-bd35-6968ba142197',
    '00000002-0000-0ff1-ce00-000000000000','00000003-0000-0ff1-ce00-000000000000',
    'REPLACE-WITH-APP-ID'
)
$validStates = @('enabled','disabled','enabledForReportingButNotEnforced')
$guidRe = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

function Read-JsonStrict([string]$File) {
    $bytes = [System.IO.File]::ReadAllBytes($File)
    if ($bytes.Length -ge 2 -and (($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF))) {
        $findings.Add("$File : UTF-16 encoding — must be UTF-8"); return $null
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $findings.Add("$File : UTF-8 BOM present — must be UTF-8 without BOM")
    }
    try { return Get-Content -Raw -Path $File | ConvertFrom-Json }
    catch { $findings.Add("$File : JSON parse error — $($_.Exception.Message)"); return $null }
}

# --- groups & named locations ---
$groups = @{}
Get-ChildItem (Join-Path $Path 'Config/Groups/*.json') | ForEach-Object {
    $g = Read-JsonStrict $_.FullName
    if ($g) { $groups[$g.id] = $g.displayName }
}
$locations = @{}
Get-ChildItem (Join-Path $Path 'Config/NamedLocations/*.json') | ForEach-Object {
    $n = Read-JsonStrict $_.FullName
    if ($n) { $locations[$n.id] = $n.displayName }
}
$bgId = ($groups.GetEnumerator() | Where-Object { $_.Value -eq 'SG-CA-BreakGlass' }).Key
if (-not $bgId) { $findings.Add('SG-CA-BreakGlass group missing from Config/Groups') }

# --- policies ---
$exclUsage = @{}
$policyFiles = @(
    Get-ChildItem (Join-Path $Path 'Config/ConditionalAccess/*.json') -ErrorAction SilentlyContinue
    Get-ChildItem (Join-Path $Path 'Config-Overlay-P2/ConditionalAccess/*.json') -ErrorAction SilentlyContinue
    Get-ChildItem (Join-Path $Path 'Templates/ConditionalAccess/*.json') -ErrorAction SilentlyContinue
)
foreach ($file in $policyFiles) {
    $p = Read-JsonStrict $file.FullName
    if (-not $p) { continue }
    $name = $p.displayName
    $isTemplate = $file.FullName -match 'Templates'
    $rel = $file.Name

    if ($file.Name -ne "$name.json") { $findings.Add("$rel : filename does not match displayName '$name'") }
    if ($name -notmatch '^CA\d{3}-VCIO-') { $findings.Add("$rel : displayName does not match CAnnn-VCIO-* convention") }
    if ($p.state -notin $validStates) { $findings.Add("$rel : invalid state '$($p.state)'") }

    $cond = $p.conditions; $apps = $cond.applications; $users = $cond.users

    # inert scope (the CA104 class)
    $incApps = @($apps.includeApplications); $incActions = @($apps.includeUserActions)
    $agentScope = $cond.agents -or $cond.clientApplications -or $cond.agentIdRiskLevels
    if ($incApps.Count -eq 1 -and $incApps[0] -eq 'None' -and $incActions.Count -eq 0 -and -not $agentScope) {
        $findings.Add("$rel : INERT POLICY — includeApplications=['None'] with no user action or agent scope")
    }
    if ($incApps.Count -eq 0 -and $incActions.Count -eq 0) { $findings.Add("$rel : no application or user-action scope") }

    # user scope
    $hasUsers = @($users.includeUsers).Count -or @($users.includeGroups).Count -or
                @($users.includeRoles).Count -or $users.includeGuestsOrExternalUsers
    if (-not $hasUsers) { $findings.Add("$rel : no user scope") }

    # must do something
    $g = $p.grantControls; $s = $p.sessionControls
    $activeSession = $false
    if ($s) {
        foreach ($prop in $s.PSObject.Properties) {
            if ($prop.Name -notmatch '^@' -and $prop.Value) { $activeSession = $true }
        }
    }
    if (-not $g -and -not $activeSession) { $findings.Add("$rel : neither grant controls nor active session controls") }
    if ($g -and -not @($g.builtInControls).Count -and -not $g.authenticationStrength) {
        $findings.Add("$rel : grantControls present but empty")
    }

    # group wiring + exclusion usage
    foreach ($gid in @($users.includeGroups) + @($users.excludeGroups)) {
        if ($gid -and -not $groups.ContainsKey($gid)) { $findings.Add("$rel : references unknown group $gid") }
    }
    foreach ($gid in @($users.excludeGroups)) {
        if ($gid -and $groups.ContainsKey($gid) -and $groups[$gid] -like 'SG-CA-Excl-*') {
            if (-not $exclUsage.ContainsKey($gid)) { $exclUsage[$gid] = @() }
            $exclUsage[$gid] += $name
        }
    }

    # location wiring
    if ($cond.locations) {
        foreach ($lid in @($cond.locations.includeLocations) + @($cond.locations.excludeLocations)) {
            if ($lid -and $lid -notin @('All','AllTrusted') -and -not $locations.ContainsKey($lid)) {
                $findings.Add("$rel : references unknown named location $lid")
            }
        }
    }

    # app references sane; placeholders confined to Templates/
    foreach ($a in $incApps + @($apps.excludeApplications)) {
        if ($a -and $a -notin $wellKnownApps -and $a -notmatch $guidRe) {
            $findings.Add("$rel : unrecognized app reference '$a'")
        }
    }
    if (-not $isTemplate -and ('REPLACE-WITH-APP-ID' -in ($incApps + @($apps.excludeApplications)))) {
        $findings.Add("$rel : placeholder app id outside Templates/")
    }

    # break-glass excluded from every user-scoped, non-agent policy
    $isAgent = $agentScope -or (@($users.includeUsers).Count -eq 1 -and @($users.includeUsers)[0] -eq 'None')
    if ($bgId -and -not $isAgent -and $bgId -notin @($users.excludeGroups)) {
        $findings.Add("$rel : break-glass group not excluded")
    }
}

# exclusion reuse / orphans
foreach ($kv in $exclUsage.GetEnumerator()) {
    if ($kv.Value.Count -gt 1) { $findings.Add("exclusion group $($groups[$kv.Key]) reused by: $($kv.Value -join ', ')") }
}
foreach ($kv in $groups.GetEnumerator()) {
    if ($kv.Value -like 'SG-CA-Excl-*' -and -not $exclUsage.ContainsKey($kv.Key)) {
        $findings.Add("orphaned exclusion group: $($kv.Value)")
    }
}

Write-Host ("Checked {0} policies, {1} groups, {2} named locations." -f $policyFiles.Count, $groups.Count, $locations.Count)
if ($findings.Count) {
    Write-Host "`n$($findings.Count) FINDINGS:" -ForegroundColor Red
    $findings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    exit 1
}
Write-Host 'CLEAN — release gate passed.' -ForegroundColor Green
exit 0
