<#
.SYNOPSIS
    E1. Reconcile everyone who is actually privileged against what the
    framework's privileged policies can see.
.DESCRIPTION
    CA100, CA101 and CA102 target built-in directory roles plus
    SG-CA-Privileged. Built-in role targeting is blind to three things:

      1. Custom directory roles.
      2. Administrative-unit-scoped assignments.
      3. Azure RBAC entirely — Owner, User Access Administrator and friends
         at management-group, subscription, resource-group or resource
         scope, which are control-plane privilege by any honest definition
         and which Entra role targeting never sees.

    Anyone in those categories is privileged and is NOT covered by the 100s
    unless someone put them in SG-CA-Privileged. This script finds them.

    Output:
      FAIL       privileged but uncovered, by name
      WARN       in SG-CA-Privileged with no privilege found (stale)
      INCOMPLETE a management group or subscription in the manifest's
                 expected inventory that the caller could not read, or one
                 that exists in the tenant but is absent from the manifest

    INCOMPLETE means the run is not clean, and the Ring 3 gate (B3) will not
    pass on it. A scope you could not read is not a scope with nobody in it.

    Runbook: monthly, and the privilege-grant procedure adds the user to
    SG-CA-Privileged at grant time. The monthly run is the backstop, not the
    mechanism.
.PARAMETER Manifest
    Deploy/<tenant>/manifest.json. expectedAzureScope.managementGroups and
    .subscriptions are the inventory this run is measured against.
.PARAMETER RecordResult
    Write the run's outcome back into the manifest's privilegedScopeLastRun,
    which is what the Ring 3 gate reads.
.EXAMPLE
    .\Compare-VcioPrivilegedScope.ps1 -Manifest ..\Deploy\contoso\manifest.json
.NOTES
    Requires Microsoft.Graph.Authentication, Microsoft.Graph.Groups,
    Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance, and Az.Accounts
    + Az.ResourceGraph for the Azure RBAC half.
    Version 2026.9.1.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Manifest,
    [switch]$RecordResult
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Manifest)) { throw "Manifest not found: $Manifest" }
$mf = Get-Content -Raw $Manifest | ConvertFrom-Json

$uncovered  = New-Object System.Collections.Generic.List[string]
$stale      = New-Object System.Collections.Generic.List[string]
$incomplete = New-Object System.Collections.Generic.List[string]

# The 23 built-in roles CA100/101/102 target (generate.py ADMIN_ROLES). A
# holder of one of these is already in scope by role targeting.
# Keep in step with generate.py: this is a hardcoded copy.
$ADMIN_ROLES = @(
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
# Azure RBAC roles that are control-plane privilege regardless of scope.
$AZ_PRIVILEGED_ROLES = @(
    'Owner','Contributor','User Access Administrator',
    'Role Based Access Control Administrator'
)

Import-Module (Join-Path $PSScriptRoot 'VcioCaCommon.psm1') -Force

# Finding 7 — connect to the tenant the MANIFEST names, then prove it. A cached
# context signed in elsewhere would otherwise have this tool enumerate, and
# with -RecordResult write about, the wrong tenant. The assertion runs before
# any read and before any write.
Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
Connect-MgGraph -TenantId $mf.tenantId -Scopes @(
    'Directory.Read.All','RoleManagement.Read.Directory',
    'RoleEligibilitySchedule.Read.Directory','Group.Read.All','User.Read.All',
    'AdministrativeUnit.Read.All'
) -NoWelcome
$connectedTenant = Assert-VcioTenantContext -ExpectedTenantId $mf.tenantId
Write-Host "Tenant verified: $connectedTenant" -ForegroundColor Cyan

# --------------------------------------------------------------- helpers
$principalCache = @{}
function Resolve-Principal([string]$Id) {
    if ($principalCache.ContainsKey($Id)) { return $principalCache[$Id] }
    $label = $Id
    try {
        $o = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$Id"
        $label = if ($o.userPrincipalName) { $o.userPrincipalName } else { "$($o.displayName) [$($o.'@odata.type' -replace '#microsoft.graph.','')]" }
    } catch { }
    $principalCache[$Id] = $label
    $label
}
# A group assignment is one assignment and any number of privileged people.
function Expand-Principal([string]$Id) {
    $out = @()
    $type = $null
    try {
        $o = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$Id"
        $type = $o.'@odata.type'
    } catch { return @($Id) }
    if ($type -eq '#microsoft.graph.group') {
        try {
            $members = Get-VcioGraphCollection -Uri "https://graph.microsoft.com/v1.0/groups/$Id/transitiveMembers?`$select=id&`$top=999"
            foreach ($m in $members) { $out += $m.id }
        } catch { $incomplete.Add("Could not expand group ${Id}: $($_.Exception.Message)") }
    } else {
        $out += $Id
    }
    $out
}

# --------------------------------------------------------------- 1. Entra roles
Write-Host 'Enumerating Entra directory role assignments (active + eligible, built-in + custom, tenant + AU)...' -ForegroundColor Cyan
$privileged = @{}      # principalId -> list of reasons
$coveredByRole = @{}   # principalId -> $true (already in the 100s by role targeting)

function Add-Privileged([string]$Id, [string]$Reason) {
    foreach ($p in Expand-Principal $Id) {
        if (-not $privileged.ContainsKey($p)) { $privileged[$p] = @() }
        $privileged[$p] += $Reason
    }
}

$roleDefs = @{}
# Finding 3 — every one of these is a PAGED collection. $top=999 returns a
# first page, and "the first 999 holders do not include anyone else" is not
# the same statement as "nobody else holds this role". Get-VcioGraphCollection
# follows @odata.nextLink to the end and throws rather than return a partial
# set silently.
foreach ($rd in (Get-VcioGraphCollection -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$top=999')) {
    $roleDefs[$rd.id] = $rd
}

foreach ($a in (Get-VcioGraphCollection -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$top=999')) {
    $rd = $roleDefs[$a.roleDefinitionId]
    $isBuiltIn = $rd -and $rd.isBuiltIn
    $scopeNote = if ($a.directoryScopeId -and $a.directoryScopeId -ne '/') { " (AU-scoped $($a.directoryScopeId))" } else { '' }
    # Only a TENANT-scoped built-in role in the framework's list is actually
    # covered by CA100/101/102. An AU-scoped assignment of the same role is not
    # — includeRoles matches the role, and the portal shows it, but the holder
    # of an AU-scoped grant is a different population the customer may not have
    # reviewed. Treat it as needing SG-CA-Privileged.
    if ($isBuiltIn -and $a.roleDefinitionId -in $ADMIN_ROLES -and -not $scopeNote) {
        foreach ($p in Expand-Principal $a.principalId) { $coveredByRole[$p] = $true }
        continue
    }
    $kind = if ($isBuiltIn) { 'built-in' } else { 'CUSTOM' }
    Add-Privileged $a.principalId "Entra $kind role '$($rd.displayName)'$scopeNote (active)"
}

try {
    foreach ($e in (Get-VcioGraphCollection -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$top=999')) {
        $rd = $roleDefs[$e.roleDefinitionId]
        $isBuiltIn = $rd -and $rd.isBuiltIn
        $scopeNote = if ($e.directoryScopeId -and $e.directoryScopeId -ne '/') { " (AU-scoped $($e.directoryScopeId))" } else { '' }
        if ($isBuiltIn -and $e.roleDefinitionId -in $ADMIN_ROLES -and -not $scopeNote) {
            foreach ($p in Expand-Principal $e.principalId) { $coveredByRole[$p] = $true }
            continue
        }
        $kind = if ($isBuiltIn) { 'built-in' } else { 'CUSTOM' }
        Add-Privileged $e.principalId "Entra $kind role '$($rd.displayName)'$scopeNote (PIM-eligible)"
    }
} catch {
    $incomplete.Add("Could not read PIM eligibility schedules: $($_.Exception.Message)")
}

# --------------------------------------------------------------- 2. Azure RBAC
Write-Host 'Enumerating Azure RBAC (Resource Graph authorizationresources + PIM eligibility)...' -ForegroundColor Cyan
$azOk = $false
if ((Get-Module -ListAvailable Az.ResourceGraph) -and (Get-Module -ListAvailable Az.Accounts)) {
    try {
        Import-Module Az.Accounts, Az.ResourceGraph -ErrorAction Stop
        if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }
        $azOk = $true
    } catch { $incomplete.Add("Azure sign-in failed: $($_.Exception.Message)") }
} else {
    $incomplete.Add('Az.Accounts / Az.ResourceGraph not installed — the entire Azure RBAC half of privilege was not examined. This run is not clean.')
}

if ($azOk) {
    # Custom roles that can grant roles are as privileged as User Access
    # Administrator, whatever they are called.
    $customPrivilegedRoles = @()
    try {
        $q = @"
authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions'
| extend roleName = tostring(properties.roleName), roleType = tostring(properties.type)
| where roleType =~ 'CustomRole'
| mv-expand perm = properties.permissions
| mv-expand action = perm.actions
| where tostring(action) =~ 'Microsoft.Authorization/roleAssignments/write' or tostring(action) == '*'
| distinct roleName, id
"@
        $customPrivilegedRoles = @(Invoke-VcioAzGraphQuery -Query $q)
    } catch { $incomplete.Add("Custom role definition query failed: $($_.Exception.Message)") }

    $privilegedRoleNames = $AZ_PRIVILEGED_ROLES + @($customPrivilegedRoles | ForEach-Object { $_.roleName })
    $nameList = ($privilegedRoleNames | ForEach-Object { "'" + ($_ -replace "'","\'") + "'" }) -join ','
    try {
        $q2 = @"
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalId = tostring(properties.principalId),
         roleDefinitionId = tostring(properties.roleDefinitionId),
         scope = tostring(properties.scope)
| join kind=inner (
    authorizationresources
    | where type =~ 'microsoft.authorization/roledefinitions'
    | extend roleName = tostring(properties.roleName)
    | project roleDefinitionId = id, roleName
) on roleDefinitionId
| where roleName in~ ($nameList)
| project principalId, roleName, scope
"@
        # -First 5000 was not a large page — Search-AzGraph caps -First at
        # 1000 and rejects anything higher, so this query was erroring rather
        # than truncating. Invoke-VcioAzGraphQuery pages at 1000.
        foreach ($r in @(Invoke-VcioAzGraphQuery -Query $q2)) {
            Add-Privileged $r.principalId "Azure RBAC '$($r.roleName)' at $($r.scope) (active)"
        }
    } catch { $incomplete.Add("Azure RBAC assignment query failed: $($_.Exception.Message)") }

    # PIM-eligible Azure assignments are not in Resource Graph, and the REST
    # collection is paged via nextLink. Finding 3: this must cover MANAGEMENT
    # GROUP scope as well as subscriptions — an Owner eligibility at a
    # management group is inherited by every subscription beneath it and was
    # previously invisible to this tool entirely.
    function Get-AzEligibilityAtScope([string]$Scope, [string]$Label) {
        $rows = @()
        $path = "$Scope/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&`$filter=atScope()"
        $pages = 0
        while ($path -and $pages -lt 200) {
            $resp = Invoke-AzRestMethod -Path $path -Method GET
            $pages++
            if ($resp.StatusCode -ne 200) { throw "HTTP $($resp.StatusCode)" }
            $body = $resp.Content | ConvertFrom-Json
            foreach ($v in @($body.value)) { if ($v) { $rows += $v } }
            $path = $null
            if ($body.PSObject.Properties.Name -contains 'nextLink' -and $body.nextLink) {
                # nextLink is absolute; Invoke-AzRestMethod -Path wants the path.
                $path = ([uri]$body.nextLink).PathAndQuery
            }
        }
        foreach ($r in $rows) { Add-Privileged $r.properties.principalId "Azure RBAC eligible at $Label" }
        $rows.Count
    }

    foreach ($mg in @($mf.expectedAzureScope.managementGroups)) {
        if (-not $mg) { continue }
        try {
            [void](Get-AzEligibilityAtScope "/providers/Microsoft.Management/managementGroups/$mg" "management group $mg")
        } catch {
            $incomplete.Add("Management group '$mg': could not read PIM eligibility — $($_.Exception.Message)")
        }
    }
    foreach ($sub in @($mf.expectedAzureScope.subscriptions)) {
        if (-not $sub.id) { continue }
        try {
            [void](Get-AzEligibilityAtScope "/subscriptions/$($sub.id)" "subscription $($sub.name)")
        } catch {
            $incomplete.Add("Subscription '$($sub.name)' ($($sub.id)): could not read PIM eligibility — $($_.Exception.Message)")
        }
    }

    # Inventory reconciliation, both directions.
    $expectedSubs = @($mf.expectedAzureScope.subscriptions | ForEach-Object { $_.id })
    $liveSubs = @()
    try {
        $liveSubs = @(Invoke-VcioAzGraphQuery -Query 'resourcecontainers | where type =~ "microsoft.resources/subscriptions" | project subscriptionId, name')
    } catch { $incomplete.Add("Could not enumerate subscriptions: $($_.Exception.Message)") }
    foreach ($s in $liveSubs) {
        if ($s.subscriptionId -notin $expectedSubs) {
            $incomplete.Add("Subscription '$($s.name)' ($($s.subscriptionId)) exists in the tenant but is not in the manifest's expected inventory")
        }
    }
    foreach ($id in $expectedSubs) {
        if ($id -notin @($liveSubs | ForEach-Object { $_.subscriptionId })) {
            $incomplete.Add("Subscription $id is in the manifest but the caller could not read it")
        }
    }
    $expectedMgs = @($mf.expectedAzureScope.managementGroups)
    foreach ($mg in $expectedMgs) {
        try {
            $resp = Invoke-AzRestMethod -Path "/providers/Microsoft.Management/managementGroups/$mg`?api-version=2021-04-01" -Method GET
            if ($resp.StatusCode -ne 200) { throw "HTTP $($resp.StatusCode)" }
        } catch {
            $incomplete.Add("Management group '$mg' is in the manifest but the caller could not read it — $($_.Exception.Message)")
        }
    }
}

# --------------------------------------------------------------- 3. diff
Write-Host 'Diffing against SG-CA-Privileged...' -ForegroundColor Cyan
# Finding 7 — manifest object id first. Resolving by displayName would happily
# find a group someone renamed or duplicated.
$privRef = Resolve-VcioObjectId -Manifest $mf -Kind 'groups' -Name 'SG-CA-Privileged' -Fallback {
    param($n) (Get-MgGroup -Filter "displayName eq '$n'" -ErrorAction SilentlyContinue | Select-Object -First 1).Id
}
$inGroup = @()
if ($privRef.Id) {
    if ($privRef.Source -eq 'displayName-fallback') {
        Write-Host "  NOTE: SG-CA-Privileged resolved by displayName fallback (no id in manifest.objectIds.groups). Record its tenant object id." -ForegroundColor Yellow
    }
    $inGroup = @(Get-MgGroupMember -GroupId $privRef.Id -All | ForEach-Object { $_.Id })
} else {
    $incomplete.Add('SG-CA-Privileged could not be resolved from the manifest or by displayName.')
}

foreach ($p in $privileged.Keys) {
    if ($coveredByRole.ContainsKey($p)) { continue }   # already in the 100s by role
    if ($p -in $inGroup) { continue }                  # covered by the group
    $uncovered.Add("$(Resolve-Principal $p) — $(($privileged[$p] | Select-Object -Unique) -join '; ')")
}
foreach ($m in $inGroup) {
    if (-not $privileged.ContainsKey($m) -and -not $coveredByRole.ContainsKey($m)) {
        $stale.Add("$(Resolve-Principal $m) — in SG-CA-Privileged, no privilege found")
    }
}

# --------------------------------------------------------------- 4. report
Write-Host ''
Write-Host ("Examined {0} privileged principal(s) outside built-in tenant-scoped role targeting; SG-CA-Privileged holds {1}." -f $privileged.Count, $inGroup.Count) -ForegroundColor Cyan
if ($uncovered.Count) {
    Write-Host "`n$($uncovered.Count) PRIVILEGED BUT UNCOVERED (FAIL):" -ForegroundColor Red
    $uncovered | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host '  Add each to SG-CA-Privileged, or remove the privilege.' -ForegroundColor Gray
}
if ($stale.Count) {
    Write-Host "`n$($stale.Count) STALE MEMBERSHIP (WARN):" -ForegroundColor Yellow
    $stale | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
if ($incomplete.Count) {
    Write-Host "`n$($incomplete.Count) INCOMPLETE:" -ForegroundColor Magenta
    $incomplete | ForEach-Object { Write-Host "  - $_" -ForegroundColor Magenta }
    Write-Host '  A scope you could not read is not a scope with nobody in it. This run is NOT clean.' -ForegroundColor Gray
}

$clean = ($uncovered.Count -eq 0 -and $incomplete.Count -eq 0)
if ($RecordResult) {
    if (-not $mf.PSObject.Properties.Name.Contains('privilegedScopeLastRun')) {
        $mf | Add-Member -NotePropertyName privilegedScopeLastRun -NotePropertyValue ([pscustomobject]@{})
    }
    $mf.privilegedScopeLastRun = [pscustomobject]@{
        date       = (Get-Date).ToString('yyyy-MM-dd')
        clean      = $clean
        uncovered  = $uncovered.Count
        stale      = $stale.Count
        incomplete = $incomplete.Count
    }
    $mf | ConvertTo-Json -Depth 12 | Set-Content -Path $Manifest -Encoding utf8
    Write-Host "`nRecorded in $Manifest (privilegedScopeLastRun)." -ForegroundColor Cyan
}

if (-not $clean) {
    Write-Host "`nNOT CLEAN — the Ring 3 gate (B3) will not pass on this." -ForegroundColor Red
    exit 1
}
Write-Host "`nCLEAN — every privileged principal is covered and every expected scope was read." -ForegroundColor Green
exit 0
