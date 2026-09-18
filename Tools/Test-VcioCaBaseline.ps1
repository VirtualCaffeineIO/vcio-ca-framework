<#
.SYNOPSIS
    VCIO CA Framework — operator's drift validator.
.DESCRIPTION
    The companion to build/validate.py. That one is the RELEASE validator and
    runs in CI against the repo tree; this one is the DRIFT validator and runs
    against an IntuneManagement bulk export of the customer tenant, with the
    deployment manifest.

    They have different jobs, but every structural rule below is implemented in
    both, and CI runs both against the repo tree so they cannot disagree.

    Structural rules (both validators, no manifest needed):
      - Required policy identities present by displayName pattern (never a count)
      - Inert policies (application scope 'None' with no user action or agent scope)
      - C3  Agent scope: includeUsers=['None'] needs real agent principals
      - C4  Redundancy: [compliantDevice, mfa] OR inside CA002's scope
      - C5  Device filters: every standard policy uses exactly one filter string
      - A10 Transition pairing: the standard four exclude the group, the
            variants include it
      - A9  Template instances own their exclusion group
      - Dangling group / named-location GUID references
      - Exclusion-group reuse across policies (the chaining defect)
      - Missing break-glass exclusions
      - Encoding drift (UTF-16 / BOM), placeholder app IDs outside Templates/
      - MigrationTable completeness

    Manifest rules (need -Manifest, skipped without it):
      - C2  Transition lifecycle against exitDate
      - C6  Service-account fencing mode

    Neither validator gates on a policy COUNT. The tree count is informational.
.PARAMETER Path
    Repo root, or the root of an IntuneManagement bulk export.
.PARAMETER Manifest
    Deploy/<tenant>/manifest.json. See Deploy/manifest.example.json.
.EXAMPLE
    .\Test-VcioCaBaseline.ps1 -Path ..\
.EXAMPLE
    .\Test-VcioCaBaseline.ps1 -Path C:\export\contoso -Manifest C:\vcio\Deploy\contoso\manifest.json
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot '..'),
    [string]$Manifest
)

$findings = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]
$skipped  = New-Object System.Collections.Generic.List[string]

$wellKnownApps = @(
    'All','None','Office365','MicrosoftAdminPortals','AllAgentIdResources',
    '797f4846-ba00-4fd7-ba43-dac1f8f63013','0000000a-0000-0000-c000-000000000000',
    'd4ebce55-015a-49b5-a083-c84d1797ae8c','2793995e-0a7d-40d7-bd35-6968ba142197',
    '00000002-0000-0ff1-ce00-000000000000','00000003-0000-0ff1-ce00-000000000000',
    'REPLACE-WITH-APP-ID'
)
$validStates = @('enabled','disabled','enabledForReportingButNotEnforced')
$guidRe = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

# C5 — the one device-filter string any standard policy may carry.
$filterCompliant = 'device.isCompliant -eq True'

# A10 — standard policies that must exclude SG-CA-Transition-Hybrid.
$transitionExcluders = @('200','204','300','301')

# Required policy identities, per folder. Presence is checked; count is not.
$required = [ordered]@{
    'Config/ConditionalAccess' = @(
        '000','001','002','003','004','005','006','007',
        '100','101','102','103','200','201','202','203','204',
        '300','301','400','401','402','403','500','501','600','601','602'
    ) | ForEach-Object { "^CA$_-VCIO-" }
    'Config-Overlay-P2/ConditionalAccess' = @('700','701','702','703','704','705') |
        ForEach-Object { "^CA$_-VCIO-" }
    'Templates/ConditionalAccess' = @(
        '^CA500-VCIO-ServiceAccounts-IPFence-SYSTEMNAME$',
        '^CA501-VCIO-ServiceAccounts-RestrictApps-SYSTEMNAME$',
        '^CA800-VCIO-','^CA801-VCIO-','^CA802-VCIO-','^CA803-VCIO-'
    )
    'Transition/ConditionalAccess' = @(
        '^CA200-VCIO-.*-TRANSITION$','^CA204-VCIO-.*-TRANSITION$',
        '^CA300-VCIO-.*-TRANSITION$','^CA301-VCIO-.*-TRANSITION$'
    )
}

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

function Get-Files([string]$Relative) {
    Get-ChildItem (Join-Path $Path $Relative) -ErrorAction SilentlyContinue
}

# --- groups & named locations -------------------------------------------------
# Core objects import into the tenant. Template-scope objects live under
# Templates/ so the shipped SYSTEMNAME templates have resolvable references;
# they are never bulk-imported and never in the MigrationTable.
$groups = @{}; $coreGroups = @{}; $groupObjects = @{}
foreach ($f in Get-Files 'Config/Groups/*.json') {
    $g = Read-JsonStrict $f.FullName
    if ($g) { $groups[$g.id] = $g.displayName; $coreGroups[$g.id] = $g.displayName; $groupObjects[$g.displayName] = $g }
}
foreach ($f in Get-Files 'Templates/Groups/*.json') {
    $g = Read-JsonStrict $f.FullName
    if ($g) { $groups[$g.id] = $g.displayName; $groupObjects[$g.displayName] = $g }
}
$locations = @{}
foreach ($f in @(Get-Files 'Config/NamedLocations/*.json') + @(Get-Files 'Templates/NamedLocations/*.json')) {
    $n = Read-JsonStrict $f.FullName
    if ($n) { $locations[$n.id] = $n.displayName }
}

function Get-GroupId([string]$Name) {
    ($groups.GetEnumerator() | Where-Object { $_.Value -eq $Name } | Select-Object -First 1).Key
}
$bgId = Get-GroupId 'SG-CA-BreakGlass'
if (-not $bgId) { $findings.Add('SG-CA-BreakGlass group missing from Config/Groups') }
$saId = Get-GroupId 'SG-CA-ServiceAccounts'
$transitionId = Get-GroupId 'SG-CA-Transition-Hybrid'
if (-not $transitionId) { $findings.Add('SG-CA-Transition-Hybrid group missing from Config/Groups (A10)') }
if (-not (Get-GroupId 'SG-CA-Privileged')) { $findings.Add('SG-CA-Privileged group missing from Config/Groups (A8)') }

# --- migration table (core groups only) ---------------------------------------
$mtPath = Join-Path $Path 'Config/MigrationTable.json'
if (Test-Path $mtPath) {
    $mt = Read-JsonStrict $mtPath
    if ($mt) {
        $mtIds = @($mt.Objects | ForEach-Object { $_.Id })
        foreach ($kv in $coreGroups.GetEnumerator()) {
            if ($kv.Key -notin $mtIds) { $findings.Add("MigrationTable missing group: $($kv.Value)") }
        }
        foreach ($id in $mtIds) {
            if (-not $coreGroups.ContainsKey($id)) {
                $findings.Add("MigrationTable references a group not in Config/Groups: $id")
            }
        }
    }
}

# --- policies -----------------------------------------------------------------
$exclUsage = @{}
$groupUsage = @{}
$present = @{}
# C1 — Transition/ is globbed. It was missing here while the Python validator
# already covered it, which is exactly the disagreement CI now prevents.
$policyDirs = @('Config/ConditionalAccess','Config-Overlay-P2/ConditionalAccess',
                'Templates/ConditionalAccess','Transition/ConditionalAccess')
$policyFiles = @()
foreach ($d in $policyDirs) {
    $present[$d] = @()
    $policyFiles += @(Get-Files "$d/*.json" | ForEach-Object {
        [pscustomobject]@{ File = $_; Dir = $d }
    })
}
$transitionPolicies = @()

foreach ($entry in $policyFiles) {
    $file = $entry.File
    $p = Read-JsonStrict $file.FullName
    if (-not $p) { continue }
    $name = $p.displayName
    $rel = "$($entry.Dir)/$($file.Name)"
    $present[$entry.Dir] += $name

    $isTemplateDir = $entry.Dir -like 'Templates/*'
    $isTransition  = $entry.Dir -like 'Transition/*'
    $sharesNumber  = $isTemplateDir -or $isTransition
    # A shipped template still carries its placeholder; anything else under a
    # template number is an INSTANCE and gets the full structural treatment.
    $isShippedTemplate = $isTemplateDir -and ($name -like '*-APPNAME' -or $name -like '*-SYSTEMNAME')
    $isInstance = $isTemplateDir -and -not $isShippedTemplate

    if ($file.Name -ne "$name.json") { $findings.Add("$rel : filename does not match displayName '$name'") }
    if ($name -notmatch '^CA(\d{3})-VCIO-') {
        $findings.Add("$rel : displayName does not match CAnnn-VCIO-* convention"); continue
    }
    $nnn = $Matches[1]
    if ($p.state -notin $validStates) { $findings.Add("$rel : invalid state '$($p.state)'") }
    if ($isTransition) { $transitionPolicies += [pscustomobject]@{ Name = $name; State = $p.state } }

    $cond = $p.conditions; $apps = $cond.applications; $users = $cond.users
    $incUsers  = @($users.includeUsers)
    $incGroups = @($users.includeGroups)
    $excGroups = @($users.excludeGroups)

    # inert scope (the CA104 class)
    $incApps = @($apps.includeApplications); $incActions = @($apps.includeUserActions)
    $agentScope = $cond.agents -or $cond.clientApplications -or $cond.agentIdRiskLevels
    if ($incApps.Count -eq 1 -and $incApps[0] -eq 'None' -and $incActions.Count -eq 0 -and -not $agentScope) {
        $findings.Add("$rel : INERT POLICY — includeApplications=['None'] with no user action or agent scope")
    }
    if ($incApps.Count -eq 0 -and $incActions.Count -eq 0) { $findings.Add("$rel : no application or user-action scope") }

    # user scope
    $hasUsers = $incUsers.Count -or $incGroups.Count -or @($users.includeRoles).Count -or $users.includeGuestsOrExternalUsers
    if (-not $hasUsers) { $findings.Add("$rel : no user scope") }

    # C3 — includeUsers=['None'] means no human is in scope, so the principals
    # must come from an agent block that actually names some. A non-null block
    # with empty collections is still inert; agentIdRiskLevels is a CONDITION.
    if ($incUsers.Count -eq 1 -and $incUsers[0] -eq 'None') {
        # @($null).Count is 1, so every one of these must be filtered for
        # truthiness before counting or a missing block reads as real scope.
        $agentPrincipals = @(
            @($cond.agents.includeAgentUsers) +
            @($cond.clientApplications.includeAgentIdServicePrincipals) +
            @($cond.clientApplications.includeServicePrincipals)
        ) | Where-Object { $_ }
        if (-not @($agentPrincipals).Count) {
            $findings.Add("$rel : C3 INERT AGENT SCOPE — includeUsers=['None'] with no non-empty agents.includeAgentUsers, clientApplications.includeAgentIdServicePrincipals or includeServicePrincipals (agentIdRiskLevels alone is not scope)")
        }
    }

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

    # C4 — compliantDevice OR mfa adds nothing for a population already inside
    # CA002's MFA scope. Approximation of "inside CA002's scope": targets All
    # users or a member group, not guests-only, not a service-account policy.
    if ($g -and $g.operator -eq 'OR') {
        $ctl = @($g.builtInControls) | Sort-Object
        if ($ctl.Count -eq 2 -and $ctl[0] -eq 'compliantDevice' -and $ctl[1] -eq 'mfa') {
            $guestsOnly = $users.includeGuestsOrExternalUsers -and -not ($incUsers.Count -or $incGroups.Count)
            $saScoped = $saId -and ($saId -in $incGroups)
            if (-not $guestsOnly -and -not $saScoped) {
                $findings.Add("$rel : C4 REDUNDANT — grant [compliantDevice, mfa] with operator OR over a population already inside CA002's MFA scope; MFA alone satisfies it, so the policy enforces nothing new")
            }
        }
    }

    # C5 — one filter string, one meaning. Ownership is not a security state.
    # Transition/ is the only place another filter may appear.
    $rule = $cond.devices.deviceFilter.rule
    if ($rule -and -not $isTransition -and $rule -ne $filterCompliant) {
        $findings.Add("$rel : C5 FILTER DRIFT — device filter is '$rule'; every standard policy must use exactly '$filterCompliant'")
    }

    # group wiring + usage
    foreach ($gid in $incGroups + $excGroups) {
        if (-not $gid) { continue }
        if (-not $groups.ContainsKey($gid)) { $findings.Add("$rel : references unknown group $gid"); continue }
        if (-not $groupUsage.ContainsKey($gid)) { $groupUsage[$gid] = @() }
        $groupUsage[$gid] += $name
    }
    foreach ($gid in $excGroups) {
        if ($gid -and $groups.ContainsKey($gid) -and $groups[$gid] -like 'SG-CA-Excl-*') {
            if (-not $sharesNumber -or $isInstance) {
                if (-not $exclUsage.ContainsKey($gid)) { $exclUsage[$gid] = @() }
                $exclUsage[$gid] += $name
            }
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
    if (-not $isTemplateDir -and ('REPLACE-WITH-APP-ID' -in ($incApps + @($apps.excludeApplications)))) {
        $findings.Add("$rel : placeholder app id outside Templates/")
    }

    # break-glass excluded from every user-scoped, non-agent policy
    $isAgent = $agentScope -or ($incUsers.Count -eq 1 -and $incUsers[0] -eq 'None')
    if ($bgId -and -not $isAgent -and $bgId -notin $excGroups) {
        $findings.Add("$rel : break-glass group not excluded")
    }

    # A10 — the standard four exclude the transition group; the variants
    # include it. Backwards, and a user is covered twice or not at all.
    if ($transitionId) {
        if ($nnn -in $transitionExcluders -and -not $sharesNumber -and $transitionId -notin $excGroups) {
            $findings.Add("$rel : A10 — CA$nnn must exclude SG-CA-Transition-Hybrid; without it a transition user is covered by both the standard policy and its variant")
        }
        if ($isTransition -and $transitionId -notin $incGroups) {
            $findings.Add("$rel : A10 — transition variant must include SG-CA-Transition-Hybrid, not SG-CA-Users")
        }
    }

    # A9 — a template INSTANCE must own its scope. Reusing another policy's
    # exclusion group is the chaining defect; sharing a per-system group would
    # silently widen a fence.
    if ($isInstance) {
        $owned = @($incGroups + $excGroups | Where-Object {
            $_ -and $groups.ContainsKey($_) -and
            ($groups[$_] -like 'SG-CA-Excl-CA*' -or $groups[$_] -like 'SG-CA-SA-*')
        })
        if (-not $owned.Count) {
            $findings.Add("$rel : A9 — template instance references no instance-scoped group (expected its own SG-CA-Excl-CA<nnn>-<NAME>)")
        }
    }
}

# --- required identities ------------------------------------------------------
foreach ($kv in $required.GetEnumerator()) {
    $names = @($present[$kv.Key])
    foreach ($pat in $kv.Value) {
        if (-not ($names | Where-Object { $_ -match $pat })) {
            $findings.Add("$($kv.Key) : no policy matching required identity /$pat/")
        }
    }
}

# --- exclusion reuse / orphans ------------------------------------------------
foreach ($kv in $exclUsage.GetEnumerator()) {
    if ($kv.Value.Count -gt 1) { $findings.Add("exclusion group $($groups[$kv.Key]) reused by: $($kv.Value -join ', ')") }
}
foreach ($kv in $groups.GetEnumerator()) {
    if ($kv.Value -like 'SG-CA-Excl-*' -and -not $exclUsage.ContainsKey($kv.Key)) {
        $findings.Add("orphaned exclusion group: $($kv.Value)")
    }
    elseif ($kv.Value -notlike 'SG-CA-Excl-*' -and -not $groupUsage.ContainsKey($kv.Key) -and $kv.Value -ne 'SG-CA-BreakGlass') {
        $findings.Add("orphaned group: $($kv.Value) is referenced by no policy")
    }
}

# --- manifest rules (C2, C6) --------------------------------------------------
# These need facts the tree does not carry: who is in a group today, and which
# fencing mode this tenant declared. Without a manifest they are SKIPPED, not
# passed — CI runs this script against the bare repo, where they cannot apply.
if (-not $Manifest) {
    $skipped.Add('C2 (transition lifecycle) — needs -Manifest')
    $skipped.Add('C6 (service-account fencing mode) — needs -Manifest')
}
else {
    if (-not (Test-Path $Manifest)) { throw "Manifest not found: $Manifest" }
    $mf = Get-Content -Raw $Manifest | ConvertFrom-Json

    # Membership is a live fact. An export may carry it; if nothing does, the
    # check is UNVERIFIED, and UNVERIFIED does not pass.
    function Get-MemberCount([string]$GroupName) {
        $obj = $groupObjects[$GroupName]
        if ($obj -and $obj.PSObject.Properties.Name -contains 'members') { return @($obj.members).Count }
        if ($mf.groupMemberCounts -and $mf.groupMemberCounts.PSObject.Properties.Name -contains $GroupName) {
            return [int]$mf.groupMemberCounts.$GroupName
        }
        return $null
    }

    # ---- C2 transition lifecycle
    $exitRaw = $mf.transition.exitDate
    $members = Get-MemberCount 'SG-CA-Transition-Hybrid'
    if (-not $exitRaw) {
        $findings.Add('C2 : manifest has no transition.exitDate — the exit date does not live in the policy JSON (Graph documents description as "Not used"), so the manifest is the only place it exists')
    }
    elseif ($null -eq $members) {
        $findings.Add('C2 : UNVERIFIED — SG-CA-Transition-Hybrid membership is not in the export and not in manifest.groupMemberCounts. UNVERIFIED does not pass; re-export with membership or record the count')
    }
    else {
        $exitDate = [datetime]::Parse($exitRaw)
        $now = Get-Date
        if ($members -gt 0 -and $now -ge $exitDate) {
            $findings.Add("C2 : SG-CA-Transition-Hybrid still has $members member(s) after exitDate $($exitDate.ToString('yyyy-MM-dd')) — run Tools/Invoke-VcioTransitionExit.ps1")
        }
        if ($members -gt 0 -and $now -lt $exitDate -and ($exitDate - $now).TotalDays -le 30) {
            $warnings.Add("C2 : transition exitDate $($exitDate.ToString('yyyy-MM-dd')) is in $([int]($exitDate - $now).TotalDays) days with $members member(s) still in SG-CA-Transition-Hybrid")
        }
        foreach ($tp in $transitionPolicies) {
            if ($members -gt 0 -and $tp.State -ne 'enabled') {
                # The standard policies' exclusions are already live. Only an
                # ENFORCED transition policy replaces what they gave up.
                $findings.Add("C2 : $($tp.Name) is '$($tp.State)' while SG-CA-Transition-Hybrid has $members member(s) — the standard-policy exclusions are active, so those users are currently uncovered")
            }
            if ($members -eq 0 -and $tp.State -eq 'enabled' -and $mf.transition.groupEmptiedDate) {
                $emptied = [datetime]::Parse($mf.transition.groupEmptiedDate)
                if (((Get-Date) - $emptied).TotalDays -gt 30) {
                    $findings.Add("C2 : $($tp.Name) is still enabled over an empty group emptied $($emptied.ToString('yyyy-MM-dd')) — dead policy, disable it")
                }
            }
        }
    }

    # ---- C6 fencing mode
    $mode = $mf.fencingMode
    $allPolicyNames = @()
    foreach ($d in $policyDirs) { $allPolicyNames += @($present[$d]) }
    $states = @{}
    foreach ($entry in $policyFiles) {
        $p = Read-JsonStrict $entry.File.FullName
        if ($p) { $states[$p.displayName] = $p.state }
    }
    $sharedFence   = $states.Keys | Where-Object { $_ -eq 'CA500-VCIO-ServiceAccounts-IPFence' }
    $sharedRestrict= $states.Keys | Where-Object { $_ -eq 'CA501-VCIO-ServiceAccounts-RestrictApps' }
    $perSystem = @($states.Keys | Where-Object { $_ -match '^CA500-VCIO-ServiceAccounts-IPFence-(.+)$' -and $Matches[1] -ne 'SYSTEMNAME' })

    switch ($mode) {
        'Shared' {
            if ($sharedFence -and $states['CA500-VCIO-ServiceAccounts-IPFence'] -ne 'enabled') {
                $findings.Add("C6 : fencing mode Shared but CA500-VCIO-ServiceAccounts-IPFence is '$($states['CA500-VCIO-ServiceAccounts-IPFence'])', not enabled")
            }
            foreach ($inst in $perSystem) {
                # One permitted exception: the DirSync instance is a separate
                # scope that must never touch the shared group.
                if ($inst -ne 'CA500-VCIO-ServiceAccounts-IPFence-DirSync') {
                    $findings.Add("C6 : fencing mode Shared but per-system instance $inst is present — declare Mode Per-System or remove it")
                }
            }
        }
        'Per-System' {
            foreach ($n in @('CA500-VCIO-ServiceAccounts-IPFence','CA501-VCIO-ServiceAccounts-RestrictApps')) {
                if ($states.ContainsKey($n) -and $states[$n] -ne 'disabled') {
                    $findings.Add("C6 : fencing mode Per-System requires the shared $n to be 'disabled' (not report-only, which still evaluates) — it is '$($states[$n])'")
                }
            }
            $saGroups = @($groups.Values | Where-Object { $_ -like 'SG-CA-SA-*' -and $_ -ne 'SG-CA-SA-SYSTEMNAME' })
            foreach ($sg in $saGroups) {
                $suffix = $sg -replace '^SG-CA-SA-',''
                $inst = "CA500-VCIO-ServiceAccounts-IPFence-$suffix"
                if (-not $states.ContainsKey($inst)) {
                    $findings.Add("C6 : $sg has no CA500 instance ($inst) — an unfenced per-system group")
                }
                elseif ($states[$inst] -ne 'enabled') {
                    $findings.Add("C6 : $inst is '$($states[$inst])', not enabled — $sg is not actually fenced")
                }
            }
        }
        default {
            $findings.Add("C6 : manifest fencingMode is '$mode' — must be 'Shared' or 'Per-System'")
        }
    }
}

# --- report -------------------------------------------------------------------
$total = $policyFiles.Count
Write-Host ("Checked {0} policies, {1} core groups (+{2} template-scope), {3} named locations." -f `
    $total, $coreGroups.Count, ($groups.Count - $coreGroups.Count), $locations.Count)
foreach ($s in $skipped)  { Write-Host "  [SKIP] $s" -ForegroundColor DarkGray }
foreach ($w in $warnings) { Write-Host "  [WARN] $w" -ForegroundColor Yellow }
if ($findings.Count) {
    Write-Host "`n$($findings.Count) FINDINGS:" -ForegroundColor Red
    $findings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    exit 1
}
Write-Host 'CLEAN — release gate passed.' -ForegroundColor Green
exit 0
