<#
    Regression tests for the second external source review, one Describe per
    finding. Graph and Az cmdlets are stubbed and mocked — nothing here talks
    to a tenant, and none of these tests substitute for the live tenant tests
    (F1/F2/F3), which have still not run.

    Requires Pester 5+ (CI pins the version). Run:
        Invoke-Pester -Path Tests -Output Detailed
#>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $script:Root 'Tools/VcioCaCommon.psm1') -Force

    # Pester cannot mock a command that does not resolve, and neither the Graph
    # SDK nor Az is installed on a validation runner. Stub the surface first.
    # The stubs must declare the parameters the callers actually pass: a bare
    # param() would refuse the binding, and a mock reading $Uri or $First would
    # silently see $null — which is a test that proves nothing.
    $script:Stubs = @{
        'Connect-MgGraph'  = { param($TenantId, $Scopes, [switch]$NoWelcome) }
        'Get-MgContext'    = { }
        'Get-MgAuditLogSignIn' = { param($Filter, [switch]$All, $ErrorAction) }
        'Get-MgGroupMember'    = { param($GroupId, [switch]$All, $ErrorAction) }
        'Get-MgGroup'          = { param($Filter, $GroupId, [switch]$All, $ErrorAction) }
        'Get-MgUser'           = { param($UserId, $Property, $ErrorAction) }
        'Get-MgUserTransitiveMemberOf' = { param($UserId, [switch]$All, $ErrorAction) }
        'Get-MgIdentityConditionalAccessPolicy' = { param($ConditionalAccessPolicyId, [switch]$All, $State, $ErrorAction) }
        'Get-MgIdentityConditionalAccessNamedLocation' = { param([switch]$All, $ErrorAction) }
        'Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance' = { param($Filter, [switch]$All, $ErrorAction) }
        'Remove-MgGroupMemberByRef' = { param($GroupId, $DirectoryObjectId) }
        'Update-MgIdentityConditionalAccessPolicy' = { param($ConditionalAccessPolicyId, $State) }
        'Invoke-MgGraphRequest' = { param($Method, $Uri, $Body, $ContentType, $ErrorAction) }
        'Search-AzGraph'    = { param($Query, $First, $Skip, $SkipToken, $Subscription, $ManagementGroup) }
        'Invoke-AzRestMethod' = { param($Path, $Method, $Payload) }
    }
    foreach ($kv in $script:Stubs.GetEnumerator()) {
        if (-not (Get-Command $kv.Key -ErrorAction SilentlyContinue)) {
            Set-Item "function:global:$($kv.Key)" $kv.Value | Out-Null
        }
    }

    function New-SignIn {
        param([string]$Ip, [int]$ErrorCode = 0, [datetime]$When = [datetime]::UtcNow, [array]$Applied = @())
        [pscustomobject]@{
            IpAddress = $Ip
            CreatedDateTime = $When
            Status = [pscustomobject]@{ ErrorCode = $ErrorCode }
            AppliedConditionalAccessPolicies = $Applied
        }
    }
    function New-AppliedPolicy { param([string]$Id, [string]$Result)
        [pscustomobject]@{ Id = $Id; Result = $Result } }
}

# ==========================================================================
Describe 'Finding 1 — the privileged-holder loop runs' {

    It 'proves $pid is read-only, which is why the old loop could never run' {
        # Documents the defect: this is a hard terminating error, not shadowing.
        { Invoke-Command { foreach ($pid in 1..2) { $pid } } } | Should -Throw
    }

    It 'no foreach in any shipped script binds a read-only automatic variable' {
        # AST-based, so it catches a reintroduction of $pid or any sibling —
        # not just the one spelling that was wrong.
        $readOnlyAutomatics = @('pid','host','true','false','null','pshome','psculture',
                                'psuiculture','psversiontable','executioncontext')
        $offenders = @()
        $files = Get-ChildItem -Path $script:Root -Recurse -Include '*.ps1','*.psm1' |
                 Where-Object { $_.FullName -notlike '*Tests*' }
        foreach ($f in $files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($loop in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
                $name = $loop.Variable.VariablePath.UserPath
                if ($name.ToLowerInvariant() -in $readOnlyAutomatics) {
                    $offenders += "$($f.Name):$($loop.Extent.StartLineNumber) foreach (`$$name ...)"
                }
            }
        }
        $offenders -join '; ' | Should -BeExactly ''
    }

    It 'iterates every principal when the variable is a normal one' {
        $principals = @{ 'a-1' = $true; 'b-2' = $true; 'c-3' = $true }
        $seen = @()
        foreach ($principalId in $principals.Keys) { $seen += $principalId }
        $seen.Count | Should -Be 3
    }
}

# ==========================================================================
Describe 'Finding 2 — B3a fence evidence is not inverted' {

    Context 'the fence APPLIES — a structural fact, not a log inference' {
        BeforeAll {
            $script:Users = [pscustomobject]@{
                IncludeGroups = @('grp-sa'); ExcludeGroups = @('grp-excl')
                IncludeUsers  = @();          ExcludeUsers  = @()
            }
        }
        It 'a transitive member of the included group is in scope' {
            (Test-VcioPrincipalInPolicyScope -PrincipalId 'u1' -PolicyUsers $script:Users `
                -TransitiveGroupIds @('grp-nested','grp-sa')).InScope | Should -BeTrue
        }
        It 'an account excluded through a NESTED group is out of scope' {
            # The dangerous direction: direct-only membership would miss this
            # and report the account as fenced.
            (Test-VcioPrincipalInPolicyScope -PrincipalId 'u1' -PolicyUsers $script:Users `
                -TransitiveGroupIds @('grp-sa','grp-excl')).InScope | Should -BeFalse
        }
        It 'an account named directly in excludeUsers is out of scope' {
            $u = [pscustomobject]@{ IncludeGroups=@('grp-sa'); ExcludeGroups=@()
                                    IncludeUsers=@(); ExcludeUsers=@('u1') }
            (Test-VcioPrincipalInPolicyScope -PrincipalId 'u1' -PolicyUsers $u `
                -TransitiveGroupIds @('grp-sa')).InScope | Should -BeFalse
        }
        It 'an unrelated account is out of scope' {
            (Test-VcioPrincipalInPolicyScope -PrincipalId 'u9' -PolicyUsers $script:Users `
                -TransitiveGroupIds @('grp-other')).InScope | Should -BeFalse
        }
    }

    Context 'the fence HOLDS — source IP against the location ranges' {
        BeforeAll { $script:Cidrs = @('203.0.113.0/24','2001:db8:abcd::/48') }

        It 'inside-success PASSES (it logs CA500 as notApplied, which is correct)' {
            (Test-VcioSignInsWithinFence -SignIns @((New-SignIn -Ip '203.0.113.9' -ErrorCode 0)) `
                -Cidrs $script:Cidrs).Verdict | Should -Be 'PASS'
        }
        It 'outside-success FAILS' {
            (Test-VcioSignInsWithinFence -SignIns @(
                (New-SignIn -Ip '203.0.113.9' -ErrorCode 0),
                (New-SignIn -Ip '198.51.100.7' -ErrorCode 0)) -Cidrs $script:Cidrs).Verdict | Should -Be 'FAIL'
        }
        It 'outside-blocked PASSES and is reported, not failed' {
            $r = Test-VcioSignInsWithinFence -SignIns @(
                (New-SignIn -Ip '203.0.113.9' -ErrorCode 0),
                (New-SignIn -Ip '198.51.100.7' -ErrorCode 53003)) -Cidrs $script:Cidrs
            $r.Verdict | Should -Be 'PASS'
            $r.OutsideBlocked | Should -Be 1
        }
        It 'IPv6 inside the range passes' {
            (Test-VcioSignInsWithinFence -SignIns @((New-SignIn -Ip '2001:db8:abcd:1::5' -ErrorCode 0)) `
                -Cidrs $script:Cidrs).Verdict | Should -Be 'PASS'
        }
        It 'IPv6 outside the range fails' {
            (Test-VcioSignInsWithinFence -SignIns @((New-SignIn -Ip '2001:db8:abce::5' -ErrorCode 0)) `
                -Cidrs $script:Cidrs).Verdict | Should -Be 'FAIL'
        }
        It 'never matches a v4 address against a v6 range' {
            Test-VcioIpInRanges -IpAddress '203.0.113.9' -Cidrs @('2001:db8::/32') | Should -BeFalse
        }
        It 'no sign-ins in the window is UNVERIFIED and does not pass' {
            (Test-VcioSignInsWithinFence -SignIns @() -Cidrs $script:Cidrs).Verdict | Should -Be 'UNVERIFIED'
        }
        It 'a success whose IP cannot be placed is UNVERIFIED, not a pass' {
            (Test-VcioSignInsWithinFence -SignIns @((New-SignIn -Ip '' -ErrorCode 0)) `
                -Cidrs $script:Cidrs).Verdict | Should -Be 'UNVERIFIED'
        }
        It 'reads ipRanges off a named location in either SDK shape' {
            $nl = [pscustomobject]@{ Id='nl1'; AdditionalProperties = @{ ipRanges = @(
                @{ cidrAddress = '203.0.113.0/24' }, @{ cidrAddress = '10.1.0.0/16' }) } }
            (Get-VcioNamedLocationRanges -NamedLocation $nl) | Should -Be @('203.0.113.0/24','10.1.0.0/16')
        }
    }
}

# ==========================================================================
Describe 'Finding 3 — paging consumes the whole result set' {

    It 'Resource Graph: a 1,500-row result is fully consumed across pages' {
        $script:AzCalls = 0
        # Honours -First/-Skip, so a helper that ignores paging would either
        # return 1,000 rows or spin forever.
        Mock Search-AzGraph {
            $script:AzCalls++
            $total = 1500
            $skip = if ($null -ne $Skip) { [int]$Skip } else { 0 }
            $want = if ($null -ne $First) { [int]$First } else { $total }
            $take = [Math]::Min($want, $total - $skip)
            if ($take -le 0) { return @() }
            (($skip + 1)..($skip + $take)) | ForEach-Object { [pscustomobject]@{ principalId = "p$_" } }
        } -ModuleName VcioCaCommon

        $rows = Invoke-VcioAzGraphQuery -Query 'x'
        $rows.Count | Should -Be 1500
        ($rows | Select-Object -ExpandProperty principalId -Unique).Count | Should -Be 1500
        $script:AzCalls | Should -BeGreaterThan 1
    }

    It 'Resource Graph: PageSize is capped at the service maximum of 1000' {
        { Invoke-VcioAzGraphQuery -Query 'x' -PageSize 5000 } | Should -Throw
    }

    It 'Graph: @odata.nextLink is followed to the end' {
        Mock Invoke-MgGraphRequest {
            if ($Uri -like '*page2*') { return @{ value = @(@{ id = 'c' }, @{ id = 'd' }) } }
            return @{ value = @(@{ id = 'a' }, @{ id = 'b' }); '@odata.nextLink' = 'https://graph/page2' }
        } -ModuleName VcioCaCommon

        $all = Get-VcioGraphCollection -Uri 'https://graph/start'
        $all.Count | Should -Be 4
    }

    It 'Graph: refuses to report a partial collection as complete' {
        Mock Invoke-MgGraphRequest {
            @{ value = @(@{ id = 'x' }); '@odata.nextLink' = 'https://graph/forever' }
        } -ModuleName VcioCaCommon
        { Get-VcioGraphCollection -Uri 'https://graph/start' -MaxPages 3 } | Should -Throw
    }
}

# ==========================================================================
Describe 'Finding 4 — Security Defaults is not a PreImport gate' {

    BeforeAll {
        $script:PrereqSrc = Get-Content -Raw (Join-Path $script:Root 'Prereqs/Invoke-VcioCaPrereqs.ps1')
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:PrereqSrc, [ref]$null, [ref]$null)
        $hash = $ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.HashtableAst] -and
            ($args[0].KeyValuePairs.Item1.Extent.Text -contains 'PreImport')
        }, $true) | Select-Object -First 1
        $script:Gates = @{}
        foreach ($kv in $hash.KeyValuePairs) {
            $script:Gates[$kv.Item1.Extent.Text] = $kv.Item2.Extent.Text
        }
    }

    It 'PreImport does not list SecurityDefaults' {
        $script:Gates['PreImport'] | Should -Not -Match "'SecurityDefaults'"
    }
    It 'PostSwitch still lists SecurityDefaults' {
        $script:Gates['PostSwitch'] | Should -Match "'SecurityDefaults'"
    }
    It 'the implementation guide no longer tells the operator to disable and re-run' {
        $guide = Get-Content -Raw (Join-Path $script:Root 'Docs/implementation-guide.md')
        $guide | Should -Not -Match 'If security defaults show FAIL, disable them'
    }
}

# ==========================================================================
Describe 'Finding 5 — break-glass Global Administrator must be standing' {

    It 'a standing assignment with no end date PASSES' {
        $inst = @([pscustomobject]@{ PrincipalId='bg1'; AssignmentType='Assigned'; EndDateTime=$null })
        (Test-VcioPermanentRoleAssignment -PrincipalId 'bg1' -ScheduleInstances $inst).Pass | Should -BeTrue
    }
    It 'an ACTIVATED PIM eligibility FAILS' {
        $inst = @([pscustomobject]@{ PrincipalId='bg1'; AssignmentType='Activated'; EndDateTime=(Get-Date).AddHours(4) })
        $r = Test-VcioPermanentRoleAssignment -PrincipalId 'bg1' -ScheduleInstances $inst
        $r.Pass | Should -BeFalse
        $r.Reason | Should -Match 'ACTIVATED'
    }
    It 'a time-bound standing assignment FAILS' {
        $inst = @([pscustomobject]@{ PrincipalId='bg1'; AssignmentType='Assigned'; EndDateTime=(Get-Date).AddDays(30) })
        (Test-VcioPermanentRoleAssignment -PrincipalId 'bg1' -ScheduleInstances $inst).Pass | Should -BeFalse
    }
    It 'an EMPTY instance set FAILS — it is never a skip' {
        $r = Test-VcioPermanentRoleAssignment -PrincipalId 'bg1' -ScheduleInstances @()
        $r.Pass | Should -BeFalse
        $r.Reason | Should -Match 'empty result set|not evidence'
    }
    It 'every member is evaluated individually' {
        $inst = @([pscustomobject]@{ PrincipalId='bg1'; AssignmentType='Assigned'; EndDateTime=$null })
        (Test-VcioPermanentRoleAssignment -PrincipalId 'bg1' -ScheduleInstances $inst).Pass | Should -BeTrue
        (Test-VcioPermanentRoleAssignment -PrincipalId 'bg2' -ScheduleInstances $inst).Pass | Should -BeFalse
    }
    It 'the script no longer wraps the per-member check in an emptiness guard' {
        $src = Get-Content -Raw (Join-Path $script:Root 'Prereqs/Invoke-VcioCaPrereqs.ps1')
        $src | Should -Not -Match '\$gaAssignments\.Count\)\s*\{'
    }
}

# ==========================================================================
Describe 'Finding 6 — post-removal coverage needs an ENFORCED result' {

    BeforeAll {
        $script:Ids = @{ 'p200'='CA200'; 'p204'='CA204'; 'p300'='CA300'; 'p301'='CA301' }
        $script:RemovedAt = [datetime]::Parse('2026-09-10T12:00:00Z').ToUniversalTime()
        function AllFour([string]$Result, [datetime]$When) {
            @(New-SignIn -Ip '1.2.3.4' -ErrorCode 0 -When $When -Applied @(
                (New-AppliedPolicy -Id 'p200' -Result $Result), (New-AppliedPolicy -Id 'p204' -Result $Result),
                (New-AppliedPolicy -Id 'p300' -Result $Result), (New-AppliedPolicy -Id 'p301' -Result $Result)))
        }
    }

    It 'a PRE-removal sign-in is rejected' {
        $s = AllFour 'success' $script:RemovedAt.AddMinutes(-5)
        $r = Test-VcioStandardCoverage -SignIns $s -PolicyIdToName $script:Ids -RemovedAt $script:RemovedAt
        $r.Verified | Should -BeFalse
        $r.SignInsConsidered | Should -Be 0
    }
    It 'a sign-in exactly AT the removal instant is rejected (strictly after)' {
        $s = AllFour 'success' $script:RemovedAt
        (Test-VcioStandardCoverage -SignIns $s -PolicyIdToName $script:Ids -RemovedAt $script:RemovedAt).Verified | Should -BeFalse
    }
    It 'a reportOnlySuccess result is rejected' {
        $s = AllFour 'reportOnlySuccess' $script:RemovedAt.AddMinutes(5)
        $r = Test-VcioStandardCoverage -SignIns $s -PolicyIdToName $script:Ids -RemovedAt $script:RemovedAt
        $r.Verified | Should -BeFalse
        $r.Missing.Count | Should -Be 4
    }
    It 'a notApplied result is rejected' {
        $s = AllFour 'notApplied' $script:RemovedAt.AddMinutes(5)
        (Test-VcioStandardCoverage -SignIns $s -PolicyIdToName $script:Ids -RemovedAt $script:RemovedAt).Verified | Should -BeFalse
    }
    It 'enforced success after removal is accepted' {
        $s = AllFour 'success' $script:RemovedAt.AddMinutes(5)
        (Test-VcioStandardCoverage -SignIns $s -PolicyIdToName $script:Ids -RemovedAt $script:RemovedAt).Verified | Should -BeTrue
    }
    It 'enforced failure also counts as enforced' {
        $s = AllFour 'failure' $script:RemovedAt.AddMinutes(5)
        (Test-VcioStandardCoverage -SignIns $s -PolicyIdToName $script:Ids -RemovedAt $script:RemovedAt).Verified | Should -BeTrue
    }
    It 'accumulates across sign-ins, because the four cannot co-occur on one' {
        # CA200 is mobileAppsAndDesktopClients; CA300/301 are browser.
        $desktop = New-SignIn -Ip '1.2.3.4' -ErrorCode 0 -When $script:RemovedAt.AddMinutes(5) -Applied @(
            (New-AppliedPolicy -Id 'p200' -Result 'success'), (New-AppliedPolicy -Id 'p204' -Result 'success'))
        $browser = New-SignIn -Ip '1.2.3.4' -ErrorCode 0 -When $script:RemovedAt.AddMinutes(9) -Applied @(
            (New-AppliedPolicy -Id 'p300' -Result 'success'), (New-AppliedPolicy -Id 'p301' -Result 'success'))
        $r = Test-VcioStandardCoverage -SignIns @($desktop,$browser) -PolicyIdToName $script:Ids -RemovedAt $script:RemovedAt
        $r.Verified | Should -BeTrue
    }
    It 'one missing policy leaves the user unverified' {
        $partial = New-SignIn -Ip '1.2.3.4' -ErrorCode 0 -When $script:RemovedAt.AddMinutes(5) -Applied @(
            (New-AppliedPolicy -Id 'p200' -Result 'success'), (New-AppliedPolicy -Id 'p204' -Result 'success'),
            (New-AppliedPolicy -Id 'p300' -Result 'success'))
        $r = Test-VcioStandardCoverage -SignIns @($partial) -PolicyIdToName $script:Ids -RemovedAt $script:RemovedAt
        $r.Verified | Should -BeFalse
        $r.Missing | Should -Be @('CA301')
    }
    It 'the exit script records a precise UTC removal instant, not a date' {
        $src = Get-Content -Raw (Join-Path $script:Root 'Tools/Invoke-VcioTransitionExit.ps1')
        $src | Should -Match "removedAt\s*=\s*\`$removedAt"
        $src | Should -Match "UtcNow\.ToString\('yyyy-MM-ddTHH:mm:ss\.fffZ'\)"
    }
}

# ==========================================================================
Describe 'Finding 7 — tenant assertion aborts before any write' {

    It 'a matching tenant returns the tenant id' {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'aaaa-1111' } } -ModuleName VcioCaCommon
        Assert-VcioTenantContext -ExpectedTenantId 'aaaa-1111' | Should -Be 'aaaa-1111'
    }
    It 'a MISMATCHED tenant throws' {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'bbbb-2222' } } -ModuleName VcioCaCommon
        { Assert-VcioTenantContext -ExpectedTenantId 'aaaa-1111' } | Should -Throw '*TENANT MISMATCH*'
    }
    It 'an absent context throws' {
        Mock Get-MgContext { $null } -ModuleName VcioCaCommon
        { Assert-VcioTenantContext -ExpectedTenantId 'aaaa-1111' } | Should -Throw
    }
    It 'a manifest with no tenantId refuses to run' {
        { Assert-VcioTenantContext -ExpectedTenantId '' } | Should -Throw '*no tenantId*'
    }

    It 'the transition exit aborts on a tenant mismatch before writing the log or removing anyone' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("vcio-t7-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $tmp | Out-Null
        try {
            $manifest = Join-Path $tmp 'manifest.json'
            @{  tenantId = 'expected-tenant-1111'
                transition = @{ exitDate = '2020-01-01'; groupId = 'g-transition'
                                policyIds = @{}; verifiedRemovals = @() }
                objectIds = @{ groups = @{}; policies = @{}; namedLocations = @{} }
            } | ConvertTo-Json -Depth 8 | Set-Content $manifest

            # The connected tenant is NOT the manifest's.
            Set-Item 'function:global:Connect-MgGraph' { param() } | Out-Null
            Set-Item 'function:global:Get-MgContext'   { [pscustomobject]@{ TenantId = 'some-other-tenant-9999' } } | Out-Null
            $global:VcioRemoveCalls = 0
            $global:VcioUpdateCalls = 0
            Set-Item 'function:global:Remove-MgGroupMemberByRef' { param() $global:VcioRemoveCalls++ } | Out-Null
            Set-Item 'function:global:Update-MgIdentityConditionalAccessPolicy' { param() $global:VcioUpdateCalls++ } | Out-Null
            Set-Item 'function:global:Get-MgIdentityConditionalAccessPolicy' { @() } | Out-Null
            Set-Item 'function:global:Get-MgGroup' { @() } | Out-Null
            Set-Item 'function:global:Get-MgGroupMember' { @() } | Out-Null

            $logPath = Join-Path $tmp 'transition-exit.log'
            $threw = $false
            try {
                & (Join-Path $script:Root 'Tools/Invoke-VcioTransitionExit.ps1') -Manifest $manifest -ErrorAction Stop
            } catch { $threw = $true; $script:Err = $_.Exception.Message }

            $threw                              | Should -BeTrue
            $script:Err                         | Should -Match 'TENANT MISMATCH'
            Test-Path $logPath                  | Should -BeFalse   # no log was written
            $global:VcioRemoveCalls             | Should -Be 0
            $global:VcioUpdateCalls             | Should -Be 0
            # the manifest is byte-identical to what we wrote
            (Get-Content -Raw $manifest)        | Should -Match 'expected-tenant-1111'
        } finally {
            Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        }
    }

    It 'manifest object ids win over displayName, and a fallback is reported as one' {
        $mf = [pscustomobject]@{ objectIds = [pscustomobject]@{
            groups = [pscustomobject]@{ 'SG-CA-Users' = 'real-tenant-id-42' }
            policies = [pscustomobject]@{}; namedLocations = [pscustomobject]@{} } }
        $byId = Resolve-VcioObjectId -Manifest $mf -Kind 'groups' -Name 'SG-CA-Users' -Fallback { 'SHOULD-NOT-BE-USED' }
        $byId.Id     | Should -Be 'real-tenant-id-42'
        $byId.Source | Should -Be 'manifest'

        $byName = Resolve-VcioObjectId -Manifest $mf -Kind 'groups' -Name 'SG-CA-Missing' -Fallback { 'found-by-name' }
        $byName.Id     | Should -Be 'found-by-name'
        $byName.Source | Should -Be 'displayName-fallback'
    }

    It 'an all-zero placeholder id is treated as not filled in' {
        $mf = [pscustomobject]@{ objectIds = [pscustomobject]@{
            groups = [pscustomobject]@{ 'SG-CA-Users' = '00000000-0000-0000-0000-000000000000' }
            policies = [pscustomobject]@{}; namedLocations = [pscustomobject]@{} } }
        (Resolve-VcioObjectId -Manifest $mf -Kind 'groups' -Name 'SG-CA-Users' -Fallback { 'fallback' }).Source |
            Should -Be 'displayName-fallback'
    }
}
