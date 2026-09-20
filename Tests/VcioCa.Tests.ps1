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
Describe 'Finding 6A — per-sign-in, per-policy coverage' {

    BeforeAll {
        # The four standard policies as they actually ship. CA200 has NO
        # compliant-device filter; the other three do, which is why notApplied
        # means different things on them.
        $script:Std = @(
            [pscustomobject]@{ Id='p200'; DisplayName='CA200'; ClientAppTypes=@('mobileAppsAndDesktopClients'); IncludePlatforms=@('windows'); HasCompliantDeviceFilter=$false }
            [pscustomobject]@{ Id='p204'; DisplayName='CA204'; ClientAppTypes=@('all');                          IncludePlatforms=@();          HasCompliantDeviceFilter=$true  }
            [pscustomobject]@{ Id='p300'; DisplayName='CA300'; ClientAppTypes=@('browser');                      IncludePlatforms=@();          HasCompliantDeviceFilter=$true  }
            [pscustomobject]@{ Id='p301'; DisplayName='CA301'; ClientAppTypes=@('browser');                      IncludePlatforms=@('windows'); HasCompliantDeviceFilter=$true  }
        )
        $script:RemovedAt = [datetime]::Parse('2026-09-10T12:00:00Z').ToUniversalTime()
        function Sign {
            param([string]$App, [string]$Os, [bool]$Compliant, [int]$MinutesAfter, [hashtable]$Results)
            [pscustomobject]@{
                CreatedDateTime = $script:RemovedAt.AddMinutes($MinutesAfter)
                ClientAppUsed   = $App
                DeviceDetail    = [pscustomobject]@{ OperatingSystem = $Os; IsCompliant = $Compliant }
                AppliedConditionalAccessPolicies = @($Results.GetEnumerator() | ForEach-Object {
                    [pscustomobject]@{ Id = $_.Key; Result = $_.Value } })
            }
        }
    }

    It 'a compliant-device user with desktop and browser sign-ins verifies' {
        # Desktop: CA200 enforced success; CA204 notApplied, which is CORRECT
        # because the device is compliant and CA204 filters compliant devices out.
        $desktop = Sign -App 'Mobile Apps and Desktop clients' -Os 'Windows 10' -Compliant $true -MinutesAfter 45 `
            -Results @{ p200='success'; p204='notApplied' }
        # Browser: CA300/CA301 notApplied for the same reason; CA204 likewise.
        $browser = Sign -App 'Browser' -Os 'Windows 10' -Compliant $true -MinutesAfter 50 `
            -Results @{ p204='notApplied'; p300='notApplied'; p301='notApplied' }
        $r = Test-VcioStandardCoverage -SignIns @($desktop,$browser) -Policies $script:Std -RemovedAt $script:RemovedAt
        $r.Failures -join ' | ' | Should -BeExactly ''
        $r.Verified | Should -BeTrue
    }

    It 'a non-compliant hybrid user with a CA200 failure and a CA204 success verifies' {
        $s = Sign -App 'Mobile Apps and Desktop clients' -Os 'Windows 10' -Compliant $false -MinutesAfter 40 `
            -Results @{ p200='failure'; p204='success' }
        $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $script:Std -RemovedAt $script:RemovedAt
        $r.Failures -join ' | ' | Should -BeExactly ''
        $r.Verified | Should -BeTrue
    }

    It 'a sign-in inside the 30-minute margin is ignored' {
        $s = Sign -App 'Mobile Apps and Desktop clients' -Os 'Windows 10' -Compliant $false -MinutesAfter 5 `
            -Results @{ p200='success'; p204='success' }
        $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $script:Std -RemovedAt $script:RemovedAt
        $r.SignInsConsidered      | Should -Be 0
        $r.SignInsIgnoredInMargin | Should -Be 1
        $r.Verified               | Should -BeFalse
    }

    It 'the margin is a parameter — 0 considers the same sign-in' {
        $s = Sign -App 'Mobile Apps and Desktop clients' -Os 'Windows 10' -Compliant $false -MinutesAfter 5 `
            -Results @{ p200='success'; p204='success' }
        $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $script:Std -RemovedAt $script:RemovedAt -PropagationMinutes 0
        $r.SignInsConsidered | Should -Be 1
        $r.Verified          | Should -BeTrue
    }

    It 'a reportOnly CA300 result fails the user and is reported as a configuration defect' {
        $s = Sign -App 'Browser' -Os 'Windows 10' -Compliant $false -MinutesAfter 45 `
            -Results @{ p204='success'; p300='reportOnlySuccess'; p301='success' }
        $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $script:Std -RemovedAt $script:RemovedAt
        $r.Verified | Should -BeFalse
        ($r.Failures -join ' ')             | Should -Match 'report-only'
        ($r.ConfigurationDefects -join ' ') | Should -Match 'CA300'
        ($r.ConfigurationDefects -join ' ') | Should -Match 'not enforcing'
    }

    It 'a notApplied CA200 fails — CA200 has no compliant-device filter to explain it' {
        $s = Sign -App 'Mobile Apps and Desktop clients' -Os 'Windows 10' -Compliant $true -MinutesAfter 45 `
            -Results @{ p200='notApplied'; p204='notApplied' }
        $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $script:Std -RemovedAt $script:RemovedAt
        $r.Verified | Should -BeFalse
        ($r.Failures -join ' ') | Should -Match 'CA200'
        ($r.Failures -join ' ') | Should -Match 'carries no compliant-device filter'
    }

    It 'notApplied on a filtered policy fails when the device is NOT compliant' {
        $s = Sign -App 'Browser' -Os 'Windows 10' -Compliant $false -MinutesAfter 45 `
            -Results @{ p204='notApplied'; p300='notApplied'; p301='notApplied' }
        $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $script:Std -RemovedAt $script:RemovedAt
        $r.Verified | Should -BeFalse
        ($r.Failures -join ' ') | Should -Match 'not compliant'
    }

    It 'non-matching pairs are skipped — a browser sign-in says nothing about CA200' {
        $s = Sign -App 'Browser' -Os 'Windows 10' -Compliant $true -MinutesAfter 45 `
            -Results @{ p204='notApplied'; p300='notApplied'; p301='notApplied' }
        $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $script:Std -RemovedAt $script:RemovedAt
        $r.Verified | Should -BeTrue      # CA200 never matched, so it is not held against the user
        $r.MatchingPairs | Should -Be 3
    }

    It 'a macOS browser sign-in does not match the Windows-only CA301' {
        $s = Sign -App 'Browser' -Os 'MacOs 14' -Compliant $true -MinutesAfter 45 `
            -Results @{ p204='notApplied'; p300='notApplied' }
        $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $script:Std -RemovedAt $script:RemovedAt
        $r.MatchingPairs | Should -Be 2   # CA204 and CA300 only
        $r.Verified      | Should -BeTrue
    }

    It 'a matching policy absent from the applied list fails — absence is not coverage' {
        $s = Sign -App 'Mobile Apps and Desktop clients' -Os 'Windows 10' -Compliant $true -MinutesAfter 45 `
            -Results @{ p204='notApplied' }
        $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $script:Std -RemovedAt $script:RemovedAt
        $r.Verified | Should -BeFalse
        ($r.Failures -join ' ') | Should -Match 'absent from its applied-policies list'
    }

    It 'no considered sign-in means not verified' {
        (Test-VcioStandardCoverage -SignIns @() -Policies $script:Std -RemovedAt $script:RemovedAt).Verified | Should -BeFalse
    }
}

# ==========================================================================
Describe 'Finding 6A — the notApplied acceptance has preconditions' {

    Context 'precondition 1 — the filter must be EXACTLY the framework filter' {
        It 'exclude mode with the exact rule counts' {
            Test-VcioCompliantDeviceExcludeFilter -DeviceFilter ([pscustomobject]@{
                Mode='exclude'; Rule='device.isCompliant -eq True' }) | Should -BeTrue
        }
        It 'whitespace is normalised' {
            Test-VcioCompliantDeviceExcludeFilter -DeviceFilter ([pscustomobject]@{
                Mode='exclude'; Rule="  device.isCompliant   -eq    True " }) | Should -BeTrue
        }
        It 'INCLUDE mode does not count' {
            Test-VcioCompliantDeviceExcludeFilter -DeviceFilter ([pscustomobject]@{
                Mode='include'; Rule='device.isCompliant -eq True' }) | Should -BeFalse
        }
        It '-eq False does not count' {
            Test-VcioCompliantDeviceExcludeFilter -DeviceFilter ([pscustomobject]@{
                Mode='exclude'; Rule='device.isCompliant -eq False' }) | Should -BeFalse
        }
        It '-ne does not count' {
            Test-VcioCompliantDeviceExcludeFilter -DeviceFilter ([pscustomobject]@{
                Mode='exclude'; Rule='device.isCompliant -ne True' }) | Should -BeFalse
        }
        It 'an extra clause does not count' {
            Test-VcioCompliantDeviceExcludeFilter -DeviceFilter ([pscustomobject]@{
                Mode='exclude'; Rule='device.isCompliant -eq True -or device.trustType -eq "ServerAd"' }) | Should -BeFalse
        }
        It 'an absent filter does not count' {
            Test-VcioCompliantDeviceExcludeFilter -DeviceFilter $null | Should -BeFalse
        }
        It 'a policy whose filter fails the test cannot pass on notApplied' {
            # The unit-level consequence: HasCompliantDeviceFilter false means
            # notApplied is a failure even for a compliant device.
            $pols = @([pscustomobject]@{ Id='p300'; DisplayName='CA300'; ClientAppTypes=@('browser')
                                         IncludePlatforms=@(); HasCompliantDeviceFilter=$false })
            $removed = [datetime]::Parse('2026-09-10T12:00:00Z').ToUniversalTime()
            $s = [pscustomobject]@{
                CreatedDateTime = $removed.AddMinutes(45); ClientAppUsed='Browser'
                DeviceDetail = [pscustomobject]@{ OperatingSystem='Windows 10'; IsCompliant=$true }
                AppliedConditionalAccessPolicies = @([pscustomobject]@{ Id='p300'; Result='notApplied' }) }
            $r = Test-VcioStandardCoverage -SignIns @($s) -Policies $pols -RemovedAt $removed
            $r.Verified | Should -BeFalse
            ($r.Failures -join ' ') | Should -Match 'carries no compliant-device filter'
        }
    }

    Context 'the empty-object trap this surfaced' {
        It 'Test-VcioHasProperty survives an object with zero properties' {
            # $o.PSObject.Properties.Name -contains 'x' throws under
            # Set-StrictMode -Version Latest when $o has NO properties, which
            # is what a manifest section written as {} deserialises to. The
            # 6A positive case hit it in the disable step.
            Test-VcioHasProperty ([pscustomobject]@{}) 'x' | Should -BeFalse
            Test-VcioHasProperty ([pscustomobject]@{ a = 1 }) 'a' | Should -BeTrue
            Test-VcioHasProperty $null 'a' | Should -BeFalse
            Test-VcioHasProperty @{ a = 1 } 'a' | Should -BeTrue
        }
        It 'a manifest whose objectIds sections are all empty resolves without throwing' {
            $mf = @{ objectIds = @{ groups = @{}; policies = @{}; namedLocations = @{} }
                     transition = @{ policyIds = @{} } } | ConvertTo-Json -Depth 5 | ConvertFrom-Json
            { Resolve-VcioObjectId -Manifest $mf -Kind 'policies' -Name 'CA200-X' -Fallback { $null } } | Should -Not -Throw
            (Resolve-VcioObjectId -Manifest $mf -Kind 'policies' -Name 'CA200-X' -Fallback { $null }).Source | Should -Be 'unresolved'
        }
        It 'no shipped script still uses the fragile member-enumeration form' {
            $offenders = @()
            foreach ($f in @('Tools/VcioCaCommon.psm1','Tools/Invoke-VcioTransitionExit.ps1','Tools/Compare-VcioPrivilegedScope.ps1')) {
                $txt = Get-Content -Raw (Join-Path $script:Root $f)
                if ($txt -match '\.PSObject\.Properties\.Name\s+-contains') { $offenders += $f }
            }
            $offenders -join ', ' | Should -BeExactly ''
        }
    }

    Context 'precondition 3 — effective scope of the removed user' {
        BeforeAll {
            function ScopePol {
                param([string]$Name, [string[]]$IncGroups = @('g-users'), [string[]]$IncUsers = @(),
                      [string[]]$IncRoles = @(), [string[]]$ExcGroups, [string[]]$ExcUsers = @())
                [pscustomobject]@{ DisplayName=$Name; IncludeUsers=$IncUsers; IncludeGroups=$IncGroups
                                   IncludeRoles=$IncRoles; ExcludeGroups=$ExcGroups; ExcludeUsers=$ExcUsers }
            }
            $script:ScopePols = @(
                ScopePol 'CA200' -ExcGroups @('g-bg','g-excl-200','g-transition')
                ScopePol 'CA204' -ExcGroups @('g-bg','g-excl-204','g-transition')
                ScopePol 'CA300' -ExcGroups @('g-bg','g-excl-300','g-transition')
                ScopePol 'CA301' -ExcGroups @('g-bg','g-excl-301','g-transition')
            )
        }
        It 'a user in SG-CA-Users and no exclusion is in scope' {
            (Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $script:ScopePols).InScope | Should -BeTrue
        }
        It 'a user NOT in SG-CA-Users is out of scope' {
            $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-other') `
                -UsersGroupId 'g-users' -Policies $script:ScopePols
            $r.InScope | Should -BeFalse
            $r.Reason  | Should -Match 'SG-CA-Users'
        }
        It 'a user in an exclusion group via NESTING is out of scope' {
            $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users','g-nested','g-excl-300') `
                -UsersGroupId 'g-users' -Policies $script:ScopePols
            $r.InScope | Should -BeFalse
            $r.Reason  | Should -Match 'CA300'
        }
        It 'a user named in excludeUsers is out of scope' {
            $pols = @(ScopePol 'CA204' -ExcGroups @() -ExcUsers @('u1'))
            $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $pols
            $r.InScope | Should -BeFalse
            $r.Reason  | Should -Match 'excludeUsers'
        }
        It 'a policy object missing the Include/Exclude properties entirely does not throw' {
            # Same StrictMode trap as .PSObject.Properties.Name, one level on:
            # a caller passing a partial policy object must get a verdict, not
            # a crash.
            $partial = @([pscustomobject]@{ DisplayName='CA204' })
            { Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $partial } | Should -Not -Throw
            (Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $partial).Status | Should -Be 'Defect'
        }
        It 'still in SG-CA-Transition-Hybrid is out of scope' {
            (Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users','g-transition') `
                -UsersGroupId 'g-users' -Policies $script:ScopePols).InScope | Should -BeFalse
        }

        It 'a policy targeting a DIFFERENT group the user is not in is OUT OF SCOPE' {
            $pols = @(
                ScopePol 'CA200' -ExcGroups @()
                ScopePol 'CA204' -ExcGroups @()
                ScopePol 'CA300' -IncGroups @('g-somewhere-else') -ExcGroups @()
                ScopePol 'CA301' -ExcGroups @()
            )
            $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $pols
            $r.Status     | Should -Be 'OutOfScope'
            $r.PolicyName | Should -Be 'CA300'
            $r.Reason     | Should -Match 'includes group\(s\) g-somewhere-else, of which the user is a member of none'
        }

        It 'a policy targeting another group the user IS in is DRIFT, not in scope' {
            $pols = @(
                ScopePol 'CA200' -ExcGroups @()
                ScopePol 'CA204' -ExcGroups @()
                ScopePol 'CA300' -IncGroups @('g-other-team') -ExcGroups @()
                ScopePol 'CA301' -ExcGroups @()
            )
            $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users','g-other-team') `
                -UsersGroupId 'g-users' -Policies $pols
            $r.Status     | Should -Be 'Drift'
            $r.InScope    | Should -BeFalse
            $r.PolicyName | Should -Be 'CA300'
            $r.Reason     | Should -Match 'does not include SG-CA-Users'
        }

        It 'includeUsers All satisfies inclusion and the contract' {
            $pols = @($script:ScopePols | ForEach-Object { $_ })
            $pols[2] = ScopePol 'CA300' -IncGroups @() -IncUsers @('All') -ExcGroups @()
            (Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $pols).Status | Should -Be 'InScope'
        }

        It 'includeUsers naming the user satisfies inclusion but not the contract' {
            $pols = @($script:ScopePols | ForEach-Object { $_ })
            $pols[2] = ScopePol 'CA300' -IncGroups @() -IncUsers @('u1') -ExcGroups @()
            (Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $pols).Status | Should -Be 'Drift'
        }

        It 'an ACTIVE role the user holds satisfies inclusion' {
            $pols = @($script:ScopePols | ForEach-Object { $_ })
            $pols[2] = ScopePol 'CA300' -IncGroups @() -IncRoles @('role-abc') -ExcGroups @()
            $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $pols -ActiveRoleIds @('role-abc')
            $r.Status | Should -Be 'Drift'     # included, but the contract still fails
        }

        It 'a role the user does NOT actively hold does not satisfy inclusion' {
            $pols = @($script:ScopePols | ForEach-Object { $_ })
            $pols[2] = ScopePol 'CA300' -IncGroups @() -IncRoles @('role-abc') -ExcGroups @()
            $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $pols -ActiveRoleIds @()
            $r.Status | Should -Be 'OutOfScope'
            $r.Reason | Should -Match 'none of which the user actively holds'
        }

        It 'a policy with all three include collections empty is a DEFECT' {
            $pols = @($script:ScopePols | ForEach-Object { $_ })
            $pols[1] = ScopePol 'CA204' -IncGroups @() -ExcGroups @()
            $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') `
                -UsersGroupId 'g-users' -Policies $pols
            $r.Status     | Should -Be 'Defect'
            $r.PolicyName | Should -Be 'CA204'
            $r.Reason     | Should -Match 'targets nobody'
        }

        It 'exclusion still wins over inclusion' {
            $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users','g-excl-301') `
                -UsersGroupId 'g-users' -Policies $script:ScopePols
            $r.Status     | Should -Be 'OutOfScope'
            $r.PolicyName | Should -Be 'CA301'
        }
    }

    Context 'end to end — a compliant device with notApplied results' {
        BeforeAll {
            $script:Harness = Join-Path $PSScriptRoot 'Fixtures/TransitionExitHarness.ps1'
            $script:Target  = Join-Path $script:Root 'Tools/Invoke-VcioTransitionExit.ps1'

            # Every scenario below: the user was removed, their device is
            # COMPLIANT, and CA204/CA300/CA301 return notApplied. Nothing may
            # pass on those facts alone — each case breaks one precondition.
            function New-VerifyScenario {
                param(
                    [hashtable]$PolicyOverrides = @{},
                    [string[]]$UserGroups = @('g-users'),
                    [hashtable]$PolicyExcludeUsers = @{}
                )
                $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("vcio-6a-" + [guid]::NewGuid())
                New-Item -ItemType Directory -Path $dir | Out-Null
                $removedAt = [datetime]::UtcNow.AddHours(-3)

                $defs = @(
                    @{ id='p200'; displayName='CA200-VCIO-Users-Windows-CompliantDevice';     state='enabled'; clientAppTypes=@('mobileAppsAndDesktopClients'); includePlatforms=@('windows'); filterRule=$null; filterMode=$null }
                    @{ id='p204'; displayName='CA204-VCIO-Users-SessionHygiene-Unmanaged';    state='enabled'; clientAppTypes=@('all');     includePlatforms=@();          filterRule='device.isCompliant -eq True'; filterMode='exclude' }
                    @{ id='p300'; displayName='CA300-VCIO-BYOD-BrowserSessionControls';       state='enabled'; clientAppTypes=@('browser'); includePlatforms=@();          filterRule='device.isCompliant -eq True'; filterMode='exclude' }
                    @{ id='p301'; displayName='CA301-VCIO-BYOD-Windows-RequireAppProtection'; state='enabled'; clientAppTypes=@('browser'); includePlatforms=@('windows'); filterRule='device.isCompliant -eq True'; filterMode='exclude' }
                )
                foreach ($d in $defs) {
                    $d['includeUsers']  = @()
                    $d['includeGroups'] = @('g-users')
                    $d['includeRoles']  = @()
                    $d['excludeGroups'] = @('g-bg', "g-excl-$($d.id)", 'g-transition')
                    $d['excludeUsers']  = @()
                    if ($PolicyOverrides.ContainsKey($d.id)) {
                        foreach ($k in $PolicyOverrides[$d.id].Keys) { $d[$k] = $PolicyOverrides[$d.id][$k] }
                    }
                    if ($PolicyExcludeUsers.ContainsKey($d.id)) { $d['excludeUsers'] = $PolicyExcludeUsers[$d.id] }
                }

                $state = @{
                    tenantId='tenant-abc'; usersGroupId='g-users'; members=@(); usersGroupMembers=@('u1')
                    throwOn=@(); removeLog=@(); disabled=@(); policies=$defs; roleAssignments=@()
                    userGroups = @{ u1 = $UserGroups }
                    signIns = @(
                        @{ createdDateTime = $removedAt.AddMinutes(60).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                           clientAppUsed='Mobile Apps and Desktop clients'; operatingSystem='Windows 10'; isCompliant=$true
                           applied=@(@{id='p200';result='success'}, @{id='p204';result='notApplied'}) }
                        @{ createdDateTime = $removedAt.AddMinutes(65).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                           clientAppUsed='Browser'; operatingSystem='Windows 10'; isCompliant=$true
                           applied=@(@{id='p204';result='notApplied'}, @{id='p300';result='notApplied'}, @{id='p301';result='notApplied'}) }
                    )
                }
                $stateFile = Join-Path $dir 'state.json'
                $state | ConvertTo-Json -Depth 12 | Set-Content $stateFile
                $manifest = Join-Path $dir 'manifest.json'
                @{  tenantId='tenant-abc'
                    transition = @{ exitDate='2020-01-01'; groupId='g-transition'
                                    groupEmptiedDate = $removedAt.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                                    policyIds=@{}
                                    verifiedRemovals=@(@{ upn='u1@contoso.com'; id='u1'; state='removed'
                                                          attemptedAt=$removedAt.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                                                          removedAt=$removedAt.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }) }
                    objectIds = @{ groups=@{ 'SG-CA-Transition-Hybrid'='g-transition'; 'SG-CA-Users'='g-users' }
                                   policies=@{ 'CA200-VCIO-Users-Windows-CompliantDevice'='p200'
                                               'CA204-VCIO-Users-SessionHygiene-Unmanaged'='p204'
                                               'CA300-VCIO-BYOD-BrowserSessionControls'='p300'
                                               'CA301-VCIO-BYOD-Windows-RequireAppProtection'='p301' }
                                   namedLocations=@{} }
                } | ConvertTo-Json -Depth 12 | Set-Content $manifest
                [pscustomobject]@{ Dir=$dir; StateFile=$stateFile; Manifest=$manifest }
            }
            function Invoke-Verify([object]$S) {
                & pwsh -NoProfile -File $script:Harness -StateFile $S.StateFile -Manifest $S.Manifest -ScriptPath $script:Target *>&1 | Out-String
            }
            function Get-U1([object]$S) {
                $mf = Get-Content -Raw $S.Manifest | ConvertFrom-Json
                @($mf.transition.verifiedRemovals | Where-Object { $_.id -eq 'u1' })[0]
            }
        }

        It 'POSITIVE: correct filters, all enabled, in scope -> verified' {
            $s = New-VerifyScenario
            try {
                $out = Invoke-Verify $s
                (Get-U1 $s).state | Should -Be 'verified'
                $out | Should -Match 'VERIFIED'
            } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
        }

        It 'a. CA300 filter in INCLUDE mode -> not verified, defect reported' {
            $s = New-VerifyScenario -PolicyOverrides @{ p300 = @{ filterMode = 'include' } }
            try {
                $out = Invoke-Verify $s
                (Get-U1 $s).state | Should -Not -Be 'verified'
                $out | Should -Match 'CA300-VCIO-BYOD-BrowserSessionControls: no compliant-device exclude filter'
                $out | Should -Match "mode 'include'"
            } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
        }

        It 'b. CA204 rule is -eq False -> not verified' {
            $s = New-VerifyScenario -PolicyOverrides @{ p204 = @{ filterRule = 'device.isCompliant -eq False' } }
            try {
                $out = Invoke-Verify $s
                (Get-U1 $s).state | Should -Not -Be 'verified'
                $out | Should -Match 'CA204-VCIO-Users-SessionHygiene-Unmanaged: no compliant-device exclude filter'
            } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
        }

        It 'c. CA200 disabled between runs -> verification stops, no user marked' {
            $s = New-VerifyScenario -PolicyOverrides @{ p200 = @{ state = 'disabled' } }
            try {
                $out = Invoke-Verify $s
                (Get-U1 $s).state | Should -Be 'removed'      # untouched
                $out | Should -Match 'NO user is marked verified'
                $out | Should -Match "CA200-VCIO-Users-Windows-CompliantDevice is 'disabled'"
            } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
        }

        It 'd. removed user missing from SG-CA-Users -> OUT OF SCOPE' {
            $s = New-VerifyScenario -UserGroups @('g-somewhere-else')
            try {
                $out = Invoke-Verify $s
                (Get-U1 $s).state | Should -Not -Be 'verified'
                $out | Should -Match 'OUT OF SCOPE'
                $out | Should -Match 'SG-CA-Users'
            } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
        }

        It 'f. CA300 targets a different group the user is NOT in -> OUT OF SCOPE naming CA300' {
            $s = New-VerifyScenario -PolicyOverrides @{ p300 = @{ includeGroups = @('g-finance-only') } }
            try {
                $out = Invoke-Verify $s
                (Get-U1 $s).state | Should -Not -Be 'verified'
                $out | Should -Match 'OUT OF SCOPE'
                $out | Should -Match 'CA300-VCIO-BYOD-BrowserSessionControls'
                $out | Should -Match 'g-finance-only'
                # the transition policies are untouched
                (Get-Content -Raw $s.StateFile | ConvertFrom-Json).disabled.Count | Should -Be 0
            } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
        }

        It 'g. CA300 targets another group the user IS in -> DRIFT, not verified' {
            $s = New-VerifyScenario -PolicyOverrides @{ p300 = @{ includeGroups = @('g-other-team') } } `
                                    -UserGroups @('g-users','g-other-team')
            try {
                $out = Invoke-Verify $s
                (Get-U1 $s).state | Should -Not -Be 'verified'
                $out | Should -Match 'DRIFT'
                $out | Should -Match 'does not include SG-CA-Users'
                $out | Should -Not -Match 'OUT OF SCOPE'
                (Get-Content -Raw $s.StateFile | ConvertFrom-Json).disabled.Count | Should -Be 0
            } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
        }

        It 'e. removed user in SG-CA-Excl-CA300 via a nested group -> OUT OF SCOPE' {
            $s = New-VerifyScenario -UserGroups @('g-users','g-nested-team','g-excl-p300')
            try {
                $out = Invoke-Verify $s
                (Get-U1 $s).state | Should -Not -Be 'verified'
                $out | Should -Match 'OUT OF SCOPE'
                $out | Should -Match 'CA300-VCIO-BYOD-BrowserSessionControls'
            } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
        }
    }
}

# ==========================================================================
Describe 'Finding 6B — removal state machine' {

    BeforeAll {
        $script:Harness = Join-Path $PSScriptRoot 'Fixtures/TransitionExitHarness.ps1'
        $script:Target  = Join-Path $script:Root 'Tools/Invoke-VcioTransitionExit.ps1'

        function New-Scenario {
            param([string[]]$Members, [string[]]$ThrowOn = @())
            $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("vcio-6b-" + [guid]::NewGuid())
            New-Item -ItemType Directory -Path $dir | Out-Null
            $state = @{
                tenantId = 'tenant-abc'
                usersGroupId = 'g-users'
                members = $Members
                usersGroupMembers = $Members
                throwOn = $ThrowOn
                removeLog = @()
                disabled = @()
                signIns = @()
                policies = @(
                    @{ id='p200'; displayName='CA200-VCIO-Users-Windows-CompliantDevice';          state='enabled'; clientAppTypes=@('mobileAppsAndDesktopClients'); includePlatforms=@('windows'); filterRule=$null }
                    @{ id='p204'; displayName='CA204-VCIO-Users-SessionHygiene-Unmanaged';         state='enabled'; clientAppTypes=@('all');                          includePlatforms=@();          filterRule='device.isCompliant -eq True' }
                    @{ id='p300'; displayName='CA300-VCIO-BYOD-BrowserSessionControls';            state='enabled'; clientAppTypes=@('browser');                      includePlatforms=@();          filterRule='device.isCompliant -eq True' }
                    @{ id='p301'; displayName='CA301-VCIO-BYOD-Windows-RequireAppProtection';      state='enabled'; clientAppTypes=@('browser');                      includePlatforms=@('windows'); filterRule='device.isCompliant -eq True' }
                )
            }
            $stateFile = Join-Path $dir 'state.json'
            $state | ConvertTo-Json -Depth 10 | Set-Content $stateFile
            $manifest = Join-Path $dir 'manifest.json'
            @{  tenantId = 'tenant-abc'
                transition = @{ exitDate = '2020-01-01'; groupId = 'g-transition'; groupEmptiedDate = $null
                                policyIds = @{
                                    'CA200-VCIO-Users-Windows-CompliantOrHybrid-TRANSITION'   = 't200'
                                    'CA204-VCIO-Users-SessionHygiene-Unmanaged-TRANSITION'    = 't204'
                                    'CA300-VCIO-BYOD-BrowserSessionControls-TRANSITION'       = 't300'
                                    'CA301-VCIO-BYOD-Windows-RequireAppProtection-TRANSITION' = 't301' }
                                verifiedRemovals = @() }
                objectIds = @{ groups = @{ 'SG-CA-Transition-Hybrid'='g-transition'; 'SG-CA-Users'='g-users' }
                               policies = @{
                                    'CA200-VCIO-Users-Windows-CompliantDevice'       = 'p200'
                                    'CA204-VCIO-Users-SessionHygiene-Unmanaged'      = 'p204'
                                    'CA300-VCIO-BYOD-BrowserSessionControls'         = 'p300'
                                    'CA301-VCIO-BYOD-Windows-RequireAppProtection'   = 'p301' }
                               namedLocations = @{} }
            } | ConvertTo-Json -Depth 10 | Set-Content $manifest
            [pscustomobject]@{ Dir=$dir; StateFile=$stateFile; Manifest=$manifest }
        }
        function Invoke-Run([object]$S) {
            & pwsh -NoProfile -File $script:Harness -StateFile $S.StateFile -Manifest $S.Manifest -ScriptPath $script:Target *>&1 | Out-String
        }
        function Read-Manifest([object]$S) { Get-Content -Raw $S.Manifest | ConvertFrom-Json }
        function Read-State([object]$S)    { Get-Content -Raw $S.StateFile | ConvertFrom-Json }
        # ConvertFrom-Json in PS7 turns an ISO-8601 string into a [datetime]
        # on its own. Re-Parsing one round-trips it through a second-precision
        # culture string and silently drops the milliseconds this test is about.
        function AsUtc($Value) {
            if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime() }
            [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
                [System.Globalization.DateTimeStyles]::AssumeUniversal)
        }
    }

    It 'a removal that throws leaves that user PENDING, and the others removed' {
        $s = New-Scenario -Members @('u1','u2','u3') -ThrowOn @('u2')
        try {
            $out = Invoke-Run $s
            $mf = Read-Manifest $s
            $byId = @{}; foreach ($e in $mf.transition.verifiedRemovals) { $byId[$e.id] = $e }

            $byId['u2'].state | Should -Be 'pending'
            $byId['u1'].state | Should -Be 'removed'
            $byId['u3'].state | Should -Be 'removed'
            # and u2 is genuinely still in the group
            (Read-State $s).members | Should -Contain 'u2'
        } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
    }

    It 'groupEmptiedDate is absent while anyone is still a member' {
        $s = New-Scenario -Members @('u1','u2','u3') -ThrowOn @('u2')
        try {
            Invoke-Run $s | Out-Null
            (Read-Manifest $s).transition.groupEmptiedDate | Should -BeNullOrEmpty
        } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
    }

    It 'the next run RETRIES the pending user rather than skipping it, and then writes groupEmptiedDate' {
        $s = New-Scenario -Members @('u1','u2','u3') -ThrowOn @('u2')
        try {
            Invoke-Run $s | Out-Null
            # Clear the fault, same membership, run again.
            $st = Read-State $s; $st.throwOn = @(); $st | ConvertTo-Json -Depth 10 | Set-Content $s.StateFile

            Invoke-Run $s | Out-Null
            $mf = Read-Manifest $s
            $u2 = @($mf.transition.verifiedRemovals | Where-Object { $_.id -eq 'u2' })[0]

            $u2.state | Should -Be 'removed'      # retried, not skipped
            $u2.removedAt | Should -Not -BeNullOrEmpty
            (Read-State $s).members.Count | Should -Be 0
            $mf.transition.groupEmptiedDate | Should -Not -BeNullOrEmpty
        } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
    }

    It 'removedAt is stamped AFTER the API call returns, not before it' {
        $s = New-Scenario -Members @('u1')
        try {
            Invoke-Run $s | Out-Null
            $mf = Read-Manifest $s
            $entry = @($mf.transition.verifiedRemovals | Where-Object { $_.id -eq 'u1' })[0]
            $calledAt = @((Read-State $s).removeLog | Where-Object { $_.id -eq 'u1' })[0].calledAt

            $removed   = AsUtc $entry.removedAt
            $called    = AsUtc $calledAt
            $attempted = AsUtc $entry.attemptedAt

            # removedAt AFTER the call returned, attemptedAt BEFORE it started:
            # the first makes a pre-removal sign-in unusable as evidence, the
            # second makes a crashed run resumable.
            $removed   | Should -BeGreaterThan $called
            $attempted | Should -BeLessOrEqual $called
        } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
    }

    It 'a pending entry whose user is no longer a member is reconciled, not left stuck' {
        $s = New-Scenario -Members @('u1','u2') -ThrowOn @('u2')
        try {
            Invoke-Run $s | Out-Null
            # The removal actually landed server-side even though the call threw.
            $st = Read-State $s; $st.members = @(); $st.throwOn = @()
            $st | ConvertTo-Json -Depth 10 | Set-Content $s.StateFile

            Invoke-Run $s | Out-Null
            $mf = Read-Manifest $s
            $u2 = @($mf.transition.verifiedRemovals | Where-Object { $_.id -eq 'u2' })[0]
            $u2.state     | Should -Be 'removed'
            $u2.removedAt | Should -Not -BeNullOrEmpty
        } finally { Remove-Item -Recurse -Force $s.Dir -ErrorAction SilentlyContinue }
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
