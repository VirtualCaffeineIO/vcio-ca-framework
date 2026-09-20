<#
    StrictMode hardening sweep.

    Three traps have now been found in this module by accident, all of the same
    family and all invisible until a particular data shape showed up:

      - $o.PSObject.Properties.Name -contains 'x'  throws when $o has ZERO
        properties (a manifest section written as {}),
      - $o.Prop                                     throws when the property is
        absent (a partial policy object),
      - a function returning @(...) has it UNROLLED, so a one-element result
        arrives as a bare scalar and .Count / += then fail.

    Finding them one at a time as tenant-shaped data happens to expose them is
    not a strategy. This file sweeps every exported function that takes a
    policy, group, user or sign-in object and calls it under
    Set-StrictMode -Version Latest with (a) an empty [pscustomobject]@{} in
    every object slot and (b) single-element results from every helper it
    calls, asserting that no PropertyNotFoundException and no Count/op_Addition
    failure escapes.

    A function is allowed to THROW deliberately — Assert-VcioTenantContext
    does, by design. What it may not do is fall over on the shape of the data.
#>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $script:Root 'Tools/VcioCaCommon.psm1') -Force

    foreach ($kv in @{
        'Get-MgContext'         = { }
        'Invoke-MgGraphRequest' = { param($Method, $Uri, $Body, $ContentType, $ErrorAction) }
        'Search-AzGraph'        = { param($Query, $First, $Skip, $SkipToken) }
    }.GetEnumerator()) {
        if (-not (Get-Command $kv.Key -ErrorAction SilentlyContinue)) {
            Set-Item "function:global:$($kv.Key)" $kv.Value | Out-Null
        }
    }

    # The failure signatures this sweep exists to catch. A deliberate throw is
    # fine; one of these is not.
    $script:StrictSignatures = @(
        "cannot be found on this object",      # PropertyNotFoundException text
        "op_Addition",                          # += on an unrolled scalar
        "does not contain a method named",      # ditto, other phrasing
        "Cannot index into a null array"
    )

    function Test-StrictFailure {
        <#.SYNOPSIS Run a scriptblock; report only StrictMode-shape failures.#>
        param([Parameter(Mandatory)][scriptblock]$Script)
        Set-StrictMode -Version Latest
        $threw = $null
        try { $null = & $Script } catch { $threw = $_ }
        if (-not $threw) { return [pscustomobject]@{ Failed = $false; Message = '' } }

        $msg  = [string]$threw.Exception.Message
        $type = $threw.Exception.GetType().Name
        $isStrict = ($type -eq 'PropertyNotFoundException')
        foreach ($sig in $script:StrictSignatures) {
            if ($msg -like "*$sig*") { $isStrict = $true }
        }
        [pscustomobject]@{ Failed = $isStrict; Message = "$type : $msg" }
    }
}

# Case tables live at file scope: Pester evaluates -ForEach during
# discovery, which happens before BeforeAll runs.
# ---- case (a): an empty object in every object slot -------------------
$script:EmptyObjectCases = @(
    @{ Name = 'Get-VcioNamedLocationRanges';           Call = { Get-VcioNamedLocationRanges -NamedLocation ([pscustomobject]@{}) } }
    @{ Name = 'Get-VcioSignInClientCategory';          Call = { Get-VcioSignInClientCategory -SignIn ([pscustomobject]@{}) } }
    @{ Name = 'Get-VcioSignInPlatform';                Call = { Get-VcioSignInPlatform -SignIn ([pscustomobject]@{}) } }
    @{ Name = 'Resolve-VcioObjectId';                  Call = { Resolve-VcioObjectId -Manifest ([pscustomobject]@{}) -Kind 'groups' -Name 'x' -Fallback { $null } } }
    @{ Name = 'Test-VcioCompliantDeviceExcludeFilter'; Call = { Test-VcioCompliantDeviceExcludeFilter -DeviceFilter ([pscustomobject]@{}) } }
    @{ Name = 'Test-VcioHasProperty';                  Call = { Test-VcioHasProperty ([pscustomobject]@{}) 'x' } }
    @{ Name = 'Get-VcioProp';                          Call = { Get-VcioProp ([pscustomobject]@{}) 'x' } }
    @{ Name = 'Get-VcioPropCollection';                Call = { @(Get-VcioPropCollection ([pscustomobject]@{}) 'x').Count } }
    @{ Name = 'Test-VcioIpInRange';                    Call = { Test-VcioIpInRange -IpAddress '10.0.0.1' -Range ([pscustomobject]@{}) } }
    @{ Name = 'Test-VcioPermanentRoleAssignment';      Call = { Test-VcioPermanentRoleAssignment -PrincipalId 'u1' -ScheduleInstances ([pscustomobject]@{}) } }
    @{ Name = 'Test-VcioPrincipalInPolicyScope';       Call = { Test-VcioPrincipalInPolicyScope -PrincipalId 'u1' -PolicyUsers ([pscustomobject]@{}) -TransitiveGroupIds @('g1') } }
    @{ Name = 'Test-VcioSignInsWithinFence';           Call = { Test-VcioSignInsWithinFence -SignIns ([pscustomobject]@{}) -Cidrs @('10.0.0.0/8') } }
    @{ Name = 'Test-VcioStandardCoverage';             Call = { Test-VcioStandardCoverage -SignIns ([pscustomobject]@{}) -Policies ([pscustomobject]@{}) -RemovedAt ([datetime]'2026-01-01Z') } }
    @{ Name = 'Test-VcioUserInStandardScope';          Call = { Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g1') -UsersGroupId 'g1' -Policies ([pscustomobject]@{}) } }
    # An empty SignIns object short-circuits before the policy loop, so this
    # case drives a VALID sign-in against an EMPTY policy object — otherwise
    # the policy-reading half of the function is never reached.
    @{ Name = 'Test-VcioStandardCoverage (empty policy, real sign-in)'; Call = {
            Test-VcioStandardCoverage -RemovedAt ([datetime]'2026-01-01Z') -Policies ([pscustomobject]@{}) `
                -SignIns @([pscustomobject]@{ CreatedDateTime = [datetime]'2026-01-02Z'; ClientAppUsed = 'Browser'
                                              DeviceDetail = [pscustomobject]@{ OperatingSystem = 'Windows 10'; IsCompliant = $true }
                                              AppliedConditionalAccessPolicies = @([pscustomobject]@{ Id = 'p1'; Result = 'success' }) }) } }
    @{ Name = 'Get-VcioPolicyName';                    Call = { Get-VcioPolicyName ([pscustomobject]@{}) } }
)

# ---- case (b): one-element results from every helper ------------------
# A single element is the shape that unrolling turns into a scalar.
$script:SingleElementCases = @(
    @{ Name = 'Get-VcioNamedLocationRanges';           Call = { Get-VcioNamedLocationRanges -NamedLocation ([pscustomobject]@{ IpRanges = @([pscustomobject]@{ CidrAddress = '10.0.0.0/8' }) }) } }
    @{ Name = 'Get-VcioNamedLocationRanges (nested)';  Call = { Get-VcioNamedLocationRanges -NamedLocation ([pscustomobject]@{ AdditionalProperties = @{ ipRanges = @(@{ cidrAddress = '10.0.0.0/8' }) } }) } }
    @{ Name = 'Test-VcioIpInRanges';                   Call = { Test-VcioIpInRanges -IpAddress '10.0.0.1' -Cidrs @('10.0.0.0/8') } }
    @{ Name = 'Test-VcioPermanentRoleAssignment';      Call = { Test-VcioPermanentRoleAssignment -PrincipalId 'u1' -ScheduleInstances @([pscustomobject]@{ PrincipalId = 'u1'; AssignmentType = 'Assigned'; EndDateTime = $null }) } }
    @{ Name = 'Test-VcioPrincipalInPolicyScope';       Call = { Test-VcioPrincipalInPolicyScope -PrincipalId 'u1' -PolicyUsers ([pscustomobject]@{ IncludeGroups = @('g1'); ExcludeGroups = @('g2'); IncludeUsers = @('u9'); ExcludeUsers = @('u8') }) -TransitiveGroupIds @('g1') } }
    @{ Name = 'Test-VcioSignInsWithinFence';           Call = { Test-VcioSignInsWithinFence -SignIns @([pscustomobject]@{ IpAddress = '10.0.0.1'; Status = [pscustomobject]@{ ErrorCode = 0 } }) -Cidrs @('10.0.0.0/8') } }
    @{ Name = 'Test-VcioStandardCoverage';             Call = {
            Test-VcioStandardCoverage -RemovedAt ([datetime]'2026-01-01Z') `
                -SignIns @([pscustomobject]@{ CreatedDateTime = [datetime]'2026-01-02Z'; ClientAppUsed = 'Browser'
                                              DeviceDetail = [pscustomobject]@{ OperatingSystem = 'Windows 10'; IsCompliant = $true }
                                              AppliedConditionalAccessPolicies = @([pscustomobject]@{ Id = 'p1'; Result = 'success' }) }) `
                -Policies @([pscustomobject]@{ Id = 'p1'; DisplayName = 'CA300'; ClientAppTypes = @('browser')
                                               IncludePlatforms = @('windows'); HasCompliantDeviceFilter = $true }) } }
    @{ Name = 'Test-VcioUserInStandardScope';          Call = {
            Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g-users') -UsersGroupId 'g-users' -ActiveRoleIds @('r1') `
                -Policies @([pscustomobject]@{ DisplayName = 'CA300'; IncludeUsers = @(); IncludeGroups = @('g-users')
                                               IncludeRoles = @(); ExcludeUsers = @('u9'); ExcludeGroups = @('g-x') }) } }
    @{ Name = 'Resolve-VcioObjectId';                  Call = {
            Resolve-VcioObjectId -Kind 'policies' -Name 'CA200' -Fallback { 'fb' } `
                -Manifest ([pscustomobject]@{ objectIds = [pscustomobject]@{ policies = [pscustomobject]@{ CA200 = 'id-1' } }
                                              transition = [pscustomobject]@{ policyIds = [pscustomobject]@{ CA200 = 'id-2' } } }) } }
    @{ Name = 'Get-VcioGraphCollection (1 item)';      Call = {
            Mock Invoke-MgGraphRequest { @{ value = @(@{ id = 'only' }) } } -ModuleName VcioCaCommon
            Get-VcioGraphCollection -Uri 'https://graph/x' } }
    @{ Name = 'Get-VcioGraphCollection (bare value)';  Call = {
            # value that is NOT an array — the unrolled shape
            Mock Invoke-MgGraphRequest { @{ value = @{ id = 'bare' } } } -ModuleName VcioCaCommon
            Get-VcioGraphCollection -Uri 'https://graph/x' } }
    @{ Name = 'Invoke-VcioAzGraphQuery (1 row)';       Call = {
            Mock Search-AzGraph { if ($Skip) { @() } else { [pscustomobject]@{ id = 'only' } } } -ModuleName VcioCaCommon
            Invoke-VcioAzGraphQuery -Query 'x' } }
    @{ Name = 'Assert-VcioTenantContext (match)';      Call = {
            Mock Get-MgContext { [pscustomobject]@{ TenantId = 't1' } } -ModuleName VcioCaCommon
            Assert-VcioTenantContext -ExpectedTenantId 't1' } }
    @{ Name = 'Assert-VcioTenantContext (empty ctx)';  Call = {
            Mock Get-MgContext { [pscustomobject]@{} } -ModuleName VcioCaCommon
            Assert-VcioTenantContext -ExpectedTenantId 't1' } }
)

Describe 'StrictMode sweep — case (a): an empty object in every slot' {
    It '<Name> survives [pscustomobject]@{}' -ForEach $script:EmptyObjectCases {
        $r = Test-StrictFailure -Script $Call
        $r.Message | Should -BeExactly '' -Because "it must not fail on the shape of the data: $($r.Message)"
        $r.Failed  | Should -BeFalse
    }
}

Describe 'StrictMode sweep — case (b): single-element helper results' {
    It '<Name> survives a one-element result' -ForEach $script:SingleElementCases {
        $r = Test-StrictFailure -Script $Call
        $r.Failed | Should -BeFalse -Because "a one-element result must not unroll into a scalar: $($r.Message)"
    }
}

Describe 'StrictMode sweep — case (a) yields the FAIL-SAFE verdict' {
    # "No exception" is not the bar. A missing property must not resolve to a
    # PASSING verdict — that would be worse than the crash it replaced, because
    # a crash is visible and a false pass is not. Each assertion below pins the
    # specific verdict and names the direction it pushes the caller in.

    It '1 Test-VcioIpInRange: a malformed range is NOT-INSIDE, so a success from it reads as outside the fence' {
        # $false = not inside. Test-VcioSignInsWithinFence then treats a
        # successful sign-in from that IP as OutsideSuccess (FAIL) or, if the
        # IP will not parse, UNVERIFIED. Never as evidence the fence held.
        Test-VcioIpInRange -IpAddress '10.0.0.1' -Range ([pscustomobject]@{}) | Should -BeFalse
    }

    It '2 Test-VcioPermanentRoleAssignment: a partial instance is NOT a standing assignment' {
        # Pass=$false -> the Ring 1 / SwitchReadiness break-glass check emits
        # FAIL for that member. Break-glass is never assumed to hold GA.
        $r = Test-VcioPermanentRoleAssignment -PrincipalId 'u1' -ScheduleInstances ([pscustomobject]@{})
        $r.Pass   | Should -BeFalse
        $r.Reason | Should -Match 'No Global Administrator assignment of any kind'
    }

    It '3 Test-VcioPrincipalInPolicyScope: an empty users block means the policy does NOT reach the account' {
        # InScope=$false -> B3a reports "fence does not reach this account",
        # which is a FAIL by name. A service account is never assumed fenced.
        $r = Test-VcioPrincipalInPolicyScope -PrincipalId 'u1' -PolicyUsers ([pscustomobject]@{}) -TransitiveGroupIds @('g1')
        $r.InScope | Should -BeFalse
        $r.Reason  | Should -Match 'in none of the policy'
    }

    It '4 Test-VcioUserInStandardScope: a policy with no targeting is a DEFECT, not a pass' {
        # Status=Defect, InScope=$false -> the transition exit reports a
        # CONFIGURATION DEFECT and the user is never marked verified.
        $r = Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g1') -UsersGroupId 'g1' -Policies ([pscustomobject]@{})
        $r.Status  | Should -Be 'Defect'
        $r.InScope | Should -BeFalse
        $r.Reason  | Should -Match 'targets nobody'
    }

    It '5 Assert-VcioTenantContext: a context with no TenantId REFUSES to run' {
        # A deliberate throw, before any read or write. The alternative — a
        # $null TenantId comparing equal to a $null manifest value — would have
        # silently approved an unverified tenant.
        Mock Get-MgContext { [pscustomobject]@{} } -ModuleName VcioCaCommon
        { Assert-VcioTenantContext -ExpectedTenantId 't1' } | Should -Throw '*carries no TenantId*'
    }

    It '6 Test-VcioStandardCoverage: an untargetable policy leaves the user UNVERIFIED' {
        # Verified=$false -> the user stays unverified and the transition
        # policies stay enabled, which is the safe state.
        $sign = [pscustomobject]@{ CreatedDateTime = [datetime]'2026-01-02Z'; ClientAppUsed = 'Browser'
            DeviceDetail = [pscustomobject]@{ OperatingSystem = 'Windows 10'; IsCompliant = $true }
            AppliedConditionalAccessPolicies = @([pscustomobject]@{ Id = 'p1'; Result = 'success' }) }
        $r = Test-VcioStandardCoverage -SignIns @($sign) -Policies ([pscustomobject]@{}) -RemovedAt ([datetime]'2026-01-01Z')
        $r.Verified | Should -BeFalse
        ($r.Failures -join ' ') | Should -Match 'absent from its applied-policies list'
    }

    It 'no empty-object case resolves to a passing verdict' {
        # The blanket statement the six assertions above make individually.
        # If a future change makes any of these return a pass, this fails even
        # if the specific message above was edited.
        $verdicts = @(
            (Test-VcioIpInRange -IpAddress '10.0.0.1' -Range ([pscustomobject]@{})),
            (Test-VcioPermanentRoleAssignment -PrincipalId 'u1' -ScheduleInstances ([pscustomobject]@{})).Pass,
            (Test-VcioPrincipalInPolicyScope -PrincipalId 'u1' -PolicyUsers ([pscustomobject]@{}) -TransitiveGroupIds @('g1')).InScope,
            (Test-VcioUserInStandardScope -PrincipalId 'u1' -TransitiveGroupIds @('g1') -UsersGroupId 'g1' -Policies ([pscustomobject]@{})).InScope,
            (Test-VcioStandardCoverage -SignIns @([pscustomobject]@{ CreatedDateTime = [datetime]'2026-01-02Z' }) -Policies ([pscustomobject]@{}) -RemovedAt ([datetime]'2026-01-01Z')).Verified
        )
        @($verdicts | Where-Object { $_ }).Count | Should -Be 0
    }
}

Describe 'StrictMode sweep — coverage' {
    It 'every exported function is either swept or explicitly classified as taking no object' {
        # Held literally rather than derived from the case tables: those are
        # discovery-scope variables and are not visible during the run phase.
        $swept = @(
            'Get-VcioNamedLocationRanges', 'Get-VcioSignInClientCategory', 'Get-VcioSignInPlatform',
            'Resolve-VcioObjectId', 'Test-VcioCompliantDeviceExcludeFilter', 'Test-VcioHasProperty',
            'Test-VcioIpInRange', 'Test-VcioPermanentRoleAssignment', 'Test-VcioPrincipalInPolicyScope',
            'Test-VcioSignInsWithinFence', 'Test-VcioStandardCoverage', 'Test-VcioUserInStandardScope',
            'Get-VcioGraphCollection', 'Invoke-VcioAzGraphQuery', 'Assert-VcioTenantContext',
            'Get-VcioProp', 'Get-VcioPropCollection', 'Get-VcioPolicyName'
        )
        # Inputs are strings only: no object shape to get wrong.
        $noObjectInput = @('ConvertTo-VcioCidr', 'Test-VcioIsParsableIp', 'Test-VcioIpInRanges')

        $exported = @((Get-Module VcioCaCommon).ExportedFunctions.Keys)
        $uncovered = @($exported | Where-Object { $_ -notin $swept -and $_ -notin $noObjectInput })
        $uncovered -join ', ' | Should -BeExactly '' -Because 'a new exported function must be added to this sweep or to $noObjectInput'
    }
}
