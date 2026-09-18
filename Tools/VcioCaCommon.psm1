<#
.SYNOPSIS
    Shared, testable logic for the VCIO CA Framework tools.
.DESCRIPTION
    The three operational scripts connect to Graph at load time, so their
    logic cannot be exercised without a tenant. Everything here is the part
    that CAN be tested: paging, CIDR matching, tenant assertion, manifest
    object resolution, and the three evidence evaluations that the second
    external review found inverted or incomplete.

    Tests/VcioCa.Tests.ps1 covers this module with mocked Graph and Az
    cmdlets — one regression per finding.

    Deliberately NOT here: ADMIN_ROLES. It already exists in three hardcoded
    copies and a fourth would make that drift worse, not better.
    Version 2026.9.1.
#>

Set-StrictMode -Version Latest

# ============================================================ IP / CIDR
# Named-location ranges are CIDR strings in both families. A v4 address must
# never be compared against a v6 range, and the comparison is on the first
# prefixLength BITS, not on bytes or on string prefixes.

function ConvertTo-VcioCidr {
    <#.SYNOPSIS Parse "10.0.0.0/8" or "2001:db8::/32" into an address + prefix.#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Cidr)

    $text = $Cidr.Trim()
    if (-not $text) { return $null }
    $parts = $text.Split('/')
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$addr)) { return $null }

    $bits = if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { 128 } else { 32 }
    $prefix = $bits
    if ($parts.Count -gt 1) {
        $parsed = 0
        if (-not [int]::TryParse($parts[1], [ref]$parsed)) { return $null }
        if ($parsed -lt 0 -or $parsed -gt $bits) { return $null }
        $prefix = $parsed
    }
    [pscustomobject]@{
        Address       = $addr
        PrefixLength  = $prefix
        AddressFamily = $addr.AddressFamily
        Text          = $text
    }
}

function Test-VcioIpInRange {
    <#.SYNOPSIS Is a single IP inside a single CIDR range?#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$IpAddress,
        [Parameter(Mandatory)]$Range
    )
    if (-not $Range) { return $false }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse(($IpAddress -replace '^\[|\]$',''), [ref]$ip)) { return $false }
    # Never compare across families — a 4-byte address against a 16-byte range
    # would otherwise "match" on a byte prefix.
    if ($ip.AddressFamily -ne $Range.AddressFamily) { return $false }

    $a = $ip.GetAddressBytes()
    $b = $Range.Address.GetAddressBytes()
    $bitsLeft = $Range.PrefixLength
    for ($i = 0; $i -lt $a.Length -and $bitsLeft -gt 0; $i++) {
        if ($bitsLeft -ge 8) {
            if ($a[$i] -ne $b[$i]) { return $false }
            $bitsLeft -= 8
        } else {
            $mask = [byte](0xFF -shl (8 - $bitsLeft) -band 0xFF)
            if (($a[$i] -band $mask) -ne ($b[$i] -band $mask)) { return $false }
            $bitsLeft = 0
        }
    }
    return $true
}

function Test-VcioIsParsableIp {
    <#.SYNOPSIS Can this string be read as an IP at all?#>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$IpAddress)
    if ([string]::IsNullOrWhiteSpace($IpAddress)) { return $false }
    $parsed = $null
    [System.Net.IPAddress]::TryParse(($IpAddress -replace '^\[|\]$',''), [ref]$parsed)
}

function Test-VcioIpInRanges {
    <#.SYNOPSIS Is an IP inside ANY of a set of CIDR strings?#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$IpAddress,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Cidrs
    )
    if ([string]::IsNullOrWhiteSpace($IpAddress)) { return $false }
    foreach ($c in $Cidrs) {
        $r = ConvertTo-VcioCidr -Cidr $c
        if ($r -and (Test-VcioIpInRange -IpAddress $IpAddress -Range $r)) { return $true }
    }
    return $false
}

function Get-VcioNamedLocationRanges {
    <#.SYNOPSIS Pull the CIDR strings out of a named-location object.#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$NamedLocation)
    if (-not $NamedLocation) { return @() }
    # The SDK surfaces ipRanges either directly or under AdditionalProperties
    # depending on the cmdlet and the API version in play.
    $ranges = $null
    foreach ($probe in 'IpRanges','ipRanges') {
        if ($NamedLocation.PSObject.Properties.Name -contains $probe) { $ranges = $NamedLocation.$probe; break }
    }
    if (-not $ranges -and $NamedLocation.PSObject.Properties.Name -contains 'AdditionalProperties') {
        $ap = $NamedLocation.AdditionalProperties
        if ($ap) {
            foreach ($probe in 'ipRanges','IpRanges') {
                if ($ap -is [hashtable] -and $ap.ContainsKey($probe)) { $ranges = $ap[$probe]; break }
                elseif ($ap.PSObject.Properties.Name -contains $probe) { $ranges = $ap.$probe; break }
            }
        }
    }
    $out = @()
    foreach ($r in @($ranges)) {
        if (-not $r) { continue }
        $cidr = $null
        if ($r -is [hashtable]) {
            foreach ($k in 'cidrAddress','CidrAddress') { if ($r.ContainsKey($k)) { $cidr = $r[$k]; break } }
        } else {
            foreach ($k in 'CidrAddress','cidrAddress') {
                if ($r.PSObject.Properties.Name -contains $k) { $cidr = $r.$k; break }
            }
        }
        if ($cidr) { $out += [string]$cidr }
    }
    ,$out
}

# ============================================================ paging
# Every Graph collection and every Resource Graph query is paged. A first page
# is not an answer: "nobody else holds this role" and "the first 999 holders
# do not include anyone else" are different statements.

function Get-VcioGraphCollection {
    <#.SYNOPSIS GET a Graph collection, following @odata.nextLink to the end.#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$MaxPages = 1000
    )
    $all = @()
    $next = $Uri
    $pages = 0
    while ($next -and $pages -lt $MaxPages) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next
        $pages++
        if (-not $resp) { break }
        $value = $null
        if ($resp -is [hashtable]) {
            if ($resp.ContainsKey('value')) { $value = $resp['value'] }
            $next = if ($resp.ContainsKey('@odata.nextLink')) { $resp['@odata.nextLink'] } else { $null }
        } else {
            if ($resp.PSObject.Properties.Name -contains 'value') { $value = $resp.value }
            $next = if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $resp.'@odata.nextLink' } else { $null }
        }
        foreach ($v in @($value)) { if ($null -ne $v) { $all += $v } }
    }
    if ($next) { throw "Graph paging exceeded $MaxPages pages for $Uri — refusing to report a partial collection as complete." }
    ,$all
}

function Invoke-VcioAzGraphQuery {
    <#
    .SYNOPSIS Run a Resource Graph query to completion.
    .DESCRIPTION Search-AzGraph caps -First at 1000. Anything larger is an
    error, not a silent truncation, so every caller must page. Prefers the
    SkipToken the result carries; falls back to -Skip.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [ValidateRange(1,1000)][int]$PageSize = 1000,
        [int]$MaxPages = 1000
    )
    $all = @()
    $skip = 0
    $token = $null
    $pages = 0
    while ($pages -lt $MaxPages) {
        $batch = if ($token) {
            Search-AzGraph -Query $Query -First $PageSize -SkipToken $token
        } elseif ($skip -gt 0) {
            Search-AzGraph -Query $Query -First $PageSize -Skip $skip
        } else {
            Search-AzGraph -Query $Query -First $PageSize
        }
        $pages++
        $rows = @($batch)
        if (-not $rows.Count) { break }
        $all += $rows
        $skip += $rows.Count

        $token = $null
        if ($batch -and $batch.PSObject.Properties.Name -contains 'SkipToken') { $token = $batch.SkipToken }
        elseif ($rows.Count -and $rows[0].PSObject.Properties.Name -contains 'SkipToken') { $token = $rows[0].SkipToken }
        if (-not $token -and $rows.Count -lt $PageSize) { break }
    }
    if ($pages -ge $MaxPages) { throw "Resource Graph paging exceeded $MaxPages pages — refusing to report a partial result as complete." }
    ,$all
}

# ============================================================ tenant safety
function Assert-VcioTenantContext {
    <#
    .SYNOPSIS Stop unless the live Graph context is the manifest's tenant.
    .DESCRIPTION These tools remove group members and disable policies. Running
    one against the wrong tenant because a cached context was still signed in
    elsewhere is the failure worth making impossible. Call immediately after
    Connect-MgGraph and BEFORE any write — including the run log.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$ExpectedTenantId)

    if ([string]::IsNullOrWhiteSpace($ExpectedTenantId)) {
        throw 'Manifest has no tenantId. Refusing to run: there is nothing to verify the connected tenant against.'
    }
    $ctx = Get-MgContext
    if (-not $ctx) { throw 'No Microsoft Graph context. Connect-MgGraph first.' }
    $actual = $ctx.TenantId
    if ($actual -ne $ExpectedTenantId) {
        throw ("TENANT MISMATCH — connected to '$actual' but the manifest names '$ExpectedTenantId'. " +
               'Refusing to run. Nothing has been read or written.')
    }
    $actual
}

function Resolve-VcioObjectId {
    <#
    .SYNOPSIS Manifest object ID first; displayName lookup only as a fallback.
    .DESCRIPTION The shipped GUIDs are uuid5 build IDs that IntuneManagement
    remaps at import, so the manifest records what it actually created.
    Resolving by displayName instead will happily find a policy someone renamed
    or duplicated. Returns the id plus how it was found, so the caller can log
    a fallback as a fallback.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Manifest,
        [Parameter(Mandatory)][ValidateSet('groups','namedLocations','policies')][string]$Kind,
        [Parameter(Mandatory)][string]$Name,
        [scriptblock]$Fallback
    )
    $id = $null
    if ($Manifest -and $Manifest.PSObject.Properties.Name -contains 'objectIds') {
        $section = $Manifest.objectIds
        if ($section -and $section.PSObject.Properties.Name -contains $Kind) {
            $map = $section.$Kind
            if ($map -and $map.PSObject.Properties.Name -contains $Name) {
                $candidate = [string]$map.$Name
                # The example manifest ships all-zero placeholders; those are
                # "not filled in", not an object id.
                if ($candidate -and $candidate -notmatch '^0{8}-0{4}-0{4}-0{4}-0{12}$') { $id = $candidate }
            }
        }
    }
    # Transition policy IDs live under transition.policyIds, not objectIds.
    if (-not $id -and $Kind -eq 'policies' -and $Manifest -and
        $Manifest.PSObject.Properties.Name -contains 'transition') {
        $t = $Manifest.transition
        if ($t -and $t.PSObject.Properties.Name -contains 'policyIds' -and $t.policyIds -and
            $t.policyIds.PSObject.Properties.Name -contains $Name) {
            $candidate = [string]$t.policyIds.$Name
            if ($candidate -and $candidate -notmatch '^0{8}-0{4}-0{4}-0{4}-0{12}$') { $id = $candidate }
        }
    }
    if (-not $id -and $Kind -eq 'groups' -and $Name -eq 'SG-CA-Transition-Hybrid' -and
        $Manifest -and $Manifest.PSObject.Properties.Name -contains 'transition') {
        $t = $Manifest.transition
        if ($t -and $t.PSObject.Properties.Name -contains 'groupId') {
            $candidate = [string]$t.groupId
            if ($candidate -and $candidate -notmatch '^0{8}-0{4}-0{4}-0{4}-0{12}$') { $id = $candidate }
        }
    }

    if ($id) { return [pscustomobject]@{ Id = $id; Source = 'manifest'; Name = $Name } }
    if ($Fallback) {
        $found = & $Fallback $Name
        if ($found) { return [pscustomobject]@{ Id = [string]$found; Source = 'displayName-fallback'; Name = $Name } }
    }
    [pscustomobject]@{ Id = $null; Source = 'unresolved'; Name = $Name }
}

# ============================================================ evidence
function Test-VcioPermanentRoleAssignment {
    <#
    .SYNOPSIS Does this principal hold a STANDING assignment of the role?
    .DESCRIPTION Evidence is roleAssignmentScheduleInstances with
    assignmentType 'Assigned' and no endDateTime. An ACTIVATED PIM eligibility
    also appears as a role assignment, and it must not count: break-glass exists
    for the moment activation itself is unavailable.

    An empty instance set is a FAIL for the principal, never a skip — "we could
    not see any assignments" is not "this account has one".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()]$ScheduleInstances
    )
    $instances = @(@($ScheduleInstances) | Where-Object { $_ })
    if (-not $instances.Count) {
        return [pscustomobject]@{ Pass = $false; Reason =
            'No Global Administrator role-assignment schedule instances were returned at all. An empty result set is not evidence of a standing assignment.' }
    }
    $mine = @($instances | Where-Object { $_.PrincipalId -eq $PrincipalId })
    if (-not $mine.Count) {
        return [pscustomobject]@{ Pass = $false; Reason = 'No Global Administrator assignment of any kind for this account.' }
    }
    $standing = @($mine | Where-Object {
        $_.AssignmentType -eq 'Assigned' -and -not $_.EndDateTime
    })
    if ($standing.Count) {
        return [pscustomobject]@{ Pass = $true; Reason = 'Standing (permanent) Global Administrator assignment.' }
    }
    $activated = @($mine | Where-Object { $_.AssignmentType -eq 'Activated' })
    if ($activated.Count) {
        return [pscustomobject]@{ Pass = $false; Reason =
            'Global Administrator is an ACTIVATED PIM eligibility, not a standing assignment. It appears in the role today and will not be there during the outage break-glass exists for.' }
    }
    $expiring = @($mine | Where-Object { $_.AssignmentType -eq 'Assigned' -and $_.EndDateTime })
    if ($expiring.Count) {
        return [pscustomobject]@{ Pass = $false; Reason =
            "Global Administrator assignment expires $($expiring[0].EndDateTime). Break-glass must not hold a time-bound assignment." }
    }
    [pscustomobject]@{ Pass = $false; Reason = 'No standing Global Administrator assignment found.' }
}

function Test-VcioPrincipalInPolicyScope {
    <#
    .SYNOPSIS Is this principal structurally in a policy's user scope?
    .DESCRIPTION Finding 2: whether a fence APPLIES is a structural fact about
    the policy's assignment, not something to infer from the sign-in log. CA500
    blocks outside a location, so a compliant account signing in from inside its
    fence logs the policy as notApplied — deriving "applies" from the log
    inverts the test and fails exactly the well-behaved accounts.

    Membership must be TRANSITIVE: an account excluded through a nested group
    would otherwise read as fenced. excludeUsers is checked as well as
    excludeGroups — a drifted tenant can name the account directly, and
    ignoring that gives a false PASS.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)]$PolicyUsers,
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][string[]]$TransitiveGroupIds
    )
    $groups = @(@($TransitiveGroupIds) | Where-Object { $_ })
    $inc      = @(@($PolicyUsers.IncludeGroups) | Where-Object { $_ })
    $exc      = @(@($PolicyUsers.ExcludeGroups) | Where-Object { $_ })
    $excUsers = @(@($PolicyUsers.ExcludeUsers)  | Where-Object { $_ })
    $incUsers = @(@($PolicyUsers.IncludeUsers)  | Where-Object { $_ })

    if ($PrincipalId -in $excUsers) {
        return [pscustomobject]@{ InScope = $false; Reason = 'Account is named directly in the policy''s excludeUsers.' }
    }
    $excHit = @($groups | Where-Object { $_ -in $exc })
    if ($excHit.Count) {
        return [pscustomobject]@{ InScope = $false; Reason = "Account is a transitive member of excluded group $($excHit[0])." }
    }
    $incHit = @($groups | Where-Object { $_ -in $inc })
    if ($incHit.Count) {
        return [pscustomobject]@{ InScope = $true; Reason = "Transitive member of included group $($incHit[0])." }
    }
    if ('All' -in $incUsers) {
        return [pscustomobject]@{ InScope = $true; Reason = 'Policy includes All users.' }
    }
    if ($PrincipalId -in $incUsers) {
        return [pscustomobject]@{ InScope = $true; Reason = 'Account is named directly in includeUsers.' }
    }
    [pscustomobject]@{ InScope = $false; Reason = 'Account is in none of the policy''s included groups or users.' }
}

function Test-VcioSignInsWithinFence {
    <#
    .SYNOPSIS Did anything SUCCEED from outside the fenced ranges?
    .DESCRIPTION Finding 2, part two. The evidence a fence holds is about
    source IP, not about which policies the log lists:
      - success from inside the ranges  -> fine
      - success from outside            -> FAIL, the fence did not hold
      - failure from outside            -> desirable, reported not failed
      - success whose IP cannot be parsed or is absent -> UNVERIFIED. A success
        we cannot place inside the ranges is not evidence of compliance.
    No sign-ins at all -> UNVERIFIED. No data is not the same as no problem.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()]$SignIns,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Cidrs
    )
    $all = @(@($SignIns) | Where-Object { $_ })
    $result = [pscustomobject]@{
        Verdict          = 'UNVERIFIED'
        Total            = $all.Count
        InsideSuccess    = 0
        OutsideSuccess   = @()
        OutsideBlocked   = 0
        UnplaceableSuccess = @()
        Reason           = ''
    }
    if (-not $all.Count) {
        $result.Reason = 'No sign-ins in the window — nothing proves the fence holds.'
        return $result
    }
    if (-not @($Cidrs).Count) {
        $result.Reason = 'The governing named location has no IP ranges, so "inside" is undefined. A fence with no ranges is not a fence.'
        return $result
    }

    foreach ($s in $all) {
        $ip = $null
        foreach ($probe in 'IpAddress','ipAddress') {
            if ($s.PSObject.Properties.Name -contains $probe) { $ip = [string]$s.$probe; break }
        }
        $code = $null
        if ($s.PSObject.Properties.Name -contains 'Status' -and $s.Status) {
            foreach ($probe in 'ErrorCode','errorCode') {
                if ($s.Status.PSObject.Properties.Name -contains $probe) { $code = $s.Status.$probe; break }
            }
        }
        $succeeded = ($code -eq 0)
        $inside = Test-VcioIpInRanges -IpAddress $ip -Cidrs $Cidrs

        if ($succeeded) {
            if ($inside) { $result.InsideSuccess++ }
            elseif (-not (Test-VcioIsParsableIp -IpAddress $ip)) {
                $result.UnplaceableSuccess += ($(if ($ip) { $ip } else { '(no IP recorded)' }))
            } else {
                $result.OutsideSuccess += $ip
            }
        } else {
            if (-not $inside) { $result.OutsideBlocked++ }
        }
    }

    if (@($result.OutsideSuccess).Count -gt 0) {
        $result.Verdict = 'FAIL'
        $result.Reason = "$(@($result.OutsideSuccess).Count) successful sign-in(s) from outside the governing location: $((@($result.OutsideSuccess) | Select-Object -Unique -First 5) -join ', ')."
    } elseif (@($result.UnplaceableSuccess).Count -gt 0) {
        $result.Verdict = 'UNVERIFIED'
        $result.Reason = "$(@($result.UnplaceableSuccess).Count) successful sign-in(s) whose source IP could not be placed inside the ranges: $((@($result.UnplaceableSuccess) | Select-Object -Unique -First 5) -join ', '). A success we cannot place inside the fence is not evidence the fence held."
    } elseif ($result.InsideSuccess -gt 0) {
        $result.Verdict = 'PASS'
        $result.Reason = "$($result.InsideSuccess) successful sign-in(s), all from inside the fenced ranges; $($result.OutsideBlocked) blocked attempt(s) from outside (desirable, reported not failed)."
    } else {
        $result.Verdict = 'UNVERIFIED'
        $result.Reason = "No successful sign-in from inside the fenced ranges in the window ($($result.OutsideBlocked) blocked attempt(s) from outside). Nothing proves the account can still work through its fence."
    }
    $result
}

function Test-VcioStandardCoverage {
    <#
    .SYNOPSIS Is a removed user demonstrably back under the standard policies?
    .DESCRIPTION Finding 6. Evidence is an ENFORCED result: 'success' or
    'failure'. A reportOnly* result proves the policy evaluated but not that it
    was enforcing, and notApplied proves nothing at all.

    Reading note: the four standard policies cannot all appear on ONE sign-in —
    CA200 is mobileAppsAndDesktopClients while CA300/CA301 are browser, so they
    are mutually exclusive on clientAppTypes. The check is therefore per policy:
    each of the four must show an enforced result on SOME post-removal sign-in.
    Sign-ins at or before RemovedAt are ignored — a sign-in from before the
    removal says nothing about what happens after it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()]$SignIns,
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$PolicyIdToName,
        [Parameter(Mandatory)][datetime]$RemovedAt
    )
    $enforced = @('success','failure')
    $seen = @{}
    $considered = 0
    foreach ($s in @(@($SignIns) | Where-Object { $_ })) {
        $created = $null
        foreach ($probe in 'CreatedDateTime','createdDateTime') {
            if ($s.PSObject.Properties.Name -contains $probe) { $created = $s.$probe; break }
        }
        if ($null -eq $created) { continue }
        $when = if ($created -is [datetime]) { $created } else { [datetime]::Parse([string]$created, $null, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) }
        # STRICTLY after the removal.
        if ($when.ToUniversalTime() -le $RemovedAt.ToUniversalTime()) { continue }
        $considered++
        $applied = $null
        foreach ($probe in 'AppliedConditionalAccessPolicies','appliedConditionalAccessPolicies') {
            if ($s.PSObject.Properties.Name -contains $probe) { $applied = $s.$probe; break }
        }
        foreach ($p in @(@($applied) | Where-Object { $_ })) {
            $pid_ = $null; $res = $null
            foreach ($probe in 'Id','id') { if ($p.PSObject.Properties.Name -contains $probe) { $pid_ = [string]$p.$probe; break } }
            foreach ($probe in 'Result','result') { if ($p.PSObject.Properties.Name -contains $probe) { $res = [string]$p.$probe; break } }
            if ($pid_ -and $PolicyIdToName.ContainsKey($pid_) -and $res -and ($res.ToLowerInvariant() -in $enforced)) {
                $seen[$pid_] = $true
            }
        }
    }
    $missing = @($PolicyIdToName.Keys | Where-Object { -not $seen.ContainsKey($_) } | ForEach-Object { $PolicyIdToName[$_] } | Sort-Object)
    [pscustomobject]@{
        Verified            = (-not $missing.Count)
        Missing             = $missing
        SignInsConsidered   = $considered
        PoliciesWithEnforcedResult = @($seen.Keys | ForEach-Object { $PolicyIdToName[$_] } | Sort-Object)
    }
}

Export-ModuleMember -Function ConvertTo-VcioCidr, Test-VcioIpInRange, Test-VcioIpInRanges, Test-VcioIsParsableIp,
    Get-VcioNamedLocationRanges, Get-VcioGraphCollection, Invoke-VcioAzGraphQuery,
    Assert-VcioTenantContext, Resolve-VcioObjectId, Test-VcioPermanentRoleAssignment,
    Test-VcioPrincipalInPolicyScope, Test-VcioSignInsWithinFence, Test-VcioStandardCoverage
