<#
    Drives Tools/Invoke-VcioTransitionExit.ps1 against a fake tenant.

    Runs in its own process so the script's `exit` cannot take the Pester host
    with it, and so a second run genuinely starts cold — which is the whole
    point of the state-machine regression. The fake tenant lives in a JSON file
    so it survives between runs the way a real one does.
#>
param(
    [Parameter(Mandatory)][string]$StateFile,
    [Parameter(Mandatory)][string]$Manifest,
    [Parameter(Mandatory)][string]$ScriptPath,
    [int]$PropagationMinutes = 30
)

$ErrorActionPreference = 'Stop'
$global:FakeState = Get-Content -Raw $StateFile | ConvertFrom-Json

function Save-FakeState {
    $global:FakeState | ConvertTo-Json -Depth 10 | Set-Content -Path $StateFile -Encoding utf8
}

Set-Item 'function:global:Connect-MgGraph' { param($TenantId, $Scopes, [switch]$NoWelcome) } | Out-Null
Set-Item 'function:global:Get-MgContext'   { [pscustomobject]@{ TenantId = $global:FakeState.tenantId } } | Out-Null

Set-Item 'function:global:Get-MgIdentityConditionalAccessPolicy' {
    param($ConditionalAccessPolicyId, [switch]$All, $State, $ErrorAction)
    @($global:FakeState.policies) | ForEach-Object {
        $pol = $_
        [pscustomobject]@{
            Id = $pol.id; DisplayName = $pol.displayName; State = $pol.state
            Conditions = [pscustomobject]@{
                ClientAppTypes = @($pol.clientAppTypes)
                Platforms = $(if ($pol.includePlatforms) { [pscustomobject]@{ IncludePlatforms = @($pol.includePlatforms) } } else { $null })
                Devices   = $(if ($pol.filterRule) {
                    [pscustomobject]@{ DeviceFilter = [pscustomobject]@{
                        Mode = $(if ($pol.PSObject.Properties.Name -contains 'filterMode' -and $pol.filterMode) { $pol.filterMode } else { 'exclude' })
                        Rule = $pol.filterRule } } } else { $null })
                Users = [pscustomobject]@{
                    IncludeUsers  = @($pol.includeUsers)
                    IncludeGroups = @($pol.includeGroups)
                    IncludeRoles  = @($pol.includeRoles)
                    ExcludeGroups = @($pol.excludeGroups)
                    ExcludeUsers  = @($pol.excludeUsers)
                }
            }
        }
    }
} | Out-Null

Set-Item 'function:global:Invoke-MgGraphRequest' {
    param($Method, $Uri, $Body, $ContentType, $ErrorAction)
    if ($Uri -like '*roleManagement/directory/roleAssignments*') {
        return @{ value = @($global:FakeState.roleAssignments | ForEach-Object {
            @{ principalId = $_.principalId; roleDefinitionId = $_.roleDefinitionId } }) }
    }
    @{ value = @() }
} | Out-Null

Set-Item 'function:global:Get-MgUserTransitiveMemberOf' {
    param($UserId, [switch]$All, $ErrorAction)
    $map = $global:FakeState.userGroups
    $ids = @()
    if ($map -and $map.PSObject.Properties.Name -contains $UserId) { $ids = @($map.$UserId) }
    @($ids) | ForEach-Object { [pscustomobject]@{ Id = $_ } }
} | Out-Null

Set-Item 'function:global:Get-MgGroup' { param($Filter, $GroupId, [switch]$All, $ErrorAction) @() } | Out-Null

Set-Item 'function:global:Get-MgGroupMember' {
    param($GroupId, [switch]$All, $ErrorAction)
    $ids = if ($GroupId -eq $global:FakeState.usersGroupId) { @($global:FakeState.usersGroupMembers) }
           else { @($global:FakeState.members) }
    @($ids) | ForEach-Object { [pscustomobject]@{ Id = $_ } }
} | Out-Null

Set-Item 'function:global:Get-MgUser' {
    param($UserId, $Property, $ErrorAction)
    [pscustomobject]@{ Id = $UserId; UserPrincipalName = "$UserId@contoso.com" }
} | Out-Null

Set-Item 'function:global:Remove-MgGroupMemberByRef' {
    param($GroupId, $DirectoryObjectId, $ErrorAction)
    # Record the instant the API was entered, so the test can prove removedAt
    # is stamped AFTER the call returns rather than before it.
    $global:FakeState.removeLog = @(@($global:FakeState.removeLog) + @([pscustomobject]@{
        id = $DirectoryObjectId
        calledAt = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }))
    Save-FakeState
    Start-Sleep -Milliseconds 20
    if ($DirectoryObjectId -in @($global:FakeState.throwOn)) {
        throw "Simulated Graph failure removing $DirectoryObjectId"
    }
    $global:FakeState.members = @(@($global:FakeState.members) | Where-Object { $_ -ne $DirectoryObjectId })
    Save-FakeState
} | Out-Null

Set-Item 'function:global:Get-MgAuditLogSignIn' {
    param($Filter, [switch]$All, $ErrorAction)
    @($global:FakeState.signIns) | ForEach-Object {
        [pscustomobject]@{
            CreatedDateTime = [datetime]::Parse($_.createdDateTime, $null,
                [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
            ClientAppUsed = $_.clientAppUsed
            DeviceDetail = [pscustomobject]@{ OperatingSystem = $_.operatingSystem; IsCompliant = $_.isCompliant }
            AppliedConditionalAccessPolicies = @($_.applied | ForEach-Object {
                [pscustomobject]@{ Id = $_.id; Result = $_.result } })
        }
    }
} | Out-Null

Set-Item 'function:global:Update-MgIdentityConditionalAccessPolicy' {
    param($ConditionalAccessPolicyId, $State)
    $global:FakeState.disabled = @(@($global:FakeState.disabled) + @($ConditionalAccessPolicyId))
    Save-FakeState
} | Out-Null

try {
    # -Confirm:$false because the script is ConfirmImpact='High'. Without it
    # every ShouldProcess prompts and an unattended run blocks forever —
    # which is exactly what a scheduled daily run would do.
    & $ScriptPath -Manifest $Manifest -PropagationMinutes $PropagationMinutes -Confirm:$false
    $code = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 0 }
} catch {
    Write-Host "HARNESS CAUGHT: $($_.Exception.Message)"
    $code = 99
}
Save-FakeState
exit $code
