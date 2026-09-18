function Update-ADGroupAllowedMembers {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupIdentity,

        [Parameter(Mandatory = $true)]
        [ValidateSet('T1', 'PUAM')]
        [string]$AllowedMembers,

        [switch]$RemoveUsers
    )

    $suffix = ".$AllowedMembers"
    $recognizedSuffixes = @('.T1', '.PUAM')
    $actionsTaken = [System.Collections.Generic.List[string]]::new()
    $missingMatches = [System.Collections.Generic.List[string]]::new()

    $membersBefore = @(Get-ADGroupMember -Identity $GroupIdentity |
        Select-Object Name, SamAccountName, DistinguishedName, ObjectClass)

    $currentSamAccountNames = @(
        $membersBefore |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.SamAccountName) } |
            ForEach-Object { $_.SamAccountName }
    )

    foreach ($member in $membersBefore) {
        $samAccountName = $member.SamAccountName

        if ([string]::IsNullOrWhiteSpace($samAccountName)) {
            continue
        }

        $baseSamAccountName = $samAccountName

        foreach ($recognizedSuffix in $recognizedSuffixes) {
            if ($baseSamAccountName.EndsWith($recognizedSuffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $baseSamAccountName = $baseSamAccountName.Substring(0, $baseSamAccountName.Length - $recognizedSuffix.Length)
                break
            }
        }

        $targetSamAccountName = "$baseSamAccountName$suffix"

        if ($currentSamAccountNames -contains $targetSamAccountName) {
            $actionsTaken.Add("Already present: $targetSamAccountName")
            continue
        }

        $matchedUser = Get-ADUser -Filter "SamAccountName -eq '$targetSamAccountName'" -ErrorAction SilentlyContinue

        if ($null -eq $matchedUser) {
            $missingMatches.Add($targetSamAccountName)
            $actionsTaken.Add("Missing matching account: $targetSamAccountName")
            continue
        }

        if ($PSCmdlet.ShouldProcess($GroupIdentity, "Add $targetSamAccountName")) {
            Add-ADGroupMember -Identity $GroupIdentity -Members $matchedUser
        }

        $actionsTaken.Add("Added: $targetSamAccountName")
        $currentSamAccountNames += $targetSamAccountName
    }

    if ($RemoveUsers.IsPresent) {
        $membersToRemove = @(
            $membersBefore |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_.SamAccountName) -and
                    -not $_.SamAccountName.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)
                }
        )

        foreach ($memberToRemove in $membersToRemove) {
            if ($PSCmdlet.ShouldProcess($GroupIdentity, "Remove $($memberToRemove.SamAccountName)")) {
                Remove-ADGroupMember -Identity $GroupIdentity -Members $memberToRemove -Confirm:$false
            }

            $actionsTaken.Add("Removed: $($memberToRemove.SamAccountName)")
        }
    }

    $membersAfter = @(Get-ADGroupMember -Identity $GroupIdentity |
        Select-Object Name, SamAccountName, DistinguishedName, ObjectClass)

    [pscustomobject]@{
        GroupIdentity   = $GroupIdentity
        AllowedMembers  = $AllowedMembers
        RemoveUsers     = $RemoveUsers.IsPresent
        MembersBefore   = $membersBefore
        ActionsTaken    = $actionsTaken
        MissingMatches  = $missingMatches
        MembersAfter    = $membersAfter
    }
}

Export-ModuleMember -Function Update-ADGroupAllowedMembers
