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
    $isWhatIf = [bool]$WhatIfPreference
    $actionsTaken = [System.Collections.Generic.List[string]]::new()
    $missingMatches = [System.Collections.Generic.List[string]]::new()

    $membersBefore = @(Get-ADGroupMember -Identity $GroupIdentity |
        Select-Object Name, SamAccountName, DistinguishedName, ObjectClass)
    $simulatedMembersAfter = [System.Collections.Generic.List[object]]::new()

    foreach ($member in $membersBefore) {
        $simulatedMembersAfter.Add($member)
    }

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
            $actionsTaken.Add("Added: $targetSamAccountName")
        }
        else {
            $actionsTaken.Add("Would add: $targetSamAccountName")
        }

        $currentSamAccountNames += $targetSamAccountName
        $simulatedMembersAfter.Add([pscustomobject]@{
                Name              = if ($matchedUser.PSObject.Properties.Name -contains 'Name') { $matchedUser.Name } else { $targetSamAccountName }
                SamAccountName    = $targetSamAccountName
                DistinguishedName = $matchedUser.DistinguishedName
                ObjectClass       = if ($matchedUser.PSObject.Properties.Name -contains 'ObjectClass') { $matchedUser.ObjectClass } else { 'user' }
            })
    }

    if ($RemoveUsers.IsPresent) {
        $membersToRemove = @(
            $membersBefore |
                Where-Object {
                    $memberSamAccountName = $_.SamAccountName

                    if ([string]::IsNullOrWhiteSpace($memberSamAccountName)) {
                        return $false
                    }

                    $hasManagedSuffix = $false

                    foreach ($recognizedSuffix in $recognizedSuffixes) {
                        if ($memberSamAccountName.EndsWith($recognizedSuffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $hasManagedSuffix = $true
                            break
                        }
                    }

                    $hasManagedSuffix -and -not $memberSamAccountName.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)
                }
        )

        foreach ($memberToRemove in $membersToRemove) {
            if ($PSCmdlet.ShouldProcess($GroupIdentity, "Remove $($memberToRemove.SamAccountName)")) {
                Remove-ADGroupMember -Identity $GroupIdentity -Members $memberToRemove -Confirm:$false
                $actionsTaken.Add("Removed: $($memberToRemove.SamAccountName)")
            }
            else {
                $actionsTaken.Add("Would remove: $($memberToRemove.SamAccountName)")
            }

            $memberIndex = -1
            for ($index = 0; $index -lt $simulatedMembersAfter.Count; $index++) {
                if ($simulatedMembersAfter[$index].SamAccountName -eq $memberToRemove.SamAccountName) {
                    $memberIndex = $index
                    break
                }
            }

            if ($memberIndex -ge 0) {
                $simulatedMembersAfter.RemoveAt($memberIndex)
            }
        }
    }

    if ($isWhatIf) {
        $membersAfter = @($simulatedMembersAfter)
    }
    else {
        $membersAfter = @(Get-ADGroupMember -Identity $GroupIdentity |
            Select-Object Name, SamAccountName, DistinguishedName, ObjectClass)
    }

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
