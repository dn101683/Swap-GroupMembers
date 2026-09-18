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

    function ConvertTo-LdapFilterValue {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Value
        )

        $ldapFilterValue = $Value.Replace('\', '\5c')
        $ldapFilterValue = $ldapFilterValue.Replace('*', '\2a')
        $ldapFilterValue = $ldapFilterValue.Replace('(', '\28')
        $ldapFilterValue = $ldapFilterValue.Replace(')', '\29')
        $ldapFilterValue = $ldapFilterValue.Replace([string][char]0, '\00')

        $ldapFilterValue
    }

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

        $targetSamAccountNameLdapValue = ConvertTo-LdapFilterValue -Value $targetSamAccountName
        $matchedUsers = @(
            Get-ADUser -LDAPFilter "(sAMAccountName=$targetSamAccountNameLdapValue)" -ErrorAction SilentlyContinue |
                Where-Object { $null -ne $_ }
        )

        if ($matchedUsers.Count -eq 0) {
            $missingMatches.Add($targetSamAccountName)
            $actionsTaken.Add("Missing matching account: $targetSamAccountName")
            continue
        }

        if ($matchedUsers.Count -gt 1) {
            $actionsTaken.Add("Ambiguous matching account: $targetSamAccountName")
            continue
        }

        $matchedUser = $matchedUsers[0]

        if ($PSCmdlet.ShouldProcess($GroupIdentity, "Add $targetSamAccountName")) {
            try {
                Add-ADGroupMember -Identity $GroupIdentity -Members $matchedUser -ErrorAction Stop
                $actionsTaken.Add("Added: $targetSamAccountName")
                $currentSamAccountNames += $targetSamAccountName
            }
            catch {
                $actionsTaken.Add("Failed to add: $targetSamAccountName")
            }
        }
        elseif ($isWhatIf) {
            $actionsTaken.Add("Would add: $targetSamAccountName")
            $currentSamAccountNames += $targetSamAccountName
        }
        else {
            $actionsTaken.Add("Skipped add: $targetSamAccountName")
        }

        if ($isWhatIf -and -not ($simulatedMembersAfter.SamAccountName -contains $targetSamAccountName)) {
            $simulatedMembersAfter.Add([pscustomobject]@{
                    Name              = if ($matchedUser.PSObject.Properties.Name -contains 'Name') { $matchedUser.Name } else { $targetSamAccountName }
                    SamAccountName    = $targetSamAccountName
                    DistinguishedName = $matchedUser.DistinguishedName
                    ObjectClass       = if ($matchedUser.PSObject.Properties.Name -contains 'ObjectClass') { $matchedUser.ObjectClass } else { 'user' }
                })
        }
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
                try {
                    Remove-ADGroupMember -Identity $GroupIdentity -Members $memberToRemove -Confirm:$false -ErrorAction Stop
                    $actionsTaken.Add("Removed: $($memberToRemove.SamAccountName)")
                }
                catch {
                    $actionsTaken.Add("Failed to remove: $($memberToRemove.SamAccountName)")
                }
            }
            elseif ($isWhatIf) {
                $actionsTaken.Add("Would remove: $($memberToRemove.SamAccountName)")

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
            else {
                $actionsTaken.Add("Skipped remove: $($memberToRemove.SamAccountName)")
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
