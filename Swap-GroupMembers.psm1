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

    function Resolve-ADGroupMembers {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Identity
        )

        $rawMembers = @(Get-ADGroupMember -Identity $Identity)
        $resolvedMembers = foreach ($rawMember in $rawMembers) {
            $memberName = $rawMember.Name
            $memberSamAccountName = $rawMember.SamAccountName
            $memberDistinguishedName = $rawMember.DistinguishedName
            $memberObjectClass = $rawMember.ObjectClass

            if ([string]::IsNullOrWhiteSpace($memberSamAccountName) -and -not [string]::IsNullOrWhiteSpace($memberDistinguishedName)) {
                $resolvedUser = Get-ADUser -Identity $memberDistinguishedName -Properties SamAccountName, Name, DistinguishedName, ObjectClass -ErrorAction SilentlyContinue

                if ($null -ne $resolvedUser) {
                    $memberName = $resolvedUser.Name
                    $memberSamAccountName = $resolvedUser.SamAccountName
                    $memberDistinguishedName = $resolvedUser.DistinguishedName
                    $memberObjectClass = $resolvedUser.ObjectClass
                }
            }

            [pscustomobject]@{
                Name              = $memberName
                SamAccountName    = $memberSamAccountName
                DistinguishedName = $memberDistinguishedName
                ObjectClass       = $memberObjectClass
            }
        }

        [pscustomobject]@{
            RawMembers      = $rawMembers
            ResolvedMembers = @($resolvedMembers)
        }
    }

    $suffix = ".$AllowedMembers"
    $recognizedSuffixes = @('.T1', '.PUAM')
    $isWhatIf = [bool]$WhatIfPreference
    $actionsTaken = [System.Collections.Generic.List[string]]::new()
    $missingMatches = [System.Collections.Generic.List[string]]::new()
    $processedTargetSamAccountNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $membersBeforeResult = Resolve-ADGroupMembers -Identity $GroupIdentity
    $membersBeforeRaw = $membersBeforeResult.RawMembers
    $membersBefore = $membersBeforeResult.ResolvedMembers
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

        if (-not $processedTargetSamAccountNames.Add($targetSamAccountName)) {
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
                if (-not ($simulatedMembersAfter.SamAccountName -contains $targetSamAccountName)) {
                    $simulatedMembersAfter.Add([pscustomobject]@{
                            Name              = if ($matchedUser.PSObject.Properties.Name -contains 'Name') { $matchedUser.Name } else { $targetSamAccountName }
                            SamAccountName    = $targetSamAccountName
                            DistinguishedName = $matchedUser.DistinguishedName
                            ObjectClass       = if ($matchedUser.PSObject.Properties.Name -contains 'ObjectClass') { $matchedUser.ObjectClass } else { 'user' }
                        })
                }
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
            $membersBeforeRaw |
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
                    Remove-ADGroupMember -Identity $GroupIdentity -Members $memberToRemove.DistinguishedName -Confirm:$false -ErrorAction Stop
                    $actionsTaken.Add("Removed: $($memberToRemove.SamAccountName)")
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

    $membersAfter = @($simulatedMembersAfter)

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
