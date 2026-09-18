# Swap-GroupMembers

PowerShell module for aligning Active Directory group membership to a required suffix.

## Function

`Update-ADGroupAllowedMembers`

### Parameters

- `GroupIdentity` - AD group to inspect and update
- `AllowedMembers` - required suffix, either `T1` or `PUAM`
- `RemoveUsers` - optional switch; when supplied, removes members whose `SamAccountName` does not end with the selected suffix

### Behavior

- Reads the current group members
- For each member, derives the base `SamAccountName` and attempts to add the matching suffixed account:
  - `AllowedMembers T1` -> `SAMACCOUNTNAME.T1`
  - `AllowedMembers PUAM` -> `SAMACCOUNTNAME.PUAM`
- Reports accounts that do not have a matching suffixed user in AD
- Returns:
  - membership before
  - actions taken
  - missing matching accounts
  - membership after

### Example

```powershell
Import-Module /path/to/Swap-GroupMembers.psm1

Update-ADGroupAllowedMembers -GroupIdentity 'MyGroup' -AllowedMembers T1

Update-ADGroupAllowedMembers -GroupIdentity 'MyGroup' -AllowedMembers PUAM -RemoveUsers
```
