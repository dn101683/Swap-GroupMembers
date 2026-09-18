# Swap-GroupMembers

PowerShell module for aligning Active Directory group membership to a required suffix.

## Function

`Update-ADGroupAllowedMembers`

### Parameters

- `GroupIdentity` - AD group to inspect and update
- `AllowedMembers` - required suffix, either `T1` or `PUAM`
- `RemoveUsers` - optional switch; when supplied, removes only managed suffix members (`.T1`/`.PUAM`) whose `SamAccountName` does not end with the selected suffix

### Behavior

- Reads the current group members
- Resolves user members to include `SamAccountName` values before evaluating membership
- For each member that has a resolved `SamAccountName`, derives the base account name by removing only one trailing managed suffix (`.T1`/`.PUAM`) and attempts to add the matching suffixed account:
  - `AllowedMembers T1` -> `SAMACCOUNTNAME.T1`
  - `AllowedMembers PUAM` -> `SAMACCOUNTNAME.PUAM`
- When `RemoveUsers` is supplied, removes only `.T1`/`.PUAM` members that do not match the selected suffix
- Reports accounts that do not have a matching suffixed user in AD
- Returns:
  - group identity
  - selected allowed member suffix
  - whether removal mode was enabled
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
