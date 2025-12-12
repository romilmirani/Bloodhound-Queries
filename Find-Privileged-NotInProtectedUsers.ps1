<#
# Usage
.\Find-PrivilegedNotProtected.ps1
.\Find-PrivilegedNotProtected.ps1 -Domain "corp.example.com"
.\Find-PrivilegedNotProtected.ps1 -Domain "corp.example.com" | Export-Csv .\Privileged_Not_In_ProtectedUsers.csv -NoTypeInformation

#>

[CmdletBinding()]
param(
    [string]$Domain = (Get-ADDomain).DNSRoot
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "[*] Using domain: $Domain"

# Get domain info
$domainObj = Get-ADDomain -Identity $Domain -ErrorAction Stop

# Resolve Protected Users group
try {
    $protectedUsersGroup = Get-ADGroup -Server $Domain -Identity "Protected Users" -ErrorAction Stop
    Write-Host "[*] Protected Users group DN: $($protectedUsersGroup.DistinguishedName)"
} catch {
    Write-Warning "[-] Could not find 'Protected Users' group in $Domain. No exclusions will be applied."
    $protectedUsersGroup = $null
}

# Get all members (SIDs) of Protected Users (if it exists)
$protectedUserSids = @()
if ($protectedUsersGroup) {
    $protectedUserSids = Get-ADGroupMember -Server $Domain -Identity $protectedUsersGroup.DistinguishedName -Recursive |
        Where-Object { $_.objectClass -eq 'user' } |
        Select-Object -ExpandProperty SID -ErrorAction SilentlyContinue
}

# Core privileged groups (tweak as needed for your environment)
$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "Group Policy Creator Owners",
    "DnsAdmins",
    "Cert Publishers",
    "Read-only Domain Controllers"
)

Write-Host "[*] Collecting members of privileged groups ..."

$privGroupUsers = @()

foreach ($groupName in $PrivilegedGroups) {
    try {
        $group = Get-ADGroup -Server $Domain -Identity $groupName -ErrorAction Stop
        $members = Get-ADGroupMember -Server $Domain -Identity $group.DistinguishedName -Recursive |
            Where-Object { $_.objectClass -eq 'user' }

        if ($members) {
            Write-Host "[+] Found $($members.Count) user member(s) in group '$groupName'"
            $privGroupUsers += $members
        }
    } catch {
        # Group might not exist in all domains (e.g., Enterprise Admins in child domains)
        Write-Verbose "Group '$groupName' not found in $Domain. Skipping."
    }
}

# Collect adminCount=1 users (adminSDHolder-protected)
Write-Host "[*] Collecting adminCount=1 users ..."
$adminCountUsers = Get-ADUser -Server $Domain -LDAPFilter "(adminCount=1)" -Properties adminCount,Enabled |
    Where-Object { $_.Enabled -eq $true }

Write-Host "[+] Found $($adminCountUsers.Count) enabled user(s) with adminCount=1"

# Combine privileged user sets (by DN) and get full user objects
$allPrivilegedUserDns = @(
    $privGroupUsers.DistinguishedName +
    $adminCountUsers.DistinguishedName
) | Sort-Object -Unique

Write-Host "[*] Total unique privileged user DNs: $($allPrivilegedUserDns.Count)"

$allPrivilegedUsers = @()
if ($allPrivilegedUserDns.Count -gt 0) {
    $allPrivilegedUsers = Get-ADUser -Server $Domain -Identity $allPrivilegedUserDns -Properties Enabled,MemberOf,adminCount |
        Where-Object { $_.Enabled -eq $true }   # ensure enabled
}

# Exclude users that are in Protected Users
if ($protectedUserSids -and $protectedUserSids.Count -gt 0) {
    Write-Host "[*] Excluding users in Protected Users group ..."
    $result = $allPrivilegedUsers | Where-Object {
        $protectedUserSids -notcontains $_.SID
    }
} else {
    Write-Host "[*] No Protected Users group/members to exclude."
    $result = $allPrivilegedUsers
}

Write-Host "[*] Privileged users NOT in Protected Users: $($result.Count)"
Write-Host ""

# Output objects (you can pipe to Export-Csv if you want)
$result |
    Select-Object `
        SamAccountName,
        Name,
        Enabled,
        adminCount,
        @{Name="DistinguishedName";Expression={$_.DistinguishedName}},
        @{Name="Groups";Expression={ $_.MemberOf -join ";" }}
