<#
.SYNOPSIS
    Enumerate local groups on all domain-joined computers and
    identify broad memberships (Domain Users / Authenticated Users / Everyone / Domain Computers).

.DESCRIPTION
    For each computer in the specified domain:
      - Remote Desktop Users
      - Distributed COM Users
      - Administrators

    The script looks for members matching:
        Domain Users, Authenticated Users, Everyone, Domain Computers

    It also identifies *large* AD groups (size threshold configurable) that are
    granted RDP access (via membership in "Remote Desktop Users").

    A separate CSV is exported for each finding type.
    Requires:
        - ActiveDirectory module
        - PowerView's Get-NetLocalGroupMember (or replace with Get-LocalGroupMember, see note).
#>

[CmdletBinding()]
param(
    [string]$Domain     = (Get-ADDomain).DNSRoot,
    [string]$OutputPath = ".",
    [int]$LargeGroupThreshold = 100
)

Import-Module ActiveDirectory -ErrorAction Stop

# Regex of "too broad" principals you care about
$BroadPrincipalRegex = 'Domain Users|Authenticated Users|Everyone|Domain Computers'

# Get list of computers to test
Write-Host "[*] Enumerating domain computers from $Domain ..."
$Computers = Get-ADComputer -Server $Domain -Filter * -Properties DNSHostName |
             Where-Object { $_.DNSHostName } |
             Select-Object -ExpandProperty DNSHostName

Write-Host "[*] Found $($Computers.Count) computers."

# Cache for AD group sizes so we don't query the same group repeatedly
$GroupSizeCache = @{}

function Get-ADGroupSize {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($GroupSizeCache.ContainsKey($Name)) {
        return $GroupSizeCache[$Name]
    }

    try {
        $g = Get-ADGroup -Server $Domain -Identity $Name -Properties member -ErrorAction Stop
        $count = ($g.member).Count
        $GroupSizeCache[$Name] = $count
        return $count
    }
    catch {
        return $null
    }
}

# Helper function to enumerate a local group on all computers
function Get-InsecureLocalGroupMembership {
    param(
        [Parameter(Mandatory)]
        [string]$GroupName
    )

    $results = @()

    foreach ($c in $Computers) {
        try {
            # NOTE: This uses PowerView's Get-NetLocalGroupMember.
            # If you don't have it, swap with:
            #   Get-LocalGroupMember -Group $GroupName -ComputerName $c
            $members = Get-NetLocalGroupMember -ComputerName $c -GroupName $GroupName -ErrorAction Stop |
                       Where-Object { $_.MemberName -match $BroadPrincipalRegex }

            foreach ($m in $members) {
                $results += [pscustomobject]@{
                    ComputerName               = $c
                    GroupName                  = $GroupName
                    MemberName                 = $m.MemberName
                    MemberSID                  = $m.SID
                    MemberDomain               = $m.MemberDomain
                    IsGroup                    = $m.IsGroup
                    IsForeignSecurityPrincipal = $m.IsForeignSecurityPrincipal
                }
            }
        }
        catch {
            Write-Verbose "[-] Failed to query $GroupName on $c : $($_.Exception.Message)"
        }
    }

    return $results
}

# --- Finding 1: Remote Desktop Users with broad membership ---
Write-Host "[*] Checking 'Remote Desktop Users' ..."
$RDPResults = Get-InsecureLocalGroupMembership -GroupName "Remote Desktop Users"
if ($RDPResults.Count -gt 0) {
    $path = Join-Path $OutputPath "Finding_RemoteDesktopUsers_BroadMembership.csv"
    $RDPResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $path
    Write-Host "[+] Exported RDP broad membership results to $path"
}
else {
    Write-Host "[*] No broad principals found in 'Remote Desktop Users'."
}

# --- Finding 2: Distributed COM Users with broad membership ---
Write-Host "[*] Checking 'Distributed COM Users' ..."
$DCOMResults = Get-InsecureLocalGroupMembership -GroupName "Distributed COM Users"
if ($DCOMResults.Count -gt 0) {
    $path = Join-Path $OutputPath "Finding_DistributedCOMUsers_BroadMembership.csv"
    $DCOMResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $path
    Write-Host "[+] Exported Distributed COM Users broad membership results to $path"
}
else {
    Write-Host "[*] No broad principals found in 'Distributed COM Users'."
}

# --- Finding 3: Administrators with broad membership ---
Write-Host "[*] Checking 'Administrators' ..."
$AdminResults = Get-InsecureLocalGroupMembership -GroupName "Administrators"
if ($AdminResults.Count -gt 0) {
    $path = Join-Path $OutputPath "Finding_Administrators_BroadMembership.csv"
    $AdminResults | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $path
    Write-Host "[+] Exported Administrators broad membership results to $path"
}
else {
    Write-Host "[*] No broad principals found in 'Administrators'."
}

# --- Finding 4: Large default groups with RDP access ---
Write-Host "[*] Checking for large AD groups with RDP access (threshold: $LargeGroupThreshold members) ..."

$LargeRDPGroups = @()

foreach ($entry in $RDPResults | Where-Object { $_.IsGroup }) {
    # MemberName is usually 'DOMAIN\GroupName' – take the last part
    $groupSam = $entry.MemberName.Split('\')[-1]
    $size     = Get-ADGroupSize -Name $groupSam

    if ($size -ne $null -and $size -ge $LargeGroupThreshold) {
        $LargeRDPGroups += [pscustomobject]@{
            ComputerName = $entry.ComputerName
            LocalGroup   = $entry.GroupName            # 'Remote Desktop Users'
            ADGroup      = $groupSam
            MemberCount  = $size
        }
    }
}

if ($LargeRDPGroups.Count -gt 0) {
    $path = Join-Path $OutputPath "Finding_LargeDefaultGroups_RDPAccess.csv"
    $LargeRDPGroups | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $path
    Write-Host "[+] Exported large RDP group results to $path."
}
else {
    Write-Host "[*] No large AD groups with RDP access found."
}

Write-Host "[*] Enumeration complete."