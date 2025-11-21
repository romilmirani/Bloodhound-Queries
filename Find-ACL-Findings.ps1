<#
  Find-ACL-Findings.ps1
  --------------------
  Usage:
    .\Find-ACL-Findings.ps1
    .\Find-ACL-Findings.ps1 -Domain corp.local -Server dc01.corp.local -OutDir C:\Temp
#>

[CmdletBinding()]
param(
    [string]$Domain,
    [string]$Server,
    [string]$OutDir = "."
)


if (-not (Get-Command Get-ObjectAcl -ErrorAction SilentlyContinue)) {
    Write-Error "Get-ObjectAcl not found. Import PowerView.ps1 first."
    exit 1
}

if (-not (Test-Path $OutDir)) {
    New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
}

if (-not $Domain) {
    try {
        $Domain = (Get-Domain).Name
    } catch {
        $Domain = Read-Host "Enter domain (e.g. corp.local)"
    }
}

Write-Host "`n[*] Domain      : $Domain"
if ($Server) { Write-Host "[*] DC / Server : $Server" }

$LargeDefaultRegex   = 'Domain Users|Authenticated Users|Domain Computers|Everyone'
$TierZeroGroupsRegex = 'CN=Domain Admins|CN=Enterprise Admins|CN=Administrators|CN=Schema Admins|CN=Account Operators'
$TierZeroObjectsRegex= 'CN=AdminSDHolder|OU=Domain Controllers|CN=krbtgt'
$TierZeroPrincipalRx = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Server Operators|Backup Operators|Domain Controllers|Read-only Domain Controllers|krbtgt'

Write-Host "`n[*] Pulling all ACLs via Get-ObjectAcl (this may take a bit)..." -ForegroundColor Cyan

$acl = Get-ObjectAcl -ResolveGUIDs -LDAPFilter '(objectClass=*)' -Domain $Domain -Server $Server

if (-not $acl) {
    Write-Error "No ACL data returned. Aborting."
    exit 1
}

$aclNamed = $acl | Select-Object *,
    @{Name='Principal';Expression={ ConvertFrom-SID $_.SecurityIdentifier }}

$allAclCsv = Join-Path $OutDir ("{0}_AllACLs.csv" -f $Domain)
$aclNamed |
  Select-Object ObjectDN,Principal,SecurityIdentifier,ActiveDirectoryRights,ObjectAceType,IsInherited,InheritanceFlags |
  Export-Csv -Path $allAclCsv -NoTypeInformation -Encoding UTF8

Write-Host "[+] Full ACL dump saved to: $allAclCsv" -ForegroundColor Green

function Export-Finding {
    param(
        [string]$ShortName,   # used in filename
        [string]$Description, # for console
        $Data
    )

    $items = @($Data)  # force array
    $csvPath = Join-Path $OutDir ("{0}_{1}.csv" -f $Domain,$ShortName)

    if ($items.Count -eq 0) {
        Write-Host "[+] $Description : NONE found. Creating empty CSV." -ForegroundColor Green
        [pscustomobject]@{
            ObjectDN            = ''
            Principal           = ''
            SecurityIdentifier  = ''
            ActiveDirectoryRights = ''
            ObjectAceType       = ''
            IsInherited         = ''
        } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        return
    }

    $items |
      Select-Object ObjectDN,Principal,SecurityIdentifier,ActiveDirectoryRights,ObjectAceType,IsInherited |
      Sort-Object ObjectDN,Principal |
      Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host ("[!] {0} : {1} ACE(s) found. CSV: {2}" -f $Description,$items.Count,$csvPath) -ForegroundColor Yellow
}

# 1) Non Tier Zero Principals with DCSync Privileges
$nonTier0DCSync = $aclNamed | Where-Object {
    $_.ObjectAceType -match 'DS-Replication-Get-Changes' -and
    $_.Principal -notmatch $TierZeroPrincipalRx
}
Export-Finding -ShortName 'NonTier0_DCSync' -Description 'Non Tier Zero Principals with DCSync Privileges' -Data $nonTier0DCSync

# 2) Large Default Groups with Write Account Restrictions Privileges
$ld_WriteAccRestr = $aclNamed | Where-Object {
    $_.ObjectAceType -eq 'User-Account-Restrictions' -and
    $_.Principal -match $LargeDefaultRegex
}
Export-Finding -ShortName 'LargeDefault_WriteAccountRestrictions' -Description 'Large Default Groups with Write Account Restrictions Privileges' -Data $ld_WriteAccRestr

# 3) Large Default Groups with Generic Write Privileges
$ld_GenericWrite = $aclNamed | Where-Object {
    $_.ActiveDirectoryRights -match 'GenericWrite' -and
    $_.Principal -match $LargeDefaultRegex
}
Export-Finding -ShortName 'LargeDefault_GenericWrite' -Description 'Large Default Groups with Generic Write Privileges' -Data $ld_GenericWrite

# 4) Generic All Privileges on Tier Zero Groups
$ga_Tier0Groups = $aclNamed | Where-Object {
    $_.ActiveDirectoryRights -match 'GenericAll' -and
    $_.ObjectDN -match $TierZeroGroupsRegex
}
Export-Finding -ShortName 'GenericAll_Tier0Groups' -Description 'Generic All Privileges on Tier Zero Groups' -Data $ga_Tier0Groups

# 5) Large Default Groups with Generic All Privileges
$ld_GenericAll = $aclNamed | Where-Object {
    $_.ActiveDirectoryRights -match 'GenericAll' -and
    $_.Principal -match $LargeDefaultRegex
}
Export-Finding -ShortName 'LargeDefault_GenericAll' -Description 'Large Default Groups with Generic All Privileges' -Data $ld_GenericAll

# 6) Large Default Groups with Add Self Privileges
$ld_AddSelf = $aclNamed | Where-Object {
    $_.ActiveDirectoryRights -match 'Self' -and
    $_.Principal -match $LargeDefaultRegex
}
Export-Finding -ShortName 'LargeDefault_AddSelf' -Description 'Large Default Groups with Add Self Privileges' -Data $ld_AddSelf

# 7) Large Default Groups with Force Change Password Privileges
$ld_ForceChangePwd = $aclNamed | Where-Object {
    $_.ObjectAceType -eq 'User-Change-Password' -and
    $_.Principal -match $LargeDefaultRegex
}
Export-Finding -ShortName 'LargeDefault_ForceChangePassword' -Description 'Large Default Groups with Force Change Password Privileges' -Data $ld_ForceChangePwd

# 8) Generic All Privileges on Tier Zero Objects
$ga_Tier0Objects = $aclNamed | Where-Object {
    $_.ActiveDirectoryRights -match 'GenericAll' -and
    $_.ObjectDN -match $TierZeroObjectsRegex
}
Export-Finding -ShortName 'GenericAll_Tier0Objects' -Description 'Generic All Privileges on Tier Zero Objects' -Data $ga_Tier0Objects

# 9) Large Default Groups with All Extended Privileges
$ld_Extended = $aclNamed | Where-Object {
    $_.ActiveDirectoryRights -match 'ExtendedRight' -and
    $_.Principal -match $LargeDefaultRegex
}
Export-Finding -ShortName 'LargeDefault_AllExtended' -Description 'Large Default Groups with All Extended Privileges' -Data $ld_Extended

# 10) Large Default Groups with Write DACL Privilege
$ld_WriteDacl = $aclNamed | Where-Object {
    $_.ActiveDirectoryRights -match 'WriteDacl' -and
    $_.Principal -match $LargeDefaultRegex
}
Export-Finding -ShortName 'LargeDefault_WriteDacl' -Description 'Large Default Groups with Write DACL Privilege' -Data $ld_WriteDacl

# 11) Large Default Groups with Write Owner Privileges
$ld_WriteOwner = $aclNamed | Where-Object {
    $_.ActiveDirectoryRights -match 'WriteOwner' -and
    $_.Principal -match $LargeDefaultRegex
}
Export-Finding -ShortName 'LargeDefault_WriteOwner' -Description 'Large Default Groups with Write Owner Privileges' -Data $ld_WriteOwner

# 12) Ownership Privileges on Tier Zero Objects
$owner_Tier0Objects = $aclNamed | Where-Object {
    $_.ActiveDirectoryRights -match 'WriteOwner' -and
    $_.ObjectDN -match $TierZeroObjectsRegex
}
Export-Finding -ShortName 'Owner_Tier0Objects' -Description 'Ownership Privileges on Tier Zero Objects' -Data $owner_Tier0Objects

Write-Host "`n[+] Enumeration complete." -ForegroundColor Green
