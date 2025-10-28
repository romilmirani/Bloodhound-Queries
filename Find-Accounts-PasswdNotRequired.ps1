<#
  Find-Accounts-PasswdNotRequired.ps1
  -----------------------------------

  Usage:
    .\Find-Accounts-PasswdNotRequired.ps1
    .\Find-Accounts-PasswdNotRequired.ps1 -Server corp.local -OutCsv C:\Temp\passwd_not_required.csv
    .\Find-Accounts-PasswdNotRequired.ps1 -Server dc01.corp.local -IncludeComputers
#>

[CmdletBinding()]
param(
  [string]$Server,
  [string]$OutCsv = ".\PasswdNotRequired_$Server.csv",
  [switch]$IncludeComputers
)

if (-not $Server) {
  $Server = Read-Host "Enter domain FQDN or DC hostname/IP"
}

if (-not (Get-Module ActiveDirectory)) {
  try { Import-Module ActiveDirectory -ErrorAction Stop }
  catch { Write-Error "ActiveDirectory module not available (install RSAT)."; exit 1 }
}

$UacBitFilter = "(userAccountControl:1.2.840.113556.1.4.803:=32)"

Write-Host "[*] Searching users with PASSWD_NOTREQD on $Server ..." -ForegroundColor Cyan

$users = Get-ADUser -Server $Server -LDAPFilter "(& (objectCategory=person) (objectClass=user) $UacBitFilter )" `
         -Properties userAccountControl,Enabled,SamAccountName,Name,UserPrincipalName,pwdLastSet,whenCreated,distinguishedName

$rows = @()

if ($users) {
  $rows += $users | ForEach-Object {
    [pscustomobject]@{
      ObjectClass        = 'user'
      SamAccountName     = $_.SamAccountName
      Name               = $_.Name
      Enabled            = $_.Enabled
      UserPrincipalName  = $_.UserPrincipalName
      PwdLastSet         = if ($_.pwdLastSet) { [DateTime]::FromFileTime([int64]$_.pwdLastSet) } else { $null }
      WhenCreated        = $_.whenCreated
      DistinguishedName  = $_.distinguishedName
    }
  }
}

if ($IncludeComputers) {
  Write-Host "[*] Searching computers with PASSWD_NOTREQD on $Server ..." -ForegroundColor Cyan
  $computers = Get-ADComputer -Server $Server -LDAPFilter "(& (objectCategory=computer) $UacBitFilter )" `
               -Properties userAccountControl,Enabled,SamAccountName,Name,pwdLastSet,whenCreated,distinguishedName
  if ($computers) {
    $rows += $computers | ForEach-Object {
      [pscustomobject]@{
        ObjectClass        = 'computer'
        SamAccountName     = $_.SamAccountName
        Name               = $_.Name
        Enabled            = $_.Enabled
        UserPrincipalName  = $null
        PwdLastSet         = if ($_.pwdLastSet) { [DateTime]::FromFileTime([int64]$_.pwdLastSet) } else { $null }
        WhenCreated        = $_.whenCreated
        DistinguishedName  = $_.distinguishedName
      }
    }
  }
}

if (-not $rows -or $rows.Count -eq 0) {
  Write-Host "[+] No objects found with PASSWD_NOTREQD set." -ForegroundColor Green
  [pscustomobject]@{
    ObjectClass='';SamAccountName='';Name='';Enabled='';UserPrincipalName='';
    PwdLastSet='';WhenCreated='';DistinguishedName=''
  } | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "[*] Empty CSV with headers saved to: $OutCsv"
  return
}

$rows | Sort-Object ObjectClass, SamAccountName |
  Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

Write-Host ("[+] Found {0} object(s). CSV: {1}" -f $rows.Count, $OutCsv) -ForegroundColor Yellow
$rows | Select-Object ObjectClass,SamAccountName,Name,Enabled | Format-Table -AutoSize
