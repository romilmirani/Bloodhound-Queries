<#
  Find-Priv-NoAccountNotDelegated.ps1
  -----------------------------------
  Usage:
  Find-Priv-NoAccountNotDelegated.ps1 -Server corp.local
#>

param(
  [string]$Server,
  [string]$OutCsv = ".\PrivUsers_NoAccountNotDelegated_$Server.csv"
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
  Write-Error "ActiveDirectory module not found. Install RSAT."
  exit 1
}

if (-not $Server) {
  $tmp = Read-Host "Enter DC hostname/IP or domain FQDN (Enter = default)"
  if ($tmp) { $Server = $tmp }
}

$PrivGroups = @(
  'Domain Admins','Enterprise Admins','Schema Admins','Administrators',
  'Account Operators','Server Operators','Backup Operators','Print Operators'
)

$results = @()

foreach ($g in $PrivGroups) {
  try {
    $members = if ($Server) {
      Get-ADGroupMember -Identity $g -Server $Server -Recursive -ErrorAction Stop
    } else {
      Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop
    }
  } catch {
    Write-Warning "Could not read members of '$g' : $($_.Exception.Message)"
    continue
  }

  foreach ($m in $members) {
    if ($m.ObjectClass -ne 'user') { continue }

    try {
      $u = if ($Server) {
        Get-ADUser -Identity $m.DistinguishedName -Server $Server `
          -Properties SamAccountName,Name,Enabled,AccountNotDelegated,memberOf,DistinguishedName
      } else {
        Get-ADUser -Identity $m.DistinguishedName `
          -Properties SamAccountName,Name,Enabled,AccountNotDelegated,memberOf,DistinguishedName
      }
    } catch {
      Write-Warning "Failed to read user $($m.DistinguishedName) : $($_.Exception.Message)"
      continue
    }

    $inPU = ($u.memberOf -like 'CN=Protected Users,*') -as [bool]

    if (-not $u.AccountNotDelegated) {
      $results += [pscustomobject]@{
        SourceGroup         = $g
        SamAccountName      = $u.SamAccountName
        Name                = $u.Name
        Enabled             = $u.Enabled
        InProtectedUsers    = $inPU
        AccountNotDelegated = $false
        DistinguishedName   = $u.DistinguishedName
      }
    }
  }
}

if ($results.Count -gt 0) {
  $results | Sort-Object SourceGroup, SamAccountName |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "[!] Found $($results.Count) privileged user(s) WITHOUT 'Cannot be delegated'. CSV: $OutCsv" -ForegroundColor Yellow
  $results | Select SourceGroup,SamAccountName,Name,Enabled,InProtectedUsers,DistinguishedName | Format-Table -AutoSize
} else {
  Write-Host "[+] All checked privileged users have 'Cannot be delegated' set." -ForegroundColor Green
  [pscustomobject]@{SourceGroup='';SamAccountName='';Name='';Enabled='';InProtectedUsers='';AccountNotDelegated='';DistinguishedName=''} |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "Empty CSV saved: $OutCsv"
}
