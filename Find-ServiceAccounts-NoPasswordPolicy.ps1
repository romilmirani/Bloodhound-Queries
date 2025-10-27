<#
  Find-ServiceAccounts-NoPasswordPolicy.ps1
  -----------------------------------------
  Usage:
    .\Find-ServiceAccounts-NoPasswordPolicy.ps1
    .\Find-ServiceAccounts-NoPasswordPolicy.ps1 -Server corp.local -OutCsv C:\Temp\svc_no_password_policy.csv
#>

param(
  [string]$Server,
  [string]$OutCsv = ".\ServiceAccounts_NoPasswordPolicy_$Server.csv"
)

if (-not $Server) {
  $Server = Read-Host "Enter domain FQDN or DC hostname/IP"
}

if (-not (Get-Module ActiveDirectory)) {
  try { Import-Module ActiveDirectory -ErrorAction Stop }
  catch { Write-Error "ActiveDirectory module not available (install RSAT)."; exit 1 }
}

# UAC flags
$UAC_DONT_EXPIRE = 0x10000  # 65536
$UAC_PWD_NOTREQD = 0x20     # 32

Write-Host "[*] Querying service accounts (users with SPNs) from: $Server ..." -ForegroundColor Cyan

$svcUsers = Get-ADUser -Server $Server -LDAPFilter "(servicePrincipalName=*)" `
            -Properties servicePrincipalName, userAccountControl, Enabled, samAccountName, name, pwdLastSet, msDS-ResultantPSO

if (-not $svcUsers) {
  Write-Host "[+] No user objects with SPNs found." -ForegroundColor Yellow
  [pscustomobject]@{SamAccountName='';Name='';Enabled='';PasswordNeverExpires='';PasswordNotRequired='';PwdLastSet='';SPNCount='';ResultantPSO=''} |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "CSV saved: $OutCsv"
  exit
}

$rows = foreach ($u in $svcUsers) {
  $uac = [int]$u.userAccountControl
  $pwdNever = (($uac -band $UAC_DONT_EXPIRE) -ne 0)
  $pwdNotReq = (($uac -band $UAC_PWD_NOTREQD) -ne 0)

  if ($pwdNever -or $pwdNotReq) {
    [pscustomobject]@{
      SamAccountName       = $u.SamAccountName
      Name                 = $u.Name
      Enabled              = $u.Enabled
      PasswordNeverExpires = $pwdNever
      PasswordNotRequired  = $pwdNotReq
      PwdLastSet           = if ($u.pwdLastSet) { [DateTime]::FromFileTime([int64]$u.pwdLastSet) } else { $null }
      SPNCount             = ($u.servicePrincipalName | Measure-Object).Count
      ResultantPSO         = $u.'msDS-ResultantPSO'
      DistinguishedName    = $u.DistinguishedName
    }
  }
}

if ($rows -and $rows.Count -gt 0) {
  $rows | Sort-Object SamAccountName | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host ("[+] Found {0} service account(s) with weak password settings. CSV: {1}" -f $rows.Count, $OutCsv) -ForegroundColor Green
  $rows | Select SamAccountName,Name,Enabled,PasswordNeverExpires,PasswordNotRequired,SPNCount | Format-Table -AutoSize
} else {
  Write-Host "[+] No service accounts with 'Password never expires' or 'Password not required' were found." -ForegroundColor Green
  [pscustomobject]@{SamAccountName='';Name='';Enabled='';PasswordNeverExpires='';PasswordNotRequired='';PwdLastSet='';SPNCount='';ResultantPSO='';DistinguishedName=''} |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "CSV saved: $OutCsv"
}
