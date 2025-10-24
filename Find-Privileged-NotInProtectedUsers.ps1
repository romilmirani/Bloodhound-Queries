<#
  Usage:
    .\Find-Privileged-NotInProtectedUsers.ps1
    .\Find-Privileged-NotInProtectedUsers.ps1 -Server corp.local -OutCsv C:\Temp\priv_not_protected.csv
#>

param(
  [string]$Server,
  [string]$OutCsv = ".\Privileged_NotIn_ProtectedUsers_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

$PrivilegedGroups = @(
  'Domain Admins','Enterprise Admins','Schema Admins',
  'Administrators','Account Operators','Backup Operators',
  'Server Operators','Print Operators'
)

if (-not $Server) { $Server = Read-Host "Enter domain FQDN or DC hostname/IP" }

$ProtectedUsersDN = $null
try { $ProtectedUsersDN = (Get-ADGroup -Server $Server -Identity 'Protected Users' -ErrorAction Stop).DistinguishedName } catch { }

$map = @{} # DN -> list of source groups
foreach ($g in $PrivilegedGroups) {
  try {
    $grp = Get-ADGroup -Server $Server -Identity $g -ErrorAction Stop
    Get-ADGroupMember -Server $Server -Identity $grp -Recursive -ErrorAction Stop |
      Where-Object { $_.objectClass -eq 'user' } |
      ForEach-Object {
        if (-not $map.ContainsKey($_.DistinguishedName)) { $map[$_.DistinguishedName] = [System.Collections.ArrayList]::new() }
        [void]$map[$_.DistinguishedName].Add($g)
      }
  } catch { }
}

if ($map.Count -eq 0) {
  Write-Host "No privileged users found (or groups not resolvable)." -ForegroundColor Yellow
  [pscustomobject]@{SamAccountName='';Name='';Enabled='';InProtectedUsers='';SourceGroups='';DistinguishedName=''} |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "CSV saved: $OutCsv"
  exit
}

$results = foreach ($dn in $map.Keys) {
  try {
    $u = Get-ADUser -Server $Server -Identity $dn -Properties samAccountName,name,enabled,memberOf
    $inPU = 'Unknown'
    if ($ProtectedUsersDN) {
      if ($u.MemberOf -and ($u.MemberOf -contains $ProtectedUsersDN)) { $inPU = 'Yes' }
      else {
        try {
          $all = Get-ADPrincipalGroupMembership -Server $Server -Identity $u.DistinguishedName -ErrorAction SilentlyContinue
          $inPU = if ($all -and ($all.DistinguishedName -contains $ProtectedUsersDN)) { 'Yes' } else { 'No' }
        } catch { $inPU = 'Unknown' }
      }
    }
    if ($inPU -ne 'Yes') {
      [pscustomobject]@{
        SamAccountName    = $u.SamAccountName
        Name              = $u.Name
        Enabled           = $u.Enabled
        InProtectedUsers  = $inPU
        SourceGroups      = ($map[$dn] -join ';')
        DistinguishedName = $u.DistinguishedName
      }
    }
  } catch { }
}

$results | Sort-Object SamAccountName | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host ("Saved {0} rows to: {1}" -f ($results | Measure-Object).Count, $OutCsv) -ForegroundColor Green

$results | Select SamAccountName,Name,InProtectedUsers,SourceGroups | Format-Table -AutoSize -First 15
