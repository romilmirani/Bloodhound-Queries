<#
  Find-UnconstrainedDelegation.ps1
  ------------------------------------------
    - Example usage:
        .\Find-UnconstrainedDelegation.ps1
        .\Find-UnconstrainedDelegation.ps1 -Domain corp.local -OutCsv C:\temp\ud.csv
#>

param(
  [string]$Domain,
  [string]$OutCsv = ".\UnconstrainedDelegation_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

$UAC_UNCONSTRAINED = 0x80000

if (-not $Domain) {
  $Domain = Read-Host "Enter the domain name (e.g. corp.local)"
}

Write-Host "`n[*] Running PowerView lookup for domain: $Domain" -ForegroundColor Cyan

if (-not (Get-Command Get-NetComputer -ErrorAction SilentlyContinue)) {
  Write-Error "Get-NetComputer not found. Please load PowerView first (Import-Module PowerView) and try again."
  exit 1
}

# Query the domain and filter by the delegation flag
$results = Get-NetComputer -Domain $Domain -FullData |
           Where-Object { $_.UserAccountControl -band $UAC_UNCONSTRAINED } |
           Select-Object @{Name='Domain';Expression={$Domain}},
                         @{Name='Name';Expression={$_.Name}},
                         @{Name='UserAccountControl';Expression={$_.UserAccountControl}}

# Print & save
if ($results -and $results.Count -gt 0) {
  Write-Host "`n[!] Found $($results.Count) object(s) with Unconstrained Delegation." -ForegroundColor Yellow
  $results | Format-Table -AutoSize
  $results | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
  Write-Host "`n[+] CSV saved to: $OutCsv" -ForegroundColor Green
} else {
  Write-Host "`n[+] No objects with Unconstrained Delegation found in $Domain." -ForegroundColor Green
}
