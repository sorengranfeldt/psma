$locations = @(
    "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll",
    "C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll",
    "C:\Program Files\Reference Assemblies\Microsoft\WindowsPowerShell\3.0\System.Management.Automation.dll",
    "C:\Program Files (x86)\Reference Assemblies\Microsoft\WindowsPowerShell\3.0\System.Management.Automation.dll",
    "C:\Windows\System32\WindowsPowerShell\v1.0\System.Management.Automation.dll"
)

Write-Host "Searching for System.Management.Automation.dll..."
foreach ($location in $locations) {
    if (Test-Path $location) {
        Write-Host "FOUND: $location"
    } else {
        Write-Host "NOT FOUND: $location"
    }
}

Write-Host "`nSearching all drives for PowerShell assemblies..."
Get-ChildItem -Path "C:\" -Filter "System.Management.Automation.dll" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "FOUND AT: $($_.FullName)"
}
