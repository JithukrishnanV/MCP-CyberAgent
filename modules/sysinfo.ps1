# sysinfo.ps1
# Collects hashes from startup apps and outputs new hashes as CSV via stdout

# Optional parameter retained for compatibility
param (
    [string]$OutputFilePath
)

# STEP 1: Get startup commands
$applicationList = Get-CimInstance Win32_StartupCommand | 
    Where-Object { $_.Command -match '\\[^\\]+\.exe' } | 
    ForEach-Object {
        $command = $_.Command -replace '^\"', '' -replace '(\s--.*|\s/.*|"\s.*|"\s*$)', ''
        if ($command -like 'C:*') { $command }
    }

# STEP 2: Get SHA256 hashes
$currentHashes = foreach ($line in $applicationList) {
    if (Test-Path -Path $line) {
        (Get-FileHash -Path $line -Algorithm SHA256).Hash
    }
}

# STEP 3: Load default hash baseline (optional)
$defaultHashes = Get-Content -Path "Default-hash.txt" -ErrorAction SilentlyContinue

if (-Not $defaultHashes) {
    $defaultHashes = $currentHashes
}

# STEP 4: Filter for only *new/unmatched* hashes
$newHashes = foreach ($hash in $currentHashes) {
    if (-Not ($hash -in $defaultHashes)) {
        $hash
    }
}

# STEP 5: Output new hashes as CSV string (for Python)
$newHashesString = $newHashes -join ","
#hash for demp
#$newHashesString = "105c607308d533b85db17a2d5cdf775244f4d2682250fa9bbaa993f847eaef4c"
Write-Output $newHashesString
