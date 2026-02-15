<#
.SYNOPSIS
    Creates EICAR test file to verify YARA detection.

.DESCRIPTION
    Creates the standard EICAR antivirus test file.
    This file is safe and triggers antivirus/YARA detection for testing.

.EXAMPLE
    .\create-eicar.ps1
    .\create-eicar.ps1 -Path "C:\TestFolder"
#>

param(
    [string]$Path = "$env:USERPROFILE\Downloads"
)

$eicarString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$testFile = Join-Path $Path "eicar-test-file.txt"

try {
    # Ensure directory exists
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }

    # Create EICAR file
    $eicarString | Out-File -FilePath $testFile -Encoding ASCII -NoNewline

    Write-Host "EICAR test file created: $testFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "To verify YARA detection manually:" -ForegroundColor Cyan
    Write-Host "  & 'C:\Program Files\yara\yara64.exe' 'C:\Program Files\yara\rules\malware_index.yar' '$testFile'"
    Write-Host ""
    Write-Host "Expected output:" -ForegroundColor Cyan
    Write-Host "  EICAR_Test_File $testFile"
    Write-Host ""
    Write-Host "If Wazuh FIM is monitoring $Path, an alert should appear in the dashboard." -ForegroundColor Yellow
}
catch {
    Write-Host "Error creating test file: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
