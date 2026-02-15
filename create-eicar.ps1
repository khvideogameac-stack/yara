<#
.SYNOPSIS
    Creates EICAR test file to verify YARA detection.

.DESCRIPTION
    Creates the standard EICAR antivirus test file.
    This file is safe and triggers antivirus/YARA detection for testing.
    
    The EICAR test file is an industry-standard test file that all antivirus
    products should detect. It contains no actual malicious code.

.PARAMETER Path
    Directory where the test file will be created. Default: User's Downloads folder

.PARAMETER FileName
    Name of the test file. Default: eicar-test-file.txt

.EXAMPLE
    .\create-eicar.ps1
    
.EXAMPLE
    .\create-eicar.ps1 -Path "C:\TestFolder" -FileName "malware-test.txt"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Path = "$env:USERPROFILE\Downloads",
    
    [Parameter(Mandatory=$false)]
    [string]$FileName = "eicar-test-file.txt"
)

# EICAR test string - this is safe and not actual malware
$eicarString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

$testFile = Join-Path $Path $FileName

try {
    # Ensure directory exists
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
        Write-Host "Created directory: $Path" -ForegroundColor Gray
    }
    
    # Create EICAR file (ASCII encoding, no BOM, no newline)
    [System.IO.File]::WriteAllText($testFile, $eicarString, [System.Text.Encoding]::ASCII)
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "EICAR Test File Created Successfully" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Location: $testFile" -ForegroundColor White
    Write-Host ""
    
    # Verify file was created
    if (Test-Path $testFile) {
        $fileInfo = Get-Item $testFile
        Write-Host "File size: $($fileInfo.Length) bytes" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "To manually verify YARA detection:" -ForegroundColor Yellow
    Write-Host "  & 'C:\Program Files\yara\yara64.exe' 'C:\Program Files\yara\rules\malware_index.yar' '$testFile'" -ForegroundColor White
    Write-Host ""
    Write-Host "Expected output:" -ForegroundColor Yellow
    Write-Host "  EICAR_Test_File $testFile" -ForegroundColor Gray
    Write-Host ""
    
    # Check if Wazuh agent is installed
    $wazuhPath = "C:\Program Files (x86)\ossec-agent"
    if (Test-Path $wazuhPath) {
        Write-Host "Wazuh agent detected." -ForegroundColor Green
        Write-Host "If FIM is monitoring $Path, an alert should appear in the Wazuh dashboard." -ForegroundColor Yellow
    }
    else {
        Write-Host "Note: Wazuh agent not detected at standard path." -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Remember to delete the test file after testing!" -ForegroundColor Magenta
    Write-Host "  Remove-Item '$testFile'" -ForegroundColor White
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Host "Error creating test file: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
