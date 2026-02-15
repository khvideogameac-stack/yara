<#
.SYNOPSIS
    Updates YARA rules from GitHub repository.

.DESCRIPTION
    Downloads latest YARA rules from configured GitHub repository.
    Run manually or via scheduled task for automatic updates.
#>

$ErrorActionPreference = "SilentlyContinue"

$yaraDir = "C:\Program Files\yara"
$rulesDir = "$yaraDir\rules"
$configFile = "$yaraDir\config.json"
$logFile = "$yaraDir\update.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

try {
    # Load configuration
    if (-not (Test-Path $configFile)) {
        Write-Log "ERROR: Config file not found. Run deploy-yara.ps1 first."
        exit 1
    }

    $config = Get-Content $configFile | ConvertFrom-Json
    $baseUrl = "https://raw.githubusercontent.com/$($config.GitHubRepo)/$($config.Branch)"

    Write-Log "Starting rule update from $($config.GitHubRepo)"

    # Backup current rules
    $backupFile = "$rulesDir\malware_index.yar.bak"
    if (Test-Path "$rulesDir\malware_index.yar") {
        Copy-Item "$rulesDir\malware_index.yar" $backupFile -Force
    }

    # Download latest rules
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "$baseUrl/rules/malware_index.yar" -OutFile "$rulesDir\malware_index.yar" -UseBasicParsing -TimeoutSec 60

    # Verify download
    if (Test-Path "$rulesDir\malware_index.yar") {
        $fileSize = (Get-Item "$rulesDir\malware_index.yar").Length
        if ($fileSize -gt 1000) {
            Write-Log "SUCCESS: Rules updated ($fileSize bytes)"

            # Clean up backup
            if (Test-Path $backupFile) {
                Remove-Item $backupFile -Force
            }
        }
        else {
            Write-Log "ERROR: Downloaded file too small, restoring backup"
            if (Test-Path $backupFile) {
                Move-Item $backupFile "$rulesDir\malware_index.yar" -Force
            }
        }
    }
    else {
        Write-Log "ERROR: Download failed, restoring backup"
        if (Test-Path $backupFile) {
            Move-Item $backupFile "$rulesDir\malware_index.yar" -Force
        }
    }
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"

    # Restore backup on failure
    $backupFile = "$rulesDir\malware_index.yar.bak"
    if (Test-Path $backupFile) {
        Move-Item $backupFile "$rulesDir\malware_index.yar" -Force
        Write-Log "Restored backup rules file"
    }

    exit 1
}
