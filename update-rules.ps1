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
        Write-Log "ERROR: Config file not found at $configFile. Run deploy-yara.ps1 first."
        exit 1
    }
    
    $config = Get-Content $configFile -Raw | ConvertFrom-Json
    $baseUrl = "https://raw.githubusercontent.com/$($config.GitHubRepo)/$($config.Branch)"
    
    Write-Log "Starting rule update from $($config.GitHubRepo)"
    
    # Ensure rules directory exists
    if (-not (Test-Path $rulesDir)) {
        New-Item -Path $rulesDir -ItemType Directory -Force | Out-Null
    }
    
    # Backup current rules
    $currentRules = "$rulesDir\malware_index.yar"
    $backupFile = "$rulesDir\malware_index.yar.bak"
    
    if (Test-Path $currentRules) {
        Copy-Item $currentRules $backupFile -Force
        Write-Log "Backed up current rules"
    }
    
    # Download latest rules
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    $tempFile = "$rulesDir\malware_index.yar.tmp"
    Invoke-WebRequest -Uri "$baseUrl/rules/malware_index.yar" -OutFile $tempFile -UseBasicParsing -TimeoutSec 60
    
    # Verify download
    if (Test-Path $tempFile) {
        $fileSize = (Get-Item $tempFile).Length
        
        if ($fileSize -gt 1000) {
            # Validate YARA syntax if yara binary exists
            $yaraExe = "$yaraDir\yara64.exe"
            $valid = $true
            
            if (Test-Path $yaraExe) {
                $testResult = & $yaraExe -w $tempFile "$env:TEMP" 2>&1
                if ($LASTEXITCODE -ne 0 -and $testResult -match "error") {
                    Write-Log "ERROR: Downloaded rules file has syntax errors"
                    $valid = $false
                }
            }
            
            if ($valid) {
                # Replace current rules with new ones
                Move-Item $tempFile $currentRules -Force
                Write-Log "SUCCESS: Rules updated ($fileSize bytes)"
                
                # Count rules
                $ruleCount = (Select-String -Path $currentRules -Pattern "^rule " -AllMatches).Matches.Count
                Write-Log "Rule count: $ruleCount"
                
                # Clean up backup
                if (Test-Path $backupFile) {
                    Remove-Item $backupFile -Force
                }
            }
            else {
                # Restore backup on validation failure
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                if (Test-Path $backupFile) {
                    Move-Item $backupFile $currentRules -Force
                    Write-Log "Restored backup due to validation failure"
                }
            }
        }
        else {
            Write-Log "ERROR: Downloaded file too small ($fileSize bytes), restoring backup"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            
            if (Test-Path $backupFile) {
                Move-Item $backupFile $currentRules -Force
            }
        }
    }
    else {
        Write-Log "ERROR: Download failed, file not created"
        
        if (Test-Path $backupFile) {
            Move-Item $backupFile $currentRules -Force
            Write-Log "Restored backup rules file"
        }
    }
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    
    # Restore backup on any failure
    $backupFile = "$rulesDir\malware_index.yar.bak"
    $currentRules = "$rulesDir\malware_index.yar"
    
    if (Test-Path $backupFile) {
        Move-Item $backupFile $currentRules -Force
        Write-Log "Restored backup rules file"
    }
    
    exit 1
}
