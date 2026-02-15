<#
.SYNOPSIS
    Deploys YARA malware scanner to Windows endpoint from GitHub repository.

.DESCRIPTION
    Downloads YARA binary, rules, and active response scripts from a GitHub
    repository. Configures scheduled task for automatic rule updates.
    Integrates with Wazuh agent for real-time malware detection.

.PARAMETER GitHubRepo
    GitHub repository in format "username/repo-name"

.PARAMETER Branch
    Repository branch to pull from. Default: main

.EXAMPLE
    .\deploy-yara.ps1 -GitHubRepo "mycompany/yara-deploy"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$GitHubRepo,
    
    [Parameter(Mandatory=$false)]
    [string]$Branch = "main"
)

$ErrorActionPreference = "Stop"

# Configuration
$baseUrl = "https://raw.githubusercontent.com/$GitHubRepo/$Branch"
$yaraDir = "C:\Program Files\yara"
$rulesDir = "$yaraDir\rules"
$wazuhARDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$logFile = "$yaraDir\deploy.log"

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Ensure directory exists for log
    $logDir = Split-Path $logFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
    
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        default { Write-Host $logEntry }
    }
}

# Download function with retry
function Get-FileFromGitHub {
    param(
        [string]$RelativePath,
        [string]$Destination,
        [int]$MaxRetries = 3
    )
    
    $url = "$baseUrl/$RelativePath"
    $retryCount = 0
    
    while ($retryCount -lt $MaxRetries) {
        try {
            Write-Log "Downloading: $RelativePath"
            
            # Use TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            Invoke-WebRequest -Uri $url -OutFile $Destination -UseBasicParsing -TimeoutSec 60
            
            if (Test-Path $Destination) {
                Write-Log "Successfully downloaded: $RelativePath"
                return $true
            }
        }
        catch {
            $retryCount++
            Write-Log "Download attempt $retryCount failed for $RelativePath : $($_.Exception.Message)" -Level "WARN"
            
            if ($retryCount -lt $MaxRetries) {
                Start-Sleep -Seconds (5 * $retryCount)
            }
        }
    }
    
    Write-Log "Failed to download $RelativePath after $MaxRetries attempts" -Level "ERROR"
    return $false
}

# Main deployment
try {
    Write-Log "=========================================="
    Write-Log "Starting YARA deployment"
    Write-Log "Repository: $GitHubRepo"
    Write-Log "Branch: $Branch"
    Write-Log "=========================================="

    # Create directories
    Write-Log "Creating directories..."
    New-Item -Path $rulesDir -ItemType Directory -Force | Out-Null
    Write-Log "Created: $rulesDir"

    # Download YARA binary
    $yaraExePath = "$yaraDir\yara64.exe"
    if (-not (Test-Path $yaraExePath)) {
        $success = Get-FileFromGitHub -RelativePath "yara64.exe" -Destination $yaraExePath
        if (-not $success) {
            throw "Failed to download YARA binary"
        }
    }
    else {
        Write-Log "YARA binary already exists, skipping download"
    }

    # Download rules
    $success = Get-FileFromGitHub -RelativePath "rules/malware_index.yar" -Destination "$rulesDir\malware_index.yar"
    if (-not $success) {
        throw "Failed to download YARA rules"
    }

    # Download update script
    $success = Get-FileFromGitHub -RelativePath "scripts/update-rules.ps1" -Destination "$yaraDir\update-rules.ps1"
    if (-not $success) {
        Write-Log "Failed to download update script" -Level "WARN"
    }

    # Store repository info for updates
    @{
        GitHubRepo = $GitHubRepo
        Branch = $Branch
        DeployedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    } | ConvertTo-Json | Out-File "$yaraDir\config.json" -Encoding UTF8

    # Install Wazuh active response scripts if agent is present
    if (Test-Path $wazuhARDir) {
        Write-Log "Wazuh agent detected, installing active response scripts..."
        
        $success = Get-FileFromGitHub -RelativePath "scripts/yara-scan.ps1" -Destination "$wazuhARDir\yara-scan.ps1"
        if (-not $success) {
            Write-Log "Failed to download yara-scan.ps1" -Level "WARN"
        }
        
        $success = Get-FileFromGitHub -RelativePath "scripts/yara.cmd" -Destination "$wazuhARDir\yara.cmd"
        if (-not $success) {
            Write-Log "Failed to download yara.cmd" -Level "WARN"
        }
    }
    else {
        Write-Log "Wazuh agent not detected at expected path" -Level "WARN"
    }

    # Register Windows Event source for YARA events
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("YARA")) {
            New-EventLog -LogName Application -Source "YARA"
            Write-Log "Registered YARA event source"
        }
    }
    catch {
        Write-Log "Could not register event source (may require admin): $($_.Exception.Message)" -Level "WARN"
    }

    # Create scheduled task for daily rule updates
    $taskName = "YARA-RuleUpdate"
    $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    
    if (-not $taskExists) {
        try {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$yaraDir\update-rules.ps1`""
            $trigger = New-ScheduledTaskTrigger -Daily -At "06:00"
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
            Write-Log "Created scheduled task: $taskName"
        }
        catch {
            Write-Log "Could not create scheduled task: $($_.Exception.Message)" -Level "WARN"
        }
    }
    else {
        Write-Log "Scheduled task already exists: $taskName"
    }

    # Verify installation
    Write-Log "Verifying installation..."
    
    if (Test-Path $yaraExePath) {
        $version = & $yaraExePath --version 2>&1
        Write-Log "YARA version: $version"
    }
    
    if (Test-Path "$rulesDir\malware_index.yar") {
        $ruleCount = (Select-String -Path "$rulesDir\malware_index.yar" -Pattern "^rule " -AllMatches).Matches.Count
        Write-Log "Rules file loaded: $ruleCount rules"
    }

    Write-Log "=========================================="
    Write-Log "YARA deployment completed successfully"
    Write-Log "=========================================="
    
    exit 0
}
catch {
    Write-Log "Deployment failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log $_.ScriptStackTrace -Level "ERROR"
    exit 1
}
