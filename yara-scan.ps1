<#
.SYNOPSIS
    Wazuh Active Response script for YARA scanning.

.DESCRIPTION
    Called by Wazuh when FIM detects file changes.
    Scans the changed file with YARA rules and logs matches
    to Windows Event Log for Wazuh collection.
#>

# Read input from Wazuh via stdin
$inputData = [Console]::In.ReadLine()

# Configuration
$yaraExe = "C:\Program Files\yara\yara64.exe"
$rulesFile = "C:\Program Files\yara\rules\malware_index.yar"
$logFile = "C:\Program Files\yara\scan.log"

# Logging function
function Write-ScanLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

try {
    # Parse Wazuh alert JSON
    $alert = $inputData | ConvertFrom-Json
    $filePath = $alert.parameters.alert.syscheck.path
    
    if ([string]::IsNullOrEmpty($filePath)) {
        exit 0
    }
}
catch {
    Write-ScanLog "ERROR: Failed to parse input - $($_.Exception.Message)"
    exit 1
}

# Validate paths exist
if (-not (Test-Path $filePath)) {
    exit 0
}

if (-not (Test-Path $yaraExe)) {
    Write-ScanLog "ERROR: YARA binary not found at $yaraExe"
    exit 1
}

if (-not (Test-Path $rulesFile)) {
    Write-ScanLog "ERROR: Rules file not found at $rulesFile"
    exit 1
}

# Skip certain extensions and paths to reduce noise
$skipExtensions = @('.log', '.tmp', '.etl', '.evtx', '.db', '.db-journal', '.ldb')
$skipPaths = @(
    'C:\Windows\Temp\wct',
    'C:\Windows\ServiceProfiles',
    'C:\Windows\Logs',
    'C:\Windows\System32\winevt',
    'C:\Windows\System32\config',
    'C:\Windows\System32\LogFiles',
    'C:\ProgramData\Microsoft\Windows Defender',
    'C:\Program Files\yara\',
    'C:\Program Files (x86)\ossec-agent\queue',
    'C:\Program Files (x86)\ossec-agent\logs'
)

# Check extension
$extension = [System.IO.Path]::GetExtension($filePath).ToLower()
if ($extension -in $skipExtensions) {
    exit 0
}

# Check path prefixes
foreach ($skipPath in $skipPaths) {
    if ($filePath -like "$skipPath*") {
        exit 0
    }
}

# Check file size (skip very large files to avoid performance impact)
try {
    $fileInfo = Get-Item $filePath -ErrorAction Stop
    $maxSizeMB = 50
    if ($fileInfo.Length -gt ($maxSizeMB * 1MB)) {
        Write-ScanLog "SKIP: File too large ($([math]::Round($fileInfo.Length/1MB, 2)) MB): $filePath"
        exit 0
    }
}
catch {
    # File may have been deleted or is inaccessible
    exit 0
}

# Perform YARA scan
try {
    Write-ScanLog "Scanning: $filePath"
    
    # Run YARA with timeout, limit matches
    $result = & $yaraExe -w -r -m $rulesFile $filePath 2>&1 | Select-Object -First 10
    
    if ($result -and $result -notmatch "error" -and $result.Length -gt 0) {
        foreach ($match in $result) {
            if (-not [string]::IsNullOrWhiteSpace($match) -and $match -notmatch "^warning:") {
                # Parse rule name from result (format: "RuleName [meta] filepath")
                $parts = $match -split '\s+', 2
                $ruleName = $parts[0]
                
                if ([string]::IsNullOrEmpty($ruleName)) {
                    continue
                }
                
                # Log match
                Write-ScanLog "MATCH: $ruleName on $filePath"
                
                # Write to Windows Event Log for Wazuh to collect
                $eventMessage = "wazuh-yara: $ruleName $filePath"
                
                try {
                    Write-EventLog -LogName Application -Source "YARA" -EventId 1001 -EntryType Warning -Message $eventMessage
                }
                catch {
                    # Fallback: write to separate log file that Wazuh can monitor via localfile
                    $alertLog = "C:\Program Files\yara\alerts.log"
                    $alertEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | YARA | $ruleName | $filePath"
                    $alertEntry | Out-File -FilePath $alertLog -Append -Encoding UTF8
                }
            }
        }
    }
}
catch {
    Write-ScanLog "ERROR: Scan failed - $($_.Exception.Message)"
    exit 1
}

exit 0
