# YARA Deployment for Wazuh

Automated YARA malware detection deployment for Windows endpoints managed by Wazuh.

## Overview

This repository contains:

- **YARA rules**: Open-source malware detection signatures
- **Deployment scripts**: Automated installation and updates for Windows endpoints
- **Active response scripts**: Integration with Wazuh FIM for real-time scanning

## Requirements

- Windows endpoints with Wazuh agent installed
- PowerShell 5.1 or higher
- Network access to GitHub (raw.githubusercontent.com)

## Manual Setup

Download YARA binaries from the official releases and place in repository root:

1. Go to https://github.com/VirusTotal/yara/releases
2. Download the latest Windows zip (e.g., `yara-4.5.0-2326-win64.zip`)
3. Extract `yara64.exe` and `yarac64.exe`
4. Add both files to this repository root

## Deployment

Endpoints pull files automatically via Wazuh wodle configuration. Manual deployment:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/[YOUR-USERNAME]/yara-deploy/main/scripts/deploy-yara.ps1" -OutFile "deploy-yara.ps1"
.\deploy-yara.ps1 -GitHubRepo "[YOUR-USERNAME]/yara-deploy"
```

## File Locations on Endpoints

After deployment:

| Component | Path |
|-----------|------|
| YARA binary | `C:\Program Files\yara\yara64.exe` |
| Rules | `C:\Program Files\yara\rules\malware_index.yar` |
| Active response | `C:\Program Files (x86)\ossec-agent\active-response\bin\yara-scan.ps1` |
| Update script | `C:\Program Files\yara\update-rules.ps1` |
| Logs | `C:\Program Files\yara\update.log` |

## Rule Updates

Rules auto-update daily at 06:00 via scheduled task. Force immediate update:

```powershell
& "C:\Program Files\yara\update-rules.ps1"
```

## Testing

Create EICAR test file to verify detection:

```powershell
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$eicar | Out-File -FilePath "$env:USERPROFILE\Downloads\test-malware.txt" -Encoding ASCII
```

## Rule Sources

Rules are compiled from open-source projects:

- [YARA-Rules Community](https://github.com/Yara-Rules/rules)
- [Elastic Security](https://github.com/elastic/protections-artifacts)
- [Neo23x0 Signature Base](https://github.com/Neo23x0/signature-base)
- [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules)

## License

YARA rules are subject to their respective licenses. Scripts in this repository are provided as-is for security operations.
