# VirusTotal File Scanner

**virustotal-file-scanner** is an automated file scanning tool that leverages the [VirusTotal API](https://www.virustotal.com/) to check the integrity of files for potential malicious content. This script allows users to scan files for malware and quarantine those identified as malicious, making it a useful tool for file security and threat detection.

## Features
- Scan files (e.g., `.exe`, `.jpg`, `.xml`, etc.) using VirusTotal's extensive malware database.
- Automatically detect malicious files and move them to a quarantine folder for further investigation.
- Integration with VirusTotal's API for accurate and efficient scans.
- Supports scanning multiple files in a directory.
  
## Prerequisites
- **Python 3.x**: Ensure Python 3 is installed on your machine.
- **VirusTotal API Key**: You'll need to obtain an API key from [VirusTotal](https://www.virustotal.com/) in order to use the API.

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/sarojamarraj/virustotal-file-scanner.git
   cd virustotal-file-scanner
