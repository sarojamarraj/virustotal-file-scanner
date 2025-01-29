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

2. Install required Python libraries:
   pip install -r requirements.txt

3. Set up your VirusTotal API key:
   Rename the .env.example file to .env and paste your VirusTotal API key inside the VT_API_KEY variable.
   cp .env.example .env

4. Alternatively, you can set the VT_API_KEY directly in the script for testing purposes (not recommended for production).



## Usage
Place the files you want to scan into the files/ directory.

Run the scanner with the following command:
python scan.py

The script will scan all files in the files/ directory. Malicious files will be moved to the quarantine/ directory.
Check the logs or the output terminal for the results of each file scan.

## Script Structure
scan.py: Main file scanning script that interacts with the VirusTotal API.
files/: Directory containing files to be scanned.
quarantine/: Directory for quarantining malicious files.
requirements.txt: Python dependencies for the project.
.env.example: Example file to set up your VirusTotal API key.

## Example Output
Scanning /app/files/chisel.exe...
Scan ID: <scan_id> - File is MALICIOUS (51 detections). Moving to quarantine.
Error scanning chisel.exe: [Errno 18] Invalid cross-device link: '/app/files/chisel.exe' -> '/app/quarantine/chisel.exe'

Scanning /app/files/test.xml...
File /app/files/test.xml is CLEAN.
