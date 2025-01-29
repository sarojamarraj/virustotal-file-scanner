# VirusTotal File Scanner

**virustotal-file-scanner** is an automated file scanning tool that leverages the [VirusTotal API](https://www.virustotal.com/) to check the integrity of files for potential malicious content. This script allows users to scan files for malware and quarantine those identified as malicious, making it a useful tool for file security and threat detection.

## Features
- Scan files (e.g., `.exe`, `.jpg`, `.xml`, etc.) using VirusTotal's extensive malware database.
- Automatically detect malicious files and move them to a quarantine folder for further investigation.
- Integration with VirusTotal's API for accurate and efficient scans.
- Supports scanning multiple files in a directory.
  
## Prerequisites
- Docker (to run the container)
- VirusTotal API key

## Installation

## 1. Clone this repository:

   ```bash
   git clone https://github.com/sarojamarraj/virustotal-file-scanner.git
   cd virustotal-file-scanner

## 2. Configure API Key: To interact with the VirusTotal API, you'll need an API key.
   Get your VirusTotal API key.
   Create a .env file in the root directory of the project
   Example .env
   VT_API_KEY=your-api-key-here

   Alternatively, you can set the VT_API_KEY as an environment variable in your Docker container (explained below).
   

## 3.  Build the Docker Image:
   Make sure Docker is installed on your system. In the root directory of your project, build the Docker image:
   docker build -t virustotal-file-scanner .


## 4. Run the Docker Container.
   To run the scanner and scan files, use the following command. This will mount your local files and quarantine directories into the Docker container:
   docker run -v /path/to/your/files:/app/files -v /path/to/your/quarantine:/app/quarantine virustotal-file-scanner

Replace /path/to/your/files and /path/to/your/quarantine with the paths to your local directories where you want the files and quarantined files to be stored.

If you don't want to set up the .env file manually, you can pass the API key directly via the Docker command:
docker run -e VT_API_KEY=your-api-key-here -v /path/to/your/files:/app/files -v /path/to/your/quarantine:/app/quarantine virustotal-file-scanner


## 5. View the Results
Place the files you want to scan into the files/ directory.

After running the container, check the quarantine directory for any files flagged as malicious. The scanner will move any malicious files there.

Files and Directories
/app/files: The directory where the files to be scanned are stored.
/app/quarantine: The directory where any malicious files will be moved.


## Script Structure
scan.py: Main file scanning script that interacts with the VirusTotal API.
files/: Directory containing files to be scanned.
quarantine/: Directory for quarantining malicious files.

## Example Output
Scanning /app/files/chisel.exe...
Scan ID: <scan_id> - File is MALICIOUS (51 detections). Moving to quarantine.
Error scanning chisel.exe: [Errno 18] Invalid cross-device link: '/app/files/chisel.exe' -> '/app/quarantine/chisel.exe'

Scanning /app/files/test.xml...
File /app/files/test.xml is CLEAN.
