import os
import time
import vt
import shutil

# VirusTotal API Key (Ensure it's set as an environment variable)
VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    print("Error: VT_API_KEY environment variable not set.")
    exit(1)

# Directories
FILES_DIR = "/app/files"
QUARANTINE_DIR = "/app/quarantine"

def scan_file(client, file_path):
    """Uploads a file to VirusTotal for scanning and retrieves results."""
    file_name = os.path.basename(file_path)

    try:
        print(f"Scanning {file_path}...")

        # Upload the file to VirusTotal
        with open(file_path, "rb") as f:
            analysis = client.scan_file(f, wait_for_completion=True)

        # Get analysis results
        scan_id = analysis.id
        print(f"Scan ID: {scan_id} - Waiting for results...")

        time.sleep(10)  # Delay to allow processing

        report = client.get_object(f"/analyses/{scan_id}")

        # Get detection count
        malicious_count = report.stats.get("malicious", 0)

        if malicious_count > 0:
            print(f"File {file_name} is MALICIOUS ({malicious_count} detections). Moving to quarantine.")
            quarantine_file(file_path)
        else:
            print(f"File {file_name} is CLEAN.")

    except vt.error.APIError as e:
        print(f"Error scanning {file_name}: {e}")
    except Exception as e:
        print(f"Unexpected error scanning {file_name}: {e}")

def quarantine_file(file_path):
    """Moves malicious files to quarantine directory, ensuring cross-device support."""
    try:
        destination = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))
        shutil.copy2(file_path, destination)  # Copy to quarantine
        os.remove(file_path)  # Remove original after copying
        print(f"Moved to quarantine: {destination}")
    except Exception as e:
        print(f"Error moving {file_path} to quarantine: {e}")

def main():
    """Main function to scan all files in the target directory."""
    if not os.path.exists(FILES_DIR):
        print(f"Error: {FILES_DIR} does not exist.")
        return

    client = vt.Client(VT_API_KEY)

    try:
        for file_name in os.listdir(FILES_DIR):
            file_path = os.path.join(FILES_DIR, file_name)
            if os.path.isfile(file_path):
                scan_file(client, file_path)
    finally:
        client.close()

if __name__ == "__main__":
    main()
