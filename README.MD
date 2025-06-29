Project Structure
The file structure remains largely the same, but we'll add a pe_analyzer.py for PE file analysis.

  antivirus_scanner/
  ├── src/
  │   ├── __init__.py
  │   ├── yara_utils.py
  │   ├── virustotal_utils.py
  │   ├── pe_analyzer.py  <-- NEW
  │   └── scanner.py
  ├── yara_rules/
  │   └── sample_rules.yar
  ├── main.py
  └── .env




How to Run This Code
1. Prerequisites

Python 3.x: Ensure you have Python installed.
pip: Python's package installer.
2. Setup the Project

a.  Create the Project Directory:
bash mkdir antivirus_scanner cd antivirus_scanner

b.  Create Subdirectories:
bash mkdir src mkdir yara_rules

c.  Create Files:
Create the .env, yara_rules/sample_rules.yar, and the .py files inside src and at the root, as structured above. Copy-paste the respective code into each file.

3. Install Dependencies

Open your terminal in the antivirus_scanner directory and run:

Bash

pip install yara-python requests python-dotenv pefile
4. Obtain VirusTotal API Key

Go to VirusTotal.
Sign up for a free account if you don't have one.
Once logged in, navigate to your profile settings to find your API key.
Paste your API key into the .env file that you created:
VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY_HERE"
(Remember to replace YOUR_VIRUSTOTAL_API_KEY_HERE).
5. Run the Scanner

Open your terminal in the antivirus_scanner directory.

a.  Scan a single file with YARA and basic heuristics:

First, let's create a dummy file to test YARA and general file entropy.
```bash
echo "This is a suspicious string often found in malware" > test_string_file.txt
# Create a dummy executable for PE analysis (if you don't have a real one, it won't be a valid PE)
# For a real test, you'd need a valid PE file (e.g., Notepad.exe from a clean system)
touch dummy_executable.exe
```

Now, run the scanner:
```bash
python main.py test_string_file.txt
python main.py dummy_executable.exe --pe-analysis
```
The `test_string_file.txt` should show a YARA detection. For `dummy_executable.exe`, it will attempt PE analysis but correctly state it's not a valid PE file.
b.  Scan a legitimate executable with PE Analysis (for testing PE features):

If you're on Windows, you can try scanning a system executable like `notepad.exe`.
```bash
python main.py "C:\Windows\System32\notepad.exe" --pe-analysis
```
You should see PE analysis details like sections and imports, and it should show as clean (unless your `sample_rules.yar` has a false positive).
c.  Scan a single file with all features (YARA, VirusTotal, PE Analysis):

*(Remember to use a **safe, isolated environment like a virtual machine** when dealing with potentially malicious files for VirusTotal queries and real PE analysis.)*

```bash
python main.py /path/to/your/suspicious_file.exe --virustotal --pe-analysis
```
Replace `/path/to/your/suspicious_file.exe` with the actual path.
*Be aware of VirusTotal's public API rate limits (typically 4 requests/minute). If you scan too many files quickly, you might hit this limit.*
d.  Scan a directory with all features and debug logging:

```bash
python main.py /path/to/your/test_directory --virustotal --pe-analysis --log-level DEBUG
```
The `DEBUG` log level will provide much more verbose output, useful for understanding the scanner's internal workings.
Key Enhancements
Robust Error Handling:
Specific try-except blocks for FileNotFoundError, IOError, PermissionError, and requests exceptions (HTTP errors, connection errors, timeouts) ensure the scanner doesn't crash on common issues.
Error messages are stored in the results dictionary for each file, making it easier to track what went wrong.
Comprehensive Logging:
Integrated Python's logging module (import logging).
Log levels:
INFO: General progress messages, major detections.
WARNING: Minor issues, potential problems (e.g., YARA rule compilation error, VT rate limit).
ERROR: Significant errors that prevent scanning or API calls.
CRITICAL: High-severity detections (e.g., confirmed malicious file).
DEBUG: Detailed messages for development and troubleshooting.
The main.py now allows setting the logging level via the --log-level argument.
Heuristic Analysis - Entropy Check:
calculate_entropy(data) function computes the Shannon entropy for any byte string.
The scanner.py now calculates the overall file entropy and includes it in the results. High entropy can indicate packing or encryption.
Heuristic Analysis - PE File Analysis (pe_analyzer.py):
Uses the pefile library to parse Windows Portable Executable (PE) files.
analyze_pe_file(filepath) performs:
Section Entropy: Calculates entropy for each PE section, which is more granular than overall file entropy. High entropy in .text or .rdata sections is particularly suspicious for packed binaries.
Suspicious Imports: Checks for common API calls used by malware (e.g., process injection, anti-analysis, network activity).
Unusual Section Names: Looks for non-standard section names often used by packers or malware to hide code.
The scanner.py integrates this analysis, marking files as suspicious if PE analysis finds notable characteristics.#   A n t i v i r u s _ s c a n n e r 
 
 
