import os
import time
import logging
from datetime import datetime

from .yara_utils import compile_yara_rules, scan_file_with_yara
from .virustotal_utils import get_file_hashes, query_virustotal, analyze_virustotal_report
from .pe_analyzer import analyze_pe_file, calculate_entropy # Import new PE analysis functions

# Configure logging for the scanner module
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AntivirusScanner:
    def __init__(self, yara_rules_dir="./yara_rules", enable_virustotal=False, enable_pe_analysis=False):
        self.yara_rules_dir = yara_rules_dir
        self.enable_virustotal = enable_virustotal
        self.enable_pe_analysis = enable_pe_analysis # New flag for PE analysis
        self.compiled_yara_rules = None
        self.scan_start_time = None
        self.total_files_scanned = 0
        self.total_malicious_files = 0
        logger.info("AntivirusScanner initialized.")

    def load_rules(self):
        """Loads and compiles YARA rules."""
        logger.info(f"Attempting to load YARA rules from: {self.yara_rules_dir}")
        self.compiled_yara_rules = compile_yara_rules(self.yara_rules_dir)
        if not self.compiled_yara_rules:
            logger.warning("Failed to load YARA rules. YARA scanning will be skipped.")
            return False
        logger.info("YARA rules successfully loaded.")
        return True

    def scan_file(self, filepath):
        """
        Scans a single file using YARA, VirusTotal, and PE analysis (if enabled).

        Args:
            filepath (str): The path to the file to scan.

        Returns:
            dict: A dictionary containing scan results.
        """
        self.total_files_scanned += 1
        results = {
            "filepath": filepath,
            "file_size": 0,
            "file_entropy": None,
            "yara_detections": [],
            "virustotal_report": None,
            "pe_analysis": None, # New field for PE analysis results
            "is_malicious": False,
            "scan_timestamp": datetime.now().isoformat(),
            "errors": []
        }

        try:
            if not os.path.exists(filepath):
                results["errors"].append("File not found.")
                logger.error(f"Scan failed for {filepath}: File not found.")
                return results
            
            file_size = os.path.getsize(filepath)
            results["file_size"] = file_size

            if file_size == 0:
                results["errors"].append("File is empty.")
                logger.info(f"Skipping empty file: {filepath}")
                return results

            # Calculate overall file entropy
            try:
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                    results["file_entropy"] = calculate_entropy(file_data)
                    logger.debug(f"File {filepath} entropy: {results['file_entropy']:.2f}")
            except Exception as e:
                results["errors"].append(f"Error calculating file entropy: {e}")
                logger.warning(f"Could not calculate entropy for {filepath}: {e}")

            logger.info(f"Scanning file: {filepath} (Size: {file_size} bytes)")

            # YARA Scan
            if self.compiled_yara_rules:
                yara_matches = scan_file_with_yara(filepath, self.compiled_yara_rules)
                if yara_matches:
                    results["yara_detections"] = [{"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in yara_matches]
                    results["is_malicious"] = True
                    logger.info(f"  [+] YARA Detections for {filepath}: {len(yara_matches)} rules matched.")
                else:
                    logger.debug(f"  [-] No YARA detections for {filepath}.")
            else:
                logger.warning("  [!] YARA rules not loaded. Skipping YARA scan.")

            # PE File Analysis (Heuristic)
            if self.enable_pe_analysis:
                # Check if it's a PE file before attempting analysis
                with open(filepath, 'rb') as f:
                    header = f.read(2) # Read first two bytes
                if header == b'MZ':
                    pe_analysis_results = analyze_pe_file(filepath)
                    results["pe_analysis"] = pe_analysis_results
                    if pe_analysis_results["is_pe"]:
                        if pe_analysis_results["is_packed_heuristic"] or \
                           pe_analysis_results["suspicious_imports"] or \
                           pe_analysis_results["suspicious_sections"]:
                            results["is_malicious"] = True # Mark as suspicious based on PE analysis
                            logger.info(f"  [!] PE Analysis found suspicious characteristics in {filepath}.")
                            if pe_analysis_results["is_packed_heuristic"]: logger.info("    - Possible packing detected.")
                            if pe_analysis_results["suspicious_imports"]: logger.info(f"    - Suspicious imports: {len(pe_analysis_results['suspicious_imports'])} found.")
                            if pe_analysis_results["suspicious_sections"]: logger.info(f"    - Unusual sections: {len(pe_analysis_results['suspicious_sections'])} found.")
                        else:
                             logger.debug(f"  [+] PE Analysis of {filepath} found no obvious suspicious characteristics.")
                    else:
                        logger.debug(f"  [-] File {filepath} is not a valid PE file for advanced analysis.")
                else:
                    logger.debug(f"  [-] File {filepath} is not a PE file. Skipping PE analysis.")


            # VirusTotal Scan
            if self.enable_virustotal:
                file_hashes = get_file_hashes(filepath)
                if file_hashes and file_hashes["sha256"]:
                    logger.info(f"  [+] Querying VirusTotal for SHA256: {file_hashes['sha256']}")
                    vt_raw_report = query_virustotal(file_hashes["sha256"])
                    vt_summary = analyze_virustotal_report(vt_raw_report)
                    results["virustotal_report"] = vt_summary
                    if vt_summary["detected"]:
                        results["is_malicious"] = True
                        logger.warning(f"    [!] VirusTotal: Malicious (Positives: {vt_summary['positives']}/{vt_summary['total']}) for {filepath}")
                        logger.info(f"      Details: {vt_summary['details']}")
                    else:
                        logger.info(f"    [+] VirusTotal: Clean (Positives: {vt_summary['positives']}/{vt_summary['total']}) for {filepath}")
                else:
                    results["errors"].append("Could not generate SHA256 hash for VirusTotal lookup.")
                    logger.warning(f"  [!] Could not generate SHA256 hash for VirusTotal lookup for {filepath}.")
            
        except PermissionError:
            results["errors"].append("Permission denied to read file.")
            logger.error(f"Permission denied for {filepath}.")
        except IOError as e:
            results["errors"].append(f"I/O error during scan: {e}")
            logger.error(f"I/O error scanning {filepath}: {e}")
        except Exception as e:
            results["errors"].append(f"An unexpected error occurred during scan: {e}")
            logger.exception(f"An unexpected error occurred during scan of {filepath}.")
        
        if results["is_malicious"]:
            self.total_malicious_files += 1
            logger.critical(f"POTENTIALLY MALICIOUS FILE DETECTED: {filepath}")
        
        return results

    def scan_path(self, target_path):
        """
        Scans a file or recursively scans a directory.

        Args:
            target_path (str): The path to the file or directory to scan.
        """
        self.scan_start_time = datetime.now()
        self.total_files_scanned = 0
        self.total_malicious_files = 0
        
        if not self.load_rules():
            logger.error("Skipping scan as YARA rules could not be loaded.")
            return # Exit if rules couldn't be loaded

        all_scan_results = []

        if os.path.isfile(target_path):
            logger.info(f"Starting scan of single file: {target_path}")
            results = self.scan_file(target_path)
            all_scan_results.append(results)
        elif os.path.isdir(target_path):
            logger.info(f"Starting recursive scan of directory: {target_path}")
            for root, _, files in os.walk(target_path):
                for file_name in files:
                    filepath = os.path.join(root, file_name)
                    results = self.scan_file(filepath)
                    all_scan_results.append(results)
                    # Be mindful of VirusTotal API rate limits
                    if self.enable_virustotal:
                        time.sleep(1) # Add a small delay between VT queries
        else:
            logger.error(f"Invalid path provided: {target_path}")
            print(f"Error: Path '{target_path}' is neither a file nor a directory.")
            return

        self._print_summary(all_scan_results)
        
        scan_end_time = datetime.now()
        duration = scan_end_time - self.scan_start_time
        logger.info(f"Scan finished. Total duration: {duration}")
        logger.info(f"Total files scanned: {self.total_files_scanned}")
        logger.info(f"Total malicious files detected: {self.total_malicious_files}")

        return all_scan_results

    def _print_summary(self, results):
        """Prints a summary of the scan results to console."""
        print("\n" + "="*60)
        print("ANTIVIRUS SCAN SUMMARY".center(60))
        print("="*60)
        
        if not results:
            print("No files were scanned or no results to display.")
            return

        for res in results:
            status_indicator = "[CLEAN]"
            if res.get("is_malicious"):
                status_indicator = "[!!! MALICIOUS !!!]"
            elif res.get("errors"):
                status_indicator = "[ERROR/SKIPPED]"

            print(f"\n{status_indicator} File: {res['filepath']}")
            print(f"  Size: {res['file_size']} bytes")
            if res['file_entropy'] is not None:
                print(f"  Entropy: {res['file_entropy']:.2f}")

            if res["yara_detections"]:
                print(f"  YARA Detections ({len(res['yara_detections'])} rules matched):")
                for det in res["yara_detections"]:
                    print(f"    - Rule: {det['rule']} (Tags: {', '.join(det['tags'])})")
            
            if res["pe_analysis"] and res["pe_analysis"]["is_pe"]:
                print("  PE Analysis:")
                if res["pe_analysis"]["is_packed_heuristic"]:
                    print("    - Heuristic: Possible packing detected (High Entropy).")
                if res["pe_analysis"]["suspicious_imports"]:
                    print(f"    - Suspicious Imports: {len(res['pe_analysis']['suspicious_imports'])} found (e.g., {', '.join(res['pe_analysis']['suspicious_imports'][:3])}...)")
                if res["pe_analysis"]["suspicious_sections"]:
                    print(f"    - Unusual Section Names: {len(res['pe_analysis']['suspicious_sections'])} found (e.g., {', '.join(res['pe_analysis']['suspicious_sections'][:3])}...)")
                # Add more PE details if desired
            
            if res["virustotal_report"]:
                vt_sum = res["virustotal_report"]
                print(f"  VirusTotal Report: Detected: {vt_sum['detected']} | Positives: {vt_sum['positives']}/{vt_sum['total']}")
                if vt_sum["detected"]:
                    print(f"    Details: {vt_sum['details']}")
            
            if res["errors"]:
                print("  Errors/Warnings:")
                for error_msg in res["errors"]:
                    print(f"    - {error_msg}")
        
        print("\n" + "="*60)
        print(f"Scan completed in {(datetime.now() - self.scan_start_time).total_seconds():.2f} seconds.".center(60))
        print(f"Total files scanned: {self.total_files_scanned}".center(60))
        print(f"Potentially malicious files: {self.total_malicious_files}".center(60))
        print("="*60)