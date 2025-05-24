import argparse
import sys
import os
import logging

# Configure root logger to output to console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from scanner import AntivirusScanner

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Antivirus Scanner with YARA, VirusTotal, and Heuristic Analysis.",
        formatter_class=argparse.RawTextHelpFormatter # For multiline help text
    )
    parser.add_argument("path", help="File or directory to scan.")
    parser.add_argument(
        "--yara-rules", 
        default="./yara_rules", 
        help="Directory containing YARA rules. (Default: ./yara_rules)"
    )
    parser.add_argument(
        "--virustotal", 
        action="store_true", 
        help="Enable VirusTotal lookup for file hashes.\n"
             "Requires VIRUSTOTAL_API_KEY in .env file and internet connection.\n"
             "Be mindful of API rate limits."
    )
    parser.add_argument(
        "--pe-analysis",
        action="store_true",
        help="Enable heuristic analysis for Windows PE (Portable Executable) files.\n"
             "Includes entropy calculation, suspicious imports, and section analysis."
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level. (Default: INFO)"
    )
    args = parser.parse_args()

    # Set the logging level dynamically
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    logger = logging.getLogger(__name__)
    logger.info("Antivirus Scanner started.")

    if not os.path.exists(args.path):
        logger.error(f"Error: Path '{args.path}' does not exist.")
        sys.exit(1)

    scanner = AntivirusScanner(
        yara_rules_dir=args.yara_rules,
        enable_virustotal=args.virustotal,
        enable_pe_analysis=args.pe_analysis
    )
    scanner.scan_path(args.path)
    logger.info("Antivirus Scanner finished.")

if __name__ == "__main__":
    main()