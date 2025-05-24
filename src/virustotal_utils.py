import hashlib
import requests
import json
import os
import logging
from dotenv import load_dotenv

# Configure logging
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"

def get_file_hashes(filepath):
    """
    Generates MD5, SHA1, and SHA256 hashes for a given file.

    Args:
        filepath (str): The path to the file.

    Returns:
        dict: A dictionary containing 'md5', 'sha1', and 'sha256' hashes,
              or None if the file cannot be read.
    """
    hashes = {
        "md5": None,
        "sha1": None,
        "sha256": None
    }
    try:
        # Use a buffer to handle large files efficiently
        hasher_md5 = hashlib.md5()
        hasher_sha1 = hashlib.sha1()
        hasher_sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher_md5.update(chunk)
                hasher_sha1.update(chunk)
                hasher_sha256.update(chunk)

        hashes["md5"] = hasher_md5.hexdigest()
        hashes["sha1"] = hasher_sha1.hexdigest()
        hashes["sha256"] = hasher_sha256.hexdigest()
        
    except FileNotFoundError:
        logger.error(f"Error: File not found to hash: {filepath}")
        return None
    except IOError as e:
        logger.error(f"Error reading file {filepath} for hashing: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred while generating hashes for {filepath}: {e}")
        return None
    return hashes

def query_virustotal(file_hash):
    """
    Queries VirusTotal for a file hash.

    Args:
        file_hash (str): The SHA256 hash of the file to query.

    Returns:
        dict: The JSON response from VirusTotal API, or None if an error occurs.
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY not found in .env. Skipping VirusTotal query.")
        return None

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(f"{VIRUSTOTAL_API_URL}{file_hash}", headers=headers, timeout=10) # Add timeout
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        data = response.json()
        return data
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.info(f"File hash {file_hash} not found on VirusTotal (expected for clean files).")
        elif e.response.status_code == 401:
            logger.error("VirusTotal API Key is invalid or unauthorized.")
        elif e.response.status_code == 429:
            logger.warning("VirusTotal API rate limit exceeded. Please wait and try again.")
        else:
            logger.error(f"HTTP error querying VirusTotal for {file_hash}: {e} (Status: {e.response.status_code})")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error querying VirusTotal for {file_hash}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        logger.error(f"Timeout occurred while querying VirusTotal for {file_hash}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"An unexpected request error occurred while querying VirusTotal for {file_hash}: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON response from VirusTotal for {file_hash}: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred while querying VirusTotal for {file_hash}: {e}")
        return None

def analyze_virustotal_report(vt_report):
    """
    Parses and summarizes the VirusTotal report.

    Args:
        vt_report (dict): The JSON report from VirusTotal.

    Returns:
        dict: A summarized report with 'detected', 'positives', 'total', and 'details'.
    """
    summary = {
        "detected": False,
        "positives": 0,
        "total": 0,
        "details": "No malicious detections or report unavailable."
    }

    if not vt_report or "data" not in vt_report:
        logger.debug("No valid VirusTotal report received.")
        return summary

    attributes = vt_report["data"].get("attributes", {})
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    
    summary["positives"] = last_analysis_stats.get("malicious", 0)
    summary["total"] = sum(last_analysis_stats.values()) # Sum of all categories

    if summary["positives"] > 0:
        summary["detected"] = True
        detected_by = []
        # Iterate through actual analysis results to get vendor names
        for vendor, result in attributes.get("last_analysis_results", {}).items():
            if result.get("category") == "malicious":
                detected_by.append(f"{vendor}: {result.get('result', 'N/A')}")
        
        if detected_by:
            summary["details"] = f"Detected by: {', '.join(detected_by)}"
        else:
            summary["details"] = "Malicious detections but no specific vendor details."
    
    logger.debug(f"VirusTotal summary generated: {summary}")
    return summary