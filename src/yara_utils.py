import yara
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def compile_yara_rules(rule_directory):
    """
    Compiles YARA rules from a specified directory.

    Args:
        rule_directory (str): The path to the directory containing YARA .yar files.

    Returns:
        dict: A dictionary where keys are rule filenames (without .yar) and values
              are compiled YARA rule objects, or None if compilation fails.
    """
    compiled_rules = {}
    if not os.path.isdir(rule_directory):
        logger.error(f"Error: YARA rule directory '{rule_directory}' not found.")
        return None

    logger.info(f"Compiling YARA rules from: {rule_directory}")
    for filename in os.listdir(rule_directory):
        if filename.endswith(".yar"):
            filepath = os.path.join(rule_directory, filename)
            try:
                compiled_rules[filename.replace(".yar", "")] = yara.compile(filepath=filepath)
                logger.info(f"  - Successfully compiled {filename}")
            except yara.Error as e:
                logger.warning(f"  - Error compiling YARA rule {filepath}: {e}")
            except Exception as e:
                logger.error(f"  - Unexpected error during YARA rule compilation for {filepath}: {e}")
    
    if not compiled_rules:
        logger.warning(f"No YARA rules were successfully compiled from {rule_directory}.")
        return None
    
    return compiled_rules

def scan_file_with_yara(filepath, compiled_rules):
    """
    Scans a single file using the compiled YARA rules.

    Args:
        filepath (str): The path to the file to scan.
        compiled_rules (dict): A dictionary of compiled YARA rule objects.

    Returns:
        list: A list of YARA matches found in the file.
    """
    matches = []
    if not os.path.exists(filepath):
        logger.debug(f"File not found for YARA scan: {filepath}")
        return []
    if os.path.getsize(filepath) == 0:
        logger.debug(f"Skipping empty file for YARA scan: {filepath}")
        return []

    try:
        for rule_name, rule_obj in compiled_rules.items():
            try:
                # The .match() method can take a filepath directly for scanning.
                file_matches = rule_obj.match(filepath)
                if file_matches:
                    matches.extend(file_matches)
            except yara.Error as e:
                logger.warning(f"Error scanning {filepath} with YARA rule {rule_name}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during YARA scan of {filepath} with rule {rule_name}: {e}")
    except Exception as e:
        logger.error(f"An unhandled error occurred during YARA scan of {filepath}: {e}")
    
    return matches