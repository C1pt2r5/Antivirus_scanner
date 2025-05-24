import pefile
import math
import logging

logger = logging.getLogger(__name__)

def calculate_entropy(data):
    """
    Calculates the Shannon entropy of a given byte string.
    High entropy often indicates packed, compressed, or encrypted data.
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    
    # Calculate frequency of each byte
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    # Calculate entropy
    for count in counts:
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_pe_file(filepath):
    """
    Performs basic PE file analysis for suspicious characteristics.

    Args:
        filepath (str): The path to the potential PE file.

    Returns:
        dict: A dictionary of PE analysis findings.
    """
    pe_analysis = {
        "is_pe": False,
        "sections_entropy": {},
        "suspicious_imports": [],
        "suspicious_sections": [],
        "compile_time": None,
        "is_packed_heuristic": False
    }

    try:
        pe = pefile.PE(filepath)
        pe_analysis["is_pe"] = True
        logger.info(f"Analyzing PE file: {filepath}")

        # Compile Time
        try:
            pe_analysis["compile_time"] = pe.FILE_HEADER.TimeDateStamp
            logger.debug(f"  Compile Time: {pe_analysis['compile_time']}")
        except AttributeError:
            logger.warning("  Compile time not found in PE header.")

        # Section Entropy Analysis
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = calculate_entropy(section.get_data())
            pe_analysis["sections_entropy"][section_name] = entropy
            logger.debug(f"  Section: {section_name}, Entropy: {entropy:.2f}")

            # Heuristic for packed executables (high entropy in multiple sections or specific sections)
            if entropy > 7.0: # High entropy threshold
                pe_analysis["is_packed_heuristic"] = True
                logger.info(f"  High entropy detected in section '{section_name}' ({entropy:.2f}). Possible packing.")

        # Suspicious Imports (common for malware)
        suspicious_imports = [
            "LoadLibrary", "GetProcAddress", # Often used for dynamic loading
            "CreateRemoteThread", "WriteProcessMemory", # Process injection
            "NtQueryInformationProcess", "SetWindowsHookEx", # Anti-analysis/hooking
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next", # Process enumeration
            "URLDownloadToFile", "WinExec", # Downloaders/executors
            "RegSetValueEx", "RegCreateKeyEx", # Registry manipulation
            "CoCreateInstance", # COM object creation for persistence
            "CryptEncrypt", "CryptDecrypt", # Cryptographic functions (can be legitimate, but suspicious in context)
            "DeleteFile", "MoveFile", # File manipulation
            # Add more as you identify common malware imports
        ]
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_name = imp.name.decode('utf-8', errors='ignore') if imp.name else 'Ordinal'
                    if any(susp_import.lower() in import_name.lower() for susp_import in suspicious_imports):
                        pe_analysis["suspicious_imports"].append(f"{entry.dll.decode('utf-8', errors='ignore')}.{import_name}")
                        logger.info(f"  Suspicious import detected: {entry.dll.decode('utf-8', errors='ignore')}.{import_name}")

        # Suspicious Section Names (common in packers/malware)
        suspicious_section_names = [
            ".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", # Common legitimate
            ".upx", ".MPRESS", ".petite", ".fsg", ".RLPack", # Packer sections
            "UPX0", "UPX1", # UPX specific
            ".ndata", ".sdata", # Less common, sometimes seen in malware
            ".pdata", ".reloc", # Relocation/exception handling (legitimate but worth noting)
            # Add more as you identify suspicious names
        ]

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if section_name.lower() not in [n.lower() for n in suspicious_section_names]:
                 pe_analysis["suspicious_sections"].append(section_name)
                 logger.info(f"  Unusual section name detected: '{section_name}'")


    except pefile.PEFormatError as e:
        logger.debug(f"File {filepath} is not a valid PE file or is corrupted: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during PE analysis of {filepath}: {e}")
    finally:
        if 'pe' in locals() and pe:
            pe.close() # Ensure the file handle is closed
            
    return pe_analysis