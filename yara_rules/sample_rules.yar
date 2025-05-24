rule example_malware_string {
    meta:
        author = "Your Name"
        description = "Detects a simple suspicious string"
    strings:
        $a = "This is a suspicious string often found in malware" nocase
        $b = { 4D 5A 90 00 } // MZ header, for example
    condition:
        $a or $b
}

rule large_executable {
    meta:
        author = "Your Name"
        description = "Detects executables over a certain size"
    strings:
        $mz = "MZ" at 0
    condition:
        $mz and filesize > 5MB
}