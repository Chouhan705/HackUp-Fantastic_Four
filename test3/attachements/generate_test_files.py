import os

def create_eicar():
    """
    Creates the industry-standard EICAR antivirus test file.
    It is harmless, but AVs and VirusTotal will flag it as severe malware.
    """
    # This exact 68-byte string is the global standard AV test signature
    eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    filename = "eicar_test.txt"
    with open(filename, "w") as f:
        f.write(eicar_string)
    
    print(f"✅ Created {filename}")
    print("   -> Guaranteed to trigger Yara, score high risk, and get flagged by VirusTotal.")

def create_suspicious_bat():
    """
    Creates a suspicious-looking batch file that attempts to delete shadow copies.
    This is a common ransomware behavior, which VT will flag as suspicious.
    """
    bat_content = """@echo off
vssadmin.exe Delete Shadows /All /Quiet
bcdedit /set {default} recoveryenabled No
echo "System compromised" > C:\\ransom_note.txt
"""
    filename = "fake_ransomware.bat"
    with open(filename, "w") as f:
        f.write(bat_content)
        
    print(f"✅ Created {filename}")
    print("   -> Contains ransomware-like commands to test sandbox behavioral analysis.")

if __name__ == "__main__":
    print("Generating safe test files for Phish Pipeline...\n")
    create_eicar()
    create_suspicious_bat()
    print("\nDone. Please email these files to your monitored inbox to test the pipeline.")