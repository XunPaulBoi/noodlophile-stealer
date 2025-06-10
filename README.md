import os
import re
import hashlib

# Indicators of compromise (IOCs)
SUSPICIOUS_FILENAMES = [
    "CapCut.exe",
    "AICore.dll",
    "srchost.exe",
    "Install.bat",
    "Video Dream MachineAI.mp4.exe"
]
SUSPICIOUS_PATTERNS = [
    r".+\.mp4\.exe$",    # double extension
    r".+\.doc\.bat$",    # disguised batch files
    r"[\u202E]"          # right-to-left override character (obfuscation)
]

def hash_file(filepath):
    """Generate SHA-256 hash of a file"""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def scan_directory(directory):
    print(f"🔍 Scanning: {directory}")
    flagged = []

    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)

            # Check against known suspicious filenames
            if filename in SUSPICIOUS_FILENAMES:
                flagged.append((filepath, "⚠️ Known malicious filename"))

            # Check for suspicious patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, filename):
                    flagged.append((filepath, "⚠️ Suspicious filename pattern"))

    return flagged

def main():
    target_dir = input("Enter the directory to scan (e.g., your Downloads folder): ").strip()
    if not os.path.isdir(target_dir):
        print("❌ Invalid directory.")
        return

    results = scan_directory(target_dir)

    if results:
        print("\n🚨 Suspicious files found:")
        for filepath, reason in results:
            print(f"{reason}: {filepath}")
            print(f"    🔐 SHA-256: {hash_file(filepath)}")
    else:
        print("\n✅ No suspicious files detected.")

if __name__ == "__main__":
    main()

