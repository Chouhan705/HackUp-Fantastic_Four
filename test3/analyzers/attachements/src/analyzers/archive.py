import zipfile
from pathlib import Path
from typing import Dict, Any
from src.analyzers.base import BaseAnalyzer

class ArchiveAnalyzer(BaseAnalyzer):
    name = "zip_inspector"

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        if not zipfile.is_zipfile(file_path):
            return {"is_flagged": False, "raw_output": {"ignored": "Not a ZIP archive."}}

        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                # 1. Check if it's password protected (encrypted)
                # We can't scan inside encrypted ZIPs, which is a common evasion tactic.
                is_encrypted = False
                for zinfo in z.infolist():
                    if zinfo.flag_bits & 0x1:
                        is_encrypted = True
                        break

                # 2. Check for risky file extensions inside the archive
                risky_extensions = ('.exe', '.vbs', '.js', '.bat', '.scr', '.ps1', '.wsf', '.xyz')

                file_names = z.namelist()
                risky_files_found = [f for f in file_names if f.lower().endswith(risky_extensions)]

                # Flag if it's encrypted OR if it contains risky files
                is_flagged = is_encrypted or len(risky_files_found) > 0

                return {
                    "is_flagged": is_flagged,
                    "raw_output": {
                        "is_encrypted": is_encrypted,
                        "file_count": len(file_names),
                        "risky_files_found": risky_files_found,
                        "all_files": file_names[:20] # List up to 20 files for preview
                    }
                }
        except Exception as e:
            return {"is_flagged": False, "raw_output": {"error": str(e)}}