import magic
from pathlib import Path
from typing import Dict, Any
from src.analyzers.base import BaseAnalyzer

class MagicAnalyzer(BaseAnalyzer):
    name = "python-magic"

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        try:
            # Get MIME type (e.g., 'application/pdf')
            mime_type = magic.from_file(str(file_path), mime=True)
            # Get human-readable description (e.g., 'PDF document, version 1.5')
            description = magic.from_file(str(file_path))

            # Let's flag inherently risky file types (Executables, Scripts, Macros)
            # We will do deeper extension spoofing checks in the Risk Engine (Phase 4)
            risky_mimes = [
                "application/x-dosexec", # Windows PE (exe, dll)
                "application/x-executable", # ELF
                "text/x-shellscript",
            ]
            
            is_flagged = mime_type in risky_mimes

            return {
                "is_flagged": is_flagged,
                "raw_output": {
                    "mime_type": mime_type,
                    "description": description
                }
            }
        except Exception as e:
            return {"is_flagged": False, "raw_output": {"error": str(e)}}