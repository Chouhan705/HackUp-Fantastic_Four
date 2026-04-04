import re
from pathlib import Path
from typing import Dict, Any
from analyzers.attachements.src.analyzers.base import BaseAnalyzer

class PDFAnalyzer(BaseAnalyzer):
    name = "pdf_structure"

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        try:
            # Read first few bytes to check if it's actually a PDF
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                if b'%PDF' not in header:
                    return {"is_flagged": False, "raw_output": {"ignored": "Not a PDF file."}}
                
                # Reset pointer and read the whole file to search for suspicious tags
                f.seek(0)
                content = f.read()

            # Dictionary of dangerous PDF tags to count
            suspicious_tags = {
                "JavaScript": b"/JavaScript",
                "JS": b"/JS",
                "OpenAction": b"/OpenAction",  # Triggers action when opened
                "Launch": b"/Launch",          # Launches external app/file
                "EmbeddedFiles": b"/EmbeddedFiles" # Contains dropped files
            }

            findings = {}
            is_flagged = False

            for tag_name, tag_bytes in suspicious_tags.items():
                # Count occurrences of the tag in the binary
                count = len(re.findall(tag_bytes, content))
                findings[tag_name] = count
                
                # Flag if ANY of these dangerous tags exist
                if count > 0:
                    is_flagged = True

            return {
                "is_flagged": is_flagged,
                "raw_output": findings
            }

        except Exception as e:
            return {"is_flagged": False, "raw_output": {"error": str(e)}}