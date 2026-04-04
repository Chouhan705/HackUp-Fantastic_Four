from pathlib import Path
from typing import Dict, Any
from oletools.olevba import VBA_Parser
from src.analyzers.base import BaseAnalyzer

class OfficeAnalyzer(BaseAnalyzer):
    name = "oletools"

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        try:
            # Initialize parser. It handles DOC, XLS, DOCX, XLSM, etc.
            vbaparser = VBA_Parser(str(file_path))
            
            # If it's not a valid Office file, VBA_Parser will still initialize but detect_vba_macros() handles it
            if not vbaparser.detect_vba_macros():
                vbaparser.close()
                return {"is_flagged": False, "raw_output": {"message": "No macros found or not an Office document."}}

            # Extract macro results
            results = vbaparser.analyze_macros()
            vbaparser.close()

            # results is a list of tuples: (Keyword type, Keyword, Description)
            suspicious_keywords = []
            auto_exec = False

            for kw_type, keyword, description in results:
                suspicious_keywords.append({"type": kw_type, "keyword": keyword, "description": description})
                if kw_type.lower() == 'autoexec':
                    auto_exec = True

            # We flag the file if it has ANY macros, but especially if they auto-execute
            is_flagged = len(suspicious_keywords) > 0

            return {
                "is_flagged": is_flagged,
                "raw_output": {
                    "has_macros": True,
                    "auto_exec": auto_exec,
                    "findings": suspicious_keywords
                }
            }
        except Exception as e:
            # Fails gracefully if the file is an image, plain text, etc.
            return {"is_flagged": False, "raw_output": {"ignored": "Not a valid Office document or parse error."}}