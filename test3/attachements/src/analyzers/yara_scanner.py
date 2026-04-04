import yara
from pathlib import Path
from typing import Dict, Any
from src.analyzers.base import BaseAnalyzer
from src.core.config import BASE_DIR

class YaraAnalyzer(BaseAnalyzer):
    name = "yara"

    def __init__(self):
        # Compile rules once when the analyzer is instantiated
        rule_path = BASE_DIR / "yara_rules" / "rules.yar"
        if rule_path.exists():
            self.rules = yara.compile(filepath=str(rule_path))
        else:
            self.rules = None

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        if not self.rules:
            return {"is_flagged": False, "raw_output": {"error": "No YARA rules found."}}

        try:
            matches = self.rules.match(str(file_path))
            
            # If any rule matches, we flag the file
            is_flagged = len(matches) > 0
            
            # Extract rule names and meta tags for the JSON output
            match_data = [
                {"rule": m.rule, "description": m.meta.get("description", "No description")} 
                for m in matches
            ]

            return {
                "is_flagged": is_flagged,
                "raw_output": {"matches": match_data}
            }
        except Exception as e:
            return {"is_flagged": False, "raw_output": {"error": str(e)}}