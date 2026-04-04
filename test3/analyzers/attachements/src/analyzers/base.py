from pathlib import Path
from typing import Dict, Any

class BaseAnalyzer:
    name: str = "BaseAnalyzer"

    def analyze(self, file_path: Path) -> Dict[str, Any]:
        """
        Reads the file and returns a dictionary with:
        - 'is_flagged': boolean indicating if something malicious/suspicious was found.
        - 'raw_output': dictionary containing the detailed findings.
        """
        raise NotImplementedError("Subclasses must implement analyze()")