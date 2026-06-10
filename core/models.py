from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    file_path: str
    line_number: int
    vulnerability_type: str
    severity: str
    source: str
    sink: str
    description: str
    code_snippet: str

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "source": self.source,
            "sink": self.sink,
            "description": self.description,
            "code_snippet": self.code_snippet.strip()
        }
