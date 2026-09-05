import json
from pathlib import Path

import pandas as pd

def validate_and_process(file_path: str, extension: str) -> dict:
    path = Path(file_path)

    if extension == ".csv":
        df = pd.read_csv(path)
        return {
            "format": "csv",
            "rows": len(df),
            "columns": list(df.columns),
            "column_count": len(df.columns),
        }

    if extension == ".xlsx":
        df = pd.read_excel(path)
        return {
            "format": "xlsx",
            "rows": len(df),
            "columns": list(df.columns),
            "column_count": len(df.columns),
        }

    if extension == ".json":
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return {
                "format": "json",
                "records": len(data),
                "top_level_type": "array",
            }

        return {
            "format": "json",
            "records": 1,
            "top_level_type": type(data).__name__,
        }

    if extension == ".txt":
        text = path.read_text(encoding="utf-8")
        return {
            "format": "txt",
            "characters": len(text),
            "lines": len(text.splitlines()),
        }

    raise ValueError("Unsupported dataset format")
