import json
from pathlib import Path
import openpyxl
import pytest
from app.services.dataset_processor import (
    normalize_dataset,
    validate_and_process,
    write_modified_dataset,
)


def test_csv_processing(tmp_path):
    csv_file = tmp_path / "sample.csv"
    csv_file.write_text("prompt,response\nTell me a joke,Why did the chicken cross the road?\nWhat is 2+2,4\n", encoding="utf-8")

    norm = normalize_dataset(csv_file, ".csv")
    assert norm.format == "csv"
    assert norm.record_count == 2
    assert "prompt" in norm.columns
    assert "response" in norm.columns
    assert norm.records[0].record_id == "0"
    assert norm.records[0].data["prompt"] == "Tell me a joke"
    assert norm.records[0].location["row"] == 1


def test_json_processing_array(tmp_path):
    json_file = tmp_path / "sample.json"
    data = [
        {"id": "1", "instruction": "summarize", "output": "short text"},
        {"id": "2", "instruction": "translate", "output": "texto corto"},
    ]
    json_file.write_text(json.dumps(data), encoding="utf-8")

    norm = normalize_dataset(json_file, ".json")
    assert norm.format == "json"
    assert norm.record_count == 2
    assert "instruction" in norm.columns
    assert norm.records[1].data["instruction"] == "translate"


def test_txt_processing(tmp_path):
    txt_file = tmp_path / "sample.txt"
    txt_file.write_text("Line 1 of sample text\nLine 2 of sample text\nLine 3 of sample text", encoding="utf-8")

    norm = normalize_dataset(txt_file, ".txt")
    assert norm.format == "txt"
    assert norm.record_count == 3
    assert norm.records[1].location["line_number"] == 2
    assert norm.records[1].data["text"] == "Line 2 of sample text"


def test_xlsx_processing(tmp_path):
    xlsx_file = tmp_path / "sample.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "DataSheet"
    ws.append(["header_a", "header_b"])
    ws.append(["val_1", "val_2"])
    ws.append(["val_3", "val_4"])
    wb.save(xlsx_file)

    norm = normalize_dataset(xlsx_file, ".xlsx")
    assert norm.format == "xlsx"
    assert norm.record_count == 2
    assert "header_a" in norm.columns
    assert norm.records[0].location["sheet"] == "DataSheet"


def test_invalid_format(tmp_path):
    pdf_file = tmp_path / "sample.pdf"
    pdf_file.write_text("fake pdf content", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported dataset format"):
        normalize_dataset(pdf_file, ".pdf")


def test_write_modified_dataset_creates_v2(tmp_path):
    orig_csv = tmp_path / "orig.csv"
    orig_csv.write_text("id,text\n0,Keep this row\n1,Remove this row\n2,Edit this row", encoding="utf-8")

    new_csv = tmp_path / "modified_v2.csv"
    write_modified_dataset(
        original_path=orig_csv,
        output_path=new_csv,
        file_type="csv",
        modified_records=[{"record_id": "2", "data": {"text": "Edited clean row"}}],
        removed_record_ids={"1"},
    )

    norm_v2 = normalize_dataset(new_csv, ".csv")
    assert norm_v2.record_count == 2
    # Row 1 removed
    assert not any(r.data.get("text") == "Remove this row" for r in norm_v2.records)
    # Row 2 edited
    assert any("Edited clean row" in r.data.get("text", "") for r in norm_v2.records)
