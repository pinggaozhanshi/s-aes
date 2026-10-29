"""将一次操作的输入、结果保存为独立快照，供后续复现与验收整理。"""

from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


def _encode(value):
    if isinstance(value, bytes):
        return {"encoding": "hex", "data": value.hex().upper()}
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise TypeError(f"不支持记录类型：{type(value).__name__}")


def build_record(operation: str, parameters: dict, result: dict) -> dict:
    """立即序列化形成快照，之后修改源对象或 GUI 参数不影响记录。"""
    record = {
        "schema_version": 1,
        "created_at": datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds"),
        "project": "S-AES 实验工作台",
        "record_type": "操作运行记录，非正式验收结论",
        "operation": operation,
        "parameters": parameters,
        "result": result,
    }
    return json.loads(json.dumps(record, ensure_ascii=False, default=_encode))


def write_record(path: str | Path, record: dict) -> None:
    """写入 UTF-8 JSON 或文本；不访问网络，不自动发布任何内容。"""
    path = Path(path)
    if path.suffix.lower() == ".json":
        content = json.dumps(record, ensure_ascii=False, indent=2)
    elif path.suffix.lower() == ".txt":
        content = "\n".join((
            "S-AES 操作运行记录", f"时间：{record['created_at']}",
            f"操作：{record['operation']}", record["record_type"],
            "\n输入与参数：", json.dumps(record["parameters"], ensure_ascii=False, indent=2),
            "\n结果与轨迹：", json.dumps(record["result"], ensure_ascii=False, indent=2),
        ))
    else:
        raise ValueError("记录文件扩展名应为 .json 或 .txt。")
    path.write_text(content + "\n", encoding="utf-8")
