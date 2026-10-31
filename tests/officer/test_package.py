from pathlib import Path

from officer.cli import main
from officer.events import EventLog


def test_audit_verify_accepts_an_intact_log_and_rejects_an_edited_one(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    log = EventLog(path)
    log.emit("a", x=1)
    log.emit("b", y=2)
    assert main(["audit-verify", str(path)]) == 0
    path.write_text(path.read_text(encoding="utf-8").replace('"x": 1', '"x": 2'), encoding="utf-8")
    assert main(["audit-verify", str(path)]) == 1
