from pathlib import Path

from app.utils.checkpoint import (
    Checkpoint,
    ElasticCheckpoint,
    load_checkpoint,
    load_elastic_checkpoint,
    save_checkpoint,
    save_elastic_checkpoint,
)


def test_checkpoint_load_save(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    checkpoint = Checkpoint(last_record_id=42)
    save_checkpoint(path, checkpoint)
    loaded = load_checkpoint(path)
    assert loaded.last_record_id == 42


def test_checkpoint_missing_returns_default(tmp_path: Path) -> None:
    path = tmp_path / "missing.json"
    loaded = load_checkpoint(path)
    assert loaded.last_record_id == 0


def test_elastic_checkpoint_load_save(tmp_path: Path) -> None:
    path = tmp_path / "elastic.json"
    checkpoint = ElasticCheckpoint(
        last_ts="2024-05-01T10:11:12Z",
        last_ids_at_ts=["abc123", "def456"],
        indices="logs-*",
    )
    save_elastic_checkpoint(path, checkpoint)
    loaded = load_elastic_checkpoint(path)
    assert loaded.last_ts == "2024-05-01T10:11:12Z"
    assert loaded.last_ids_at_ts == ["abc123", "def456"]
    assert loaded.indices == "logs-*"


def test_elastic_checkpoint_missing_returns_default(tmp_path: Path) -> None:
    path = tmp_path / "missing-elastic.json"
    loaded = load_elastic_checkpoint(path)
    assert loaded.last_ts is None
    assert loaded.last_ids_at_ts is None
