from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class AppConfig:
    database_path: Path
    block_threshold: float = 0.8
    alert_threshold: float = 0.45

    @classmethod
    def from_path(cls, database_path: str | Path) -> "AppConfig":
        path = Path(database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return cls(database_path=path)
