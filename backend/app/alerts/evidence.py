from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("unishield.evidence")


class EvidenceCollector:
    def __init__(self, active_dir: str | None = None, incidents_dir: str | None = None) -> None:
        self.active_dir = Path(active_dir or settings.pcap_active_path).parent
        self.incidents_dir = Path(incidents_dir or settings.pcap_incidents_path)
        self.incidents_dir.mkdir(parents=True, exist_ok=True)

    def locate_active_pcap(self) -> Path | None:
        candidates = [self.active_dir / "current.pcap", self.active_dir / "rolling.pcap"]
        for candidate in candidates:
            if candidate.exists() and candidate.stat().st_size > 0:
                return candidate
        return None

    def preserve_for_incident(self, alert_id: str, threat_type: str,
                              alert_ts: str) -> Path | None:
        source = self.locate_active_pcap()
        if source is None:
            logger.warning("No active pcap found to preserve for %s", alert_id)
            return None
        safe_type = threat_type.replace("/", "_").replace(" ", "_")
        target = self.incidents_dir / f"{alert_id}_{safe_type}_{alert_ts}.pcap"
        if target.exists():
            return target
        try:
            _copy_file(source, target)
            return target
        except Exception:
            logger.exception("Failed to preserve pcap for alert %s", alert_id)
            return None

    def archive_incident(self, incident_path: Path) -> Path:
        archive_dir = Path(settings.pcap_archive_path)
        archive_dir.mkdir(parents=True, exist_ok=True)
        target = archive_dir / incident_path.name
        _copy_file(incident_path, target)
        return target

    def incident_files(self) -> list[Path]:
        if not self.incidents_dir.exists():
            return []
        return sorted(self.incidents_dir.glob("*.pcap"))


def _copy_file(source: Path, target: Path) -> None:
    import shutil
    shutil.copy2(source, target)
    logger.info("Copied %s -> %s", source.name, target)