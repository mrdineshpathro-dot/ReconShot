"""
JSON metadata management and scan state persistence for ReconShot.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from reconshot.logger import logger
from reconshot.models import ScanSummary, TargetResult
from reconshot.naming import url_to_metadata_filename


def save_target_metadata(result: TargetResult, metadata_dir: Path) -> Path:
    """Save an individual target's metadata to a JSON file."""
    metadata_dir.mkdir(parents=True, exist_ok=True)
    filename = url_to_metadata_filename(result.url)
    target_path = metadata_dir / filename

    try:
        data = result.to_dict()
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return target_path
    except Exception as e:
        logger.error(f"Failed to save metadata for {result.url}: {e}")
        return target_path


def save_scan_summary(summary: ScanSummary, metadata_dir: Path) -> Path:
    """Save aggregate scan summary to summary.json."""
    metadata_dir.mkdir(parents=True, exist_ok=True)
    summary_path = metadata_dir / "summary.json"

    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary.to_dict(), f, indent=2, ensure_ascii=False)
        return summary_path
    except Exception as e:
        logger.error(f"Failed to save scan summary: {e}")
        return summary_path


def load_target_metadata(json_path: Path) -> Optional[TargetResult]:
    """Load TargetResult from a JSON file."""
    if not json_path.exists():
        return None
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return TargetResult.from_dict(data)
    except Exception as e:
        logger.debug(f"Failed to load metadata file {json_path}: {e}")
        return None


def load_all_metadata(metadata_dir: Path) -> List[TargetResult]:
    """Load all target metadata JSON files from the metadata directory."""
    if not metadata_dir.exists():
        return []

    results: List[TargetResult] = []
    for file_path in sorted(metadata_dir.glob("*.json")):
        if file_path.name == "summary.json":
            continue
        res = load_target_metadata(file_path)
        if res:
            results.append(res)
    return results


def save_resume_state(
    state_file: Path,
    scan_id: str,
    completed_urls: Set[str],
    results: List[TargetResult],
) -> None:
    """Persist current scan progress atomically to allow seamless resumption."""
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file = state_file.with_suffix(".tmp")

        payload = {
            "scan_id": scan_id,
            "completed_urls": list(completed_urls),
            "results": [r.to_dict() for r in results],
        }

        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        temp_file.replace(state_file)
    except Exception as e:
        logger.debug(f"Failed to write resume state: {e}")


def load_resume_state(
    state_file: Path,
) -> Tuple[Optional[str], Set[str], List[TargetResult]]:
    """
    Load resume state from disk.
    Returns (scan_id, completed_urls_set, results_list).
    """
    if not state_file.exists():
        return None, set(), []

    try:
        with open(state_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        scan_id = data.get("scan_id")
        completed = set(data.get("completed_urls", []))
        results = [
            TargetResult.from_dict(r)
            for r in data.get("results", [])
            if isinstance(r, dict)
        ]
        return scan_id, completed, results
    except Exception as e:
        logger.warning(f"Could not parse resume state file {state_file}: {e}")
        return None, set(), []
