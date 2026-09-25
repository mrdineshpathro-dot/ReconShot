"""
Unit tests for configuration file parsing and merging.
"""

from pathlib import Path
import pytest
from reconshot.config import DEFAULT_CONFIG, create_default_config_yaml, load_config_file


def test_default_config_contents():
    assert DEFAULT_CONFIG["workers"] == 5
    assert DEFAULT_CONFIG["timeout"] == 30
    assert DEFAULT_CONFIG["browser"]["width"] == 1920
    assert DEFAULT_CONFIG["browser"]["height"] == 1080


def test_create_default_config_yaml():
    yaml_text = create_default_config_yaml()
    assert "ReconShot" in yaml_text
    assert "Mr Dinesh Pathro" in yaml_text
    assert "workers: 5" in yaml_text


def test_load_config_file_valid(tmp_path: Path):
    config_file = tmp_path / "custom_config.yaml"
    config_file.write_text("""
workers: 10
timeout: 45
delay: 2.5
browser:
  width: 1440
  height: 900
  mobile: true
""")
    loaded = load_config_file(config_file)
    assert loaded["workers"] == 10
    assert loaded["timeout"] == 45
    assert loaded["delay"] == 2.5
    assert loaded["browser"]["width"] == 1440
    assert loaded["browser"]["mobile"] is True


def test_load_config_file_nonexistent(tmp_path: Path):
    missing_file = tmp_path / "nonexistent.yaml"
    loaded = load_config_file(missing_file)
    assert loaded == {}


def test_load_config_file_invalid(tmp_path: Path):
    invalid_file = tmp_path / "bad.yaml"
    invalid_file.write_text("invalid: [broken yaml")
    loaded = load_config_file(invalid_file)
    assert loaded == {}
