"""
Unit tests for visual intelligence, perceptual difference hashing, and clustering.
"""

from reconshot.models import TargetResult
from reconshot.visual_engine import (
    cluster_target_results,
    compare_scans,
    compute_bytes_dhash,
    hamming_distance,
)


def test_dhash_and_hamming_distance():
    fake_png_1 = b"\x89PNG\r\n\x1a\n" + b"\x01\x02\x03\x04" * 32
    fake_png_2 = b"\x89PNG\r\n\x1a\n" + b"\x01\x02\x03\x04" * 32
    fake_png_3 = b"\x89PNG\r\n\x1a\n" + b"\xff\xfe\xfd\xfc" * 32

    h1 = compute_bytes_dhash(fake_png_1)
    h2 = compute_bytes_dhash(fake_png_2)
    h3 = compute_bytes_dhash(fake_png_3)

    assert len(h1) == 16
    assert h1 == h2
    assert hamming_distance(h1, h2) == 0
    assert hamming_distance(h1, h3) > 0


def test_cluster_target_results():
    results = [
        TargetResult(url="https://app1.com", dhash="ffff0000ffff0000", success=True),
        TargetResult(url="https://app2.com", dhash="ffff0000ffff0000", success=True),
        TargetResult(url="https://app3.com", dhash="0000ffff0000ffff", success=True),
    ]
    clusters = cluster_target_results(results, similarity_threshold=2)

    assert clusters == 2
    assert results[0].cluster_id == results[1].cluster_id
    assert results[0].cluster_id != results[2].cluster_id


def test_compare_scans():
    prev = [
        TargetResult(url="https://app1.com", status_code=200, dhash="ffff0000ffff0000", success=True),
    ]
    curr = [
        TargetResult(url="https://app1.com", status_code=500, dhash="ffff0000ffff0000", success=True),
        TargetResult(url="https://new.com", status_code=200, dhash="0000111100001111", success=True),
    ]
    diffs = compare_scans(curr, prev)

    assert len(diffs) == 2
    diff_types = [d["change_type"] for d in diffs]
    assert "modified" in diff_types
    assert "new_target" in diff_types
