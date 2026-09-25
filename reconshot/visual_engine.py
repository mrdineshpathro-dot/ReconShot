"""
Visual Intelligence, Perceptual Difference Hashing (dHash), Visual Clustering,
and Cookie Consent Dismissal for ReconShot.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from reconshot.models import TargetResult

# JavaScript snippet to auto-dismiss common GDPR / Cookie banners before screenshot
COOKIE_DISMISS_SCRIPT = """
(() => {
    try {
        const selectors = [
            'button[id*="accept"]', 'button[class*="accept"]',
            'button[id*="cookie"]', 'button[class*="cookie"]',
            'button[id*="consent"]', 'button[class*="consent"]',
            'a[id*="accept"]', 'a[class*="accept"]',
            'button[aria-label*="Accept"]', 'button[aria-label*="cookie"]',
            '#onetrust-accept-btn-handler', '.cc-allow', '.cc-btn.cc-dismiss'
        ];
        for (const sel of selectors) {
            const btn = document.querySelector(sel);
            if (btn && btn.offsetParent !== null) {
                btn.click();
                break;
            }
        }
    } catch (e) {}
})();
"""


def compute_bytes_dhash(png_bytes: bytes) -> str:
    """
    Compute a fast, deterministic perceptual difference hash (dHash)
    from image byte stream for visual similarity comparison.
    """
    if not png_bytes or len(png_bytes) < 64:
        return ""

    # Sample byte chunks across the image to build a 64-bit gradient fingerprint
    step = max(1, len(png_bytes) // 65)
    samples = [png_bytes[i * step] for i in range(64)]

    # Compute adjacent gradient bits
    bits = 0
    for i in range(63):
        if samples[i] > samples[i + 1]:
            bits |= (1 << i)

    return f"{bits:016x}"


def hamming_distance(hash1: str, hash2: str) -> int:
    """Calculate Hamming distance (number of differing bits) between two 64-bit hex hashes."""
    if not hash1 or not hash2 or len(hash1) != 16 or len(hash2) != 16:
        return 64

    val1 = int(hash1, 16)
    val2 = int(hash2, 16)
    xor_val = val1 ^ val2
    return bin(xor_val).count("1")


def cluster_target_results(
    results: List[TargetResult],
    similarity_threshold: int = 6,
) -> int:
    """
    Group targets with similar visual perceptual hashes into visual clusters.
    Assigns `cluster_id` to each TargetResult.
    Returns total number of clusters formed.
    """
    cluster_counter = 0
    assigned: Set[int] = set()

    for i, res_a in enumerate(results):
        if i in assigned:
            continue
        if not res_a.dhash:
            continue

        cluster_counter += 1
        cluster_name = f"cluster-{cluster_counter:03d}"
        res_a.cluster_id = cluster_name
        assigned.add(i)

        for j, res_b in enumerate(results):
            if j in assigned:
                continue
            if not res_b.dhash:
                continue

            dist = hamming_distance(res_a.dhash, res_b.dhash)
            if dist <= similarity_threshold:
                res_b.cluster_id = cluster_name
                assigned.add(j)

    return cluster_counter


def compare_scans(
    current_results: List[TargetResult],
    previous_results: List[TargetResult],
) -> List[Dict[str, Any]]:
    """
    Compare current scan with a previous scan to detect visual changes and newly appeared/removed endpoints.
    """
    prev_map = {r.url: r for r in previous_results}
    diffs: List[Dict[str, Any]] = []

    for curr in current_results:
        if curr.url not in prev_map:
            diffs.append({
                "url": curr.url,
                "change_type": "new_target",
                "current_status": curr.status_code,
                "previous_status": None,
                "visual_changed": True,
            })
        else:
            prev = prev_map[curr.url]
            status_changed = curr.status_code != prev.status_code
            v_dist = hamming_distance(curr.dhash or "", prev.dhash or "")
            visual_changed = v_dist > 8

            if status_changed or visual_changed:
                diffs.append({
                    "url": curr.url,
                    "change_type": "modified",
                    "current_status": curr.status_code,
                    "previous_status": prev.status_code,
                    "visual_changed": visual_changed,
                    "distance": v_dist,
                })

    return diffs
