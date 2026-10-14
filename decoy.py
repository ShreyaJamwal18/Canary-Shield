"""
Canary Shield — Decoy Deployment & Self-Healing Honeytoken Engine.

Silently plants realistic, hidden decoy ("canary") files in monitored directories.
Strategic naming, format mimicry, and scattering maximize early interception during ransomware traversals:
- High-priority alphabetical prefixes ('!', '~$', '00_') ensure sequential traversals hit decoys first.
- Authentic business file names (financials, passwords, payroll) mimic high-value targets.
- Authentic magic bytes/headers avoid immediate rejection by content-inspecting ransomware.
- Timestamp blending: matches timestamps of existing user files to defeat anti-canary heuristic scanners.
- On Windows, files are flagged with FILE_ATTRIBUTE_HIDDEN.
- Self-Healing Tripwires: Automatically restores/re-seeds tripwires if an attack modifies or renames them.
"""

import os
import random
import string
import ctypes
import platform
import logging
import time
import json

from config import (
    BASE_DIR,
    TEST_SANDBOX_DIR,
    get_watched_directories,
    CANARY_COUNT_PER_DIR,
    CANARY_PREFIXES,
    CANARY_EXTENSIONS,
    CANARY_FILL_SIZE_BYTES,
    print_target_path,
)

logger = logging.getLogger("canary_shield.decoy")

DECOY_MANIFEST_PATH = os.path.join(BASE_DIR, "decoy_manifest.json")

# Realistic business decoy names
DECOY_BASE_NAMES = [
    "q4_financial_audit",
    "employee_payroll_records",
    "executive_compensation",
    "master_passwords_vault",
    "client_contracts_index",
    "tax_returns_consolidated",
    "merger_acquisition_brief",
    "banking_wire_credentials",
    "database_root_keys",
    "corporate_strategy_2026",
    "confidential_board_minutes",
    "customer_ssn_archive",
]

# Magic bytes for common file formats to make canaries appear valid to header inspectors
FILE_HEADERS = {
    ".pdf": b"%PDF-1.5\r\n%\xe2\xe3\xcf\xd3\r\n1 0 obj\r\n<<\r\n/Type /Catalog\r\n>>\r\n",
    ".docx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00[Content_Types].xml",
    ".xlsx": b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00[Content_Types].xml",
    ".jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00",
    ".txt": b"[CONFIDENTIAL COMPANY ASSET - RESTRICTED ACCESS AUTHORIZED PERSONNEL ONLY]\r\n\r\n",
}


def _dummy_content(extension: str, total_size: int) -> bytes:
    """Generate authentic payload with valid headers followed by random binary padding."""
    header = FILE_HEADERS.get(extension.lower(), b"")
    remaining_size = max(0, total_size - len(header))
    return header + os.urandom(remaining_size)


def _hide_file_windows(path: str) -> bool:
    """
    Apply Windows FILE_ATTRIBUTE_HIDDEN (0x02) to conceal canary files from default Explorer views.
    Fails gracefully if attributes cannot be set.
    """
    FILE_ATTRIBUTE_HIDDEN = 0x02
    try:
        res = ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
        return bool(res)
    except Exception as exc:
        logger.warning("Could not set hidden attribute on %s: %s", path, exc)
        return False


def _blend_timestamp(file_path: str, directory: str) -> None:
    """Blend canary timestamp with neighboring files so anti-honeytoken malware can't spot them."""
    try:
        candidates = [
            os.path.join(directory, f) for f in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, f)) and f != os.path.basename(file_path)
        ]
        if candidates:
            sample_time = os.path.getmtime(random.choice(candidates))
            # Slightly jitter timestamp (-5 to +5 minutes)
            jittered = sample_time + random.randint(-300, 300)
            os.utime(file_path, (jittered, jittered))
    except Exception:
        pass


def _reset_file_attributes(path: str) -> bool:
    """Clear Windows hidden and read-only attributes so files can be modified/overwritten/deleted."""
    FILE_ATTRIBUTE_NORMAL = 0x80
    if platform.system() == "Windows" and os.path.exists(path):
        try:
            res = ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_NORMAL)
            return bool(res)
        except Exception as exc:
            logger.error("Failed to reset Windows file attributes for %s: %s", path, exc)
            return False
    return True


def _safe_remove(path: str) -> bool:
    """Safely remove a file, unsetting hidden/read-only attributes first if on Windows."""
    if not os.path.exists(path):
        return True
    _reset_file_attributes(path)
    try:
        os.remove(path)
        return True
    except Exception as exc:
        logger.error("Failed to remove file %s: %s", path, exc)
        return False


def restore_canary(canary_path: str) -> bool:
    """
    Self-healing tripwire: Restores or regenerates a tripped canary file.
    Cleans up any corresponding .locked file and re-arms the decoy.
    """
    try:
        locked_variant = canary_path + ".locked"
        if os.path.exists(locked_variant):
            _safe_remove(locked_variant)

        ext = os.path.splitext(canary_path)[1].lower()
        content = _dummy_content(ext, CANARY_FILL_SIZE_BYTES)
        
        # Reset Windows attributes and remove existing file so 'wb' doesn't fail with Errno 13
        _safe_remove(canary_path)

        with open(canary_path, "wb") as f:
            f.write(content)

        if platform.system() == "Windows":
            _hide_file_windows(canary_path)

        _blend_timestamp(canary_path, os.path.dirname(canary_path))
        logger.info("Self-Healing Tripwire: Restored canary %s", canary_path)
        return True
    except Exception as exc:
        logger.error("Failed to restore canary %s: %s", canary_path, exc)
        return False


def load_decoy_manifest() -> list[str]:
    """Load list of deployed decoy file paths from decoy_manifest.json."""
    if os.path.exists(DECOY_MANIFEST_PATH):
        try:
            with open(DECOY_MANIFEST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [os.path.normcase(os.path.normpath(p)) for p in data]
        except Exception as exc:
            logger.warning("Could not load decoy manifest: %s", exc)
    return []


def save_decoy_manifest(canary_paths: list[str]) -> None:
    """Save list of deployed decoy file paths to decoy_manifest.json."""
    try:
        norm_paths = [os.path.normcase(os.path.normpath(p)) for p in canary_paths]
        with open(DECOY_MANIFEST_PATH, "w", encoding="utf-8") as f:
            json.dump(norm_paths, f, indent=2)
    except Exception as exc:
        logger.error("Failed to save decoy manifest: %s", exc)


def deploy_decoys(directories: list[str] | None = None) -> list[str]:
    """
    Deploy realistic decoy files scattered across watched directories.
    
    Hard Rule 1: Always enforces test_sandbox directory by default when in test mode.
    Returns:
        List of absolute normalized paths of all deployed canaries.
    """
    target_dirs = directories if directories is not None else get_watched_directories()
    deployed_canaries: list[str] = []

    # Clean up any previously deployed canaries tracked in manifest
    prior_manifest = load_decoy_manifest()
    if prior_manifest:
        cleanup_decoys(prior_manifest)

    for directory in target_dirs:
        print_target_path(f"Decoy Deployer -> {directory}")
        os.makedirs(directory, exist_ok=True)

        dir_canaries: list[str] = []
        used_names = set()
        attempts = 0
        max_attempts = CANARY_COUNT_PER_DIR * 5

        while len(dir_canaries) < CANARY_COUNT_PER_DIR and attempts < max_attempts:
            attempts += 1
            prefix = random.choice(CANARY_PREFIXES)
            base = random.choice(DECOY_BASE_NAMES)
            ext = random.choice(CANARY_EXTENSIONS)
            
            # Ensure uniqueness
            candidate_name = f"{prefix}{base}{ext}"
            counter = 1
            while candidate_name in used_names:
                candidate_name = f"{prefix}{base}_{counter}{ext}"
                counter += 1
            used_names.add(candidate_name)

            file_path = os.path.join(directory, candidate_name)

            # Safely clear attributes and remove any pre-existing file with this name
            if os.path.exists(file_path):
                if not _safe_remove(file_path):
                    logger.error("ERROR: Pre-existing decoy file %s could not be prepared for deployment.", file_path)
                    continue

            content = _dummy_content(ext, CANARY_FILL_SIZE_BYTES)

            try:
                with open(file_path, "wb") as f:
                    f.write(content)

                if platform.system() == "Windows":
                    _hide_file_windows(file_path)

                _blend_timestamp(file_path, directory)

                norm_path = os.path.normcase(os.path.normpath(os.path.abspath(file_path)))
                dir_canaries.append(norm_path)
                logger.info("Deployed decoy (%d/%d): %s (%d bytes)",
                            len(dir_canaries), CANARY_COUNT_PER_DIR, norm_path, len(content))
            except Exception as exc:
                logger.error("ERROR: Failed to deploy canary at %s: %s", file_path, exc)

        # Strict validation: raise visible ERROR and exception if count is not met
        if len(dir_canaries) != CANARY_COUNT_PER_DIR:
            err_msg = (
                f"FATAL DECOY DEPLOYMENT ERROR: Directory '{directory}' deployed only "
                f"{len(dir_canaries)}/{CANARY_COUNT_PER_DIR} decoys after {attempts} attempts!"
            )
            logger.critical(err_msg)
            raise RuntimeError(err_msg)

        deployed_canaries.extend(dir_canaries)

    # Save newly deployed decoys into manifest
    save_decoy_manifest(deployed_canaries)

    logger.info("Successfully deployed %d canary decoys across %d directories.",
                len(deployed_canaries), len(target_dirs))
    return deployed_canaries


def cleanup_decoys(canary_paths: list[str] | None = None) -> int:
    """
    Safely remove deployed canary files.
    Deletes ONLY files recorded in the decoy manifest (or explicitly passed in canary_paths).
    Never purges files by filename prefix to protect genuine user documents.
    """
    cleaned = 0
    targets = canary_paths if canary_paths is not None else load_decoy_manifest()

    for path in targets:
        norm_p = os.path.normcase(os.path.normpath(os.path.abspath(path)))
        if os.path.exists(norm_p):
            if _safe_remove(norm_p):
                cleaned += 1
        # Also clean up any .locked variant of this specific decoy
        locked_variant = norm_p + ".locked"
        if os.path.exists(locked_variant):
            if _safe_remove(locked_variant):
                cleaned += 1

    # Remove manifest file when all decoys are purged
    if canary_paths is None and os.path.exists(DECOY_MANIFEST_PATH):
        try:
            os.remove(DECOY_MANIFEST_PATH)
        except Exception as exc:
            logger.warning("Could not remove decoy manifest: %s", exc)

    return cleaned


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    print_target_path("decoy.py main")
    paths = deploy_decoys()
    print(f"Deployed {len(paths)} decoy files.")
