"""
Canary Shield — Realistic Attack Variant Simulator.

Provides seven attack-pattern variants (A–G) that test detection and
attribution under conditions the standard simulator does not cover.

SAFETY GUARANTEES (every variant):
  1. Refuses to run unless the target resolves to test_sandbox.
  2. Only renames or overwrites files inside test_sandbox with harmless text.
  3. Never opens network connections, never persists, never spreads.
  4. Never modifies anything outside test_sandbox.
  5. Treats mock user_ files the same benign way simulate_attack.py does
     (read → overwrite with random bytes → rename to .locked).
"""

import os
import sys
import time
import random
import argparse
import multiprocessing
from typing import List, Optional

from config import TEST_SANDBOX_DIR, print_target_path
from simulate_attack import is_safe_sandbox, seed_mock_user_files


# =========================================================================
# SHARED HELPERS
# =========================================================================

def _eligible_files(target_dir: str, order: str = "sorted") -> List[str]:
    """Return eligible (non-.locked) files in the sandbox, in given order."""
    entries = os.listdir(target_dir)
    files = [
        os.path.join(target_dir, f)
        for f in entries
        if os.path.isfile(os.path.join(target_dir, f)) and not f.endswith(".locked")
    ]
    if order == "sorted":
        files.sort()
    elif order == "reverse":
        files.sort(reverse=True)
    elif order == "random":
        random.shuffle(files)
    return files


def _encrypt_file(file_path: str, hold_handle: float = 0.0) -> bool:
    """Mimic ransomware I/O on a single file (read → overwrite → rename)."""
    locked_path = file_path + ".locked"
    try:
        with open(file_path, "rb") as f:
            _ = f.read()
        payload = os.urandom(4096)
        with open(file_path, "r+b") as f:
            f.seek(0)
            f.write(payload)
            f.truncate()
            f.flush()
            if hold_handle > 0:
                time.sleep(hold_handle)
        os.replace(file_path, locked_path)
        return True
    except (PermissionError, FileNotFoundError, OSError):
        return False


def _safety_guard(target_dir: str) -> None:
    """Abort if target is not inside the project test_sandbox."""
    if not is_safe_sandbox(target_dir):
        print(f"[CRITICAL SAFETY ABORT] Refusing to run on: {target_dir}")
        print(f"Attacks are strictly restricted to: {TEST_SANDBOX_DIR}")
        sys.exit(1)


# =========================================================================
# VARIANT A — No held handle (open, write, close immediately)
# =========================================================================

def variant_a(target_dir: str = TEST_SANDBOX_DIR, delay: float = 0.08,
              seed: bool = True) -> int:
    """Write, close handle instantly, then rename. No handle hold."""
    _safety_guard(target_dir)
    os.makedirs(target_dir, exist_ok=True)
    os.chdir(target_dir)
    if seed:
        seed_mock_user_files(target_dir)
    count = 0
    for fp in _eligible_files(target_dir):
        if _encrypt_file(fp, hold_handle=0.0):
            count += 1
        time.sleep(delay)
    return count


# =========================================================================
# VARIANT B — Maximum speed (no delay, no handle hold)
# =========================================================================

def variant_b(target_dir: str = TEST_SANDBOX_DIR, seed: bool = True) -> int:
    """Zero delay between files, zero handle hold. Maximum throughput."""
    _safety_guard(target_dir)
    os.makedirs(target_dir, exist_ok=True)
    os.chdir(target_dir)
    if seed:
        seed_mock_user_files(target_dir)
    count = 0
    for fp in _eligible_files(target_dir):
        if _encrypt_file(fp, hold_handle=0.0):
            count += 1
        # No delay at all
    return count


# =========================================================================
# VARIANT C — Different working directory
# =========================================================================

def variant_c(target_dir: str = TEST_SANDBOX_DIR, delay: float = 0.08,
              seed: bool = True) -> int:
    """Run from a temp folder so cwd/cmdline heuristics cannot match."""
    _safety_guard(target_dir)
    os.makedirs(target_dir, exist_ok=True)

    import tempfile
    with tempfile.TemporaryDirectory(prefix="canary_variant_c_") as tmpdir:
        os.chdir(tmpdir)  # cwd is now a temp folder
        if seed:
            seed_mock_user_files(target_dir)
        count = 0
        for fp in _eligible_files(target_dir):
            if _encrypt_file(fp, hold_handle=0.0):
                count += 1
            time.sleep(delay)
    return count


# =========================================================================
# VARIANT D — Multi-process (parent + 3 child workers)
# =========================================================================

def _worker_d(target_dir: str, file_list: List[str], delay: float) -> None:
    """Child worker: encrypts its assigned files."""
    _safety_guard(target_dir)
    os.chdir(target_dir)
    for fp in file_list:
        _encrypt_file(fp, hold_handle=0.0)
        time.sleep(delay)


def variant_d(target_dir: str = TEST_SANDBOX_DIR, delay: float = 0.08,
              seed: bool = True) -> int:
    """Parent spawns 3 child workers; each touches a different subset of files."""
    _safety_guard(target_dir)
    os.makedirs(target_dir, exist_ok=True)
    os.chdir(target_dir)
    if seed:
        seed_mock_user_files(target_dir)

    files = _eligible_files(target_dir)
    n_workers = 3
    chunks = [files[i::n_workers] for i in range(n_workers)]

    workers = []
    for chunk in chunks:
        p = multiprocessing.Process(
            target=_worker_d, args=(target_dir, chunk, delay)
        )
        p.start()
        workers.append(p)

    for p in workers:
        p.join(timeout=20)

    # Count locked files
    locked = [
        f for f in os.listdir(target_dir) if f.endswith(".locked")
    ]
    return len(locked)


# =========================================================================
# VARIANT E — Traversal order (alphabetical, reverse, random)
# =========================================================================

def variant_e(target_dir: str = TEST_SANDBOX_DIR, delay: float = 0.08,
              order: str = "random", seed: bool = True) -> int:
    """Traverse files in alphabetical, reverse, or random order."""
    _safety_guard(target_dir)
    os.makedirs(target_dir, exist_ok=True)
    os.chdir(target_dir)
    if seed:
        seed_mock_user_files(target_dir)
    count = 0
    for fp in _eligible_files(target_dir, order=order):
        if _encrypt_file(fp, hold_handle=0.0):
            count += 1
        time.sleep(delay)
    return count


# =========================================================================
# VARIANT F — Delete-and-recreate pattern
# =========================================================================

def variant_f(target_dir: str = TEST_SANDBOX_DIR, delay: float = 0.08,
              seed: bool = True) -> int:
    """Create new .locked file with encrypted content, then delete original."""
    _safety_guard(target_dir)
    os.makedirs(target_dir, exist_ok=True)
    os.chdir(target_dir)
    if seed:
        seed_mock_user_files(target_dir)
    count = 0
    for fp in _eligible_files(target_dir):
        locked_path = fp + ".locked"
        try:
            with open(fp, "rb") as f:
                _ = f.read()
            # Write new file first
            with open(locked_path, "wb") as f:
                f.write(os.urandom(4096))
                f.flush()
            # Then delete the original
            try:
                os.remove(fp)
            except OSError:
                pass
            count += 1
        except (PermissionError, FileNotFoundError, OSError):
            pass
        time.sleep(delay)
    return count


# =========================================================================
# VARIANT G — Immediate start (touch decoy within 50 ms of process start)
# =========================================================================

def variant_g(target_dir: str = TEST_SANDBOX_DIR, seed: bool = True) -> int:
    """Touch the first decoy within 50 ms of starting. Tests cache blind window."""
    _safety_guard(target_dir)
    os.makedirs(target_dir, exist_ok=True)
    os.chdir(target_dir)
    if seed:
        seed_mock_user_files(target_dir)
    start = time.perf_counter()
    count = 0
    files = _eligible_files(target_dir)
    for fp in files:
        if _encrypt_file(fp, hold_handle=0.0):
            count += 1
        elapsed_ms = (time.perf_counter() - start) * 1000
        if elapsed_ms < 50 and count == 1:
            print(f"  [Variant G] First decoy touched at {elapsed_ms:.1f} ms after start")
        # No delay — immediacy is the point
    return count


# =========================================================================
# CLI ENTRY POINT
# =========================================================================

VARIANT_MAP = {
    "a": ("No held handle", variant_a),
    "b": ("Maximum speed", variant_b),
    "c": ("Different working directory", variant_c),
    "d": ("Multi-process (3 workers)", variant_d),
    "e": ("Traversal order", variant_e),
    "f": ("Delete-and-recreate", variant_f),
    "g": ("Immediate start (<50ms)", variant_g),
}


def main():
    parser = argparse.ArgumentParser(
        description="Canary Shield — Realistic Attack Variant Simulator"
    )
    parser.add_argument(
        "variant", choices=list(VARIANT_MAP.keys()),
        help="Which variant to run (a-g)"
    )
    parser.add_argument(
        "--target", default=TEST_SANDBOX_DIR,
        help="Target sandbox directory"
    )
    parser.add_argument(
        "--delay", type=float, default=0.08,
        help="Inter-file delay in seconds (default: 0.08)"
    )
    parser.add_argument(
        "--order", default="random", choices=["sorted", "reverse", "random"],
        help="File traversal order for variant e (default: random)"
    )
    parser.add_argument(
        "--no-seed", action="store_true",
        help="Do not seed mock user files"
    )
    args = parser.parse_args()

    _safety_guard(args.target)
    name, func = VARIANT_MAP[args.variant]
    print(f"[Variant {args.variant.upper()}] {name}")
    print_target_path("Variant Target")

    kwargs = {"target_dir": args.target, "seed": not args.no_seed}
    if args.variant in ("a", "c"):
        kwargs["delay"] = args.delay
    elif args.variant == "e":
        kwargs["delay"] = args.delay
        kwargs["order"] = args.order

    count = func(**kwargs)
    print(f"[Variant {args.variant.upper()}] Encrypted {count} files.")


if __name__ == "__main__":
    main()
