"""
Canary Shield — Benign Ransomware Attack Simulator.

Mimics ransomware I/O patterns (rapid read + overwrite + rename) WITHOUT malware.
Used exclusively for safe testing, evaluation, and demonstrations inside an isolated sandbox.

HARD RULE 1 ENFORCEMENT:
- Target is strictly restricted to the dedicated 'test_sandbox' directory inside this repository.
- Hardcoded safety guards prevent running against ~/Documents, ~/Desktop, or any real user directories.
- Always prints the full target path clearly.
"""

import os
import sys
import time
import argparse

from config import TEST_SANDBOX_DIR, print_target_path


def is_safe_sandbox(directory: str) -> bool:
    """
    Verify that the target directory is strictly within the project sandbox.
    Rejects any real user personal directories (Documents, Desktop, User Profile).
    """
    abs_target = os.path.normcase(os.path.normpath(os.path.abspath(directory)))
    sandbox_norm = os.path.normcase(os.path.normpath(os.path.abspath(TEST_SANDBOX_DIR)))

    # Allow exact sandbox or subdirectories inside sandbox
    if abs_target == sandbox_norm or abs_target.startswith(sandbox_norm + os.sep):
        return True

    return False


def seed_mock_user_files(sandbox_dir: str) -> list[str]:
    """
    Creates mock normal user documents inside the sandbox so the simulation
    demonstrates ransomware encrypting normal files until tripping on a canary.
    """
    mock_files = [
        ("user_project_plan.docx", b"Project Goals for 2026: Deliver Capstone on time."),
        ("user_personal_budget.xlsx", b"Budget Q1: Rent 1200, Food 400, Books 150."),
        ("user_research_notes.txt", b"Notes on Active Deception: Honeytokens and canaries."),
        ("user_family_photo.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00MockPhoto"),
        ("user_resume_final.pdf", b"%PDF-1.4\r\nMock Resume Data for Engineering Student"),
    ]
    created = []
    for filename, content in mock_files:
        path = os.path.join(sandbox_dir, filename)
        if not os.path.exists(path) and not os.path.exists(path + ".locked"):
            try:
                with open(path, "wb") as f:
                    f.write(content + os.urandom(2048))
                    f.flush()
                created.append(path)
            except Exception as exc:
                print(f"Warning: Could not create mock user file {path}: {exc}")
    return created


def run_simulation(
    target_dir: str = TEST_SANDBOX_DIR,
    delay: float = 0.08,
    hold_handle: float = 0.0,
    seed_users: bool = True
) -> None:
    """
    Execute benign ransomware simulation against the target sandbox.
    """
    # HARD RULE 1: Print full sandbox path clearly
    print("=" * 70)
    print("      CANARY SHIELD — BENIGN RANSOMWARE SIMULATOR (TEST HARNESS)")
    print("=" * 70)
    print_target_path("Simulator Target")

    # HARD RULE 1: Strict guard against targeting real user directories
    if not is_safe_sandbox(target_dir):
        print(f"\n[CRITICAL SAFETY ABORT] Refusing to run on unauthorized directory: {target_dir}")
        print(f"Attacks are strictly restricted to the project sandbox: {TEST_SANDBOX_DIR}")
        sys.exit(1)

    os.makedirs(target_dir, exist_ok=True)
    # Operate directly inside the target directory from process launch (standard ransomware behavior)
    os.chdir(target_dir)

    if seed_users:
        new_mocks = seed_mock_user_files(target_dir)
        if new_mocks:
            print(f"[Simulator] Seeded {len(new_mocks)} mock user files into sandbox for realistic testing.")

    my_pid = os.getpid()
    print(f"[Simulator] Process ID (PID): {my_pid}")
    print(f"[Simulator] Traversal delay: {delay}s | Handle hold time: {hold_handle}s\n")

    # Read directory contents
    all_entries = sorted(os.listdir(target_dir))
    eligible_files = [
        os.path.join(target_dir, f) for f in all_entries
        if os.path.isfile(os.path.join(target_dir, f)) and not f.endswith(".locked")
    ]

    print(f"[Simulator] Found {len(eligible_files)} files to attack in sandbox.")
    print("[Simulator] Commencing simulated ransomware traversal (read -> overwrite -> rename)...\n")

    encrypted_count = 0
    for file_path in eligible_files:
        filename = os.path.basename(file_path)
        locked_path = file_path + ".locked"

        try:
            print(f"[Simulator PID {my_pid}] Encrypting: {filename}...")

            # Phase 1: Read original content
            with open(file_path, "rb") as f:
                _ = f.read()

            # Phase 2: Overwrite with pseudo-ransomware ciphertext
            # Use 'r+b' for in-place overwrite to seamlessly support Windows hidden decoy attributes
            encrypted_payload = os.urandom(4096)
            with open(file_path, "r+b") as f:
                f.seek(0)
                f.write(encrypted_payload)
                f.truncate()
                f.flush()
                if hold_handle > 0:
                    print(f"   [Holding open handle for {hold_handle}s to test direct match...]")
                    time.sleep(hold_handle)

            # Phase 3: Rename to .locked extension (hallmark of ransomware)
            # Use os.replace to safely overwrite if a stale .locked exists from a previous run
            os.replace(file_path, locked_path)
            encrypted_count += 1
            print(f"   -> Successfully locked: {os.path.basename(locked_path)}")

        except (PermissionError, FileNotFoundError, OSError) as exc:
            print(f"   [Access Error] {filename}: {exc}")

        # Traversal throttle
        time.sleep(delay)

    print(f"\n[Simulator] Traversal complete. Encrypted {encrypted_count} files.")
    print("[Simulator] Note: If Canary Shield was active, this process should have been killed early.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Canary Shield Benign Attack Simulator")
    parser.add_argument(
        "--target",
        default=TEST_SANDBOX_DIR,
        help="Target sandbox directory (must be inside project test_sandbox)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.08,
        help="Delay in seconds between file operations (default: 0.08s)"
    )
    parser.add_argument(
        "--hold-handle",
        type=float,
        default=0.0,
        help="Hold file handle open for N seconds to test direct handle attribution (default: 0.0s)"
    )
    parser.add_argument(
        "--no-seed",
        action="store_true",
        help="Do not seed mock user files into the sandbox"
    )

    args = parser.parse_args()
    run_simulation(
        target_dir=args.target,
        delay=args.delay,
        hold_handle=args.hold_handle,
        seed_users=not args.no_seed,
    )
