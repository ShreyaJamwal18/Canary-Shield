"""
Canary Shield — Real-Time Monitor Module.

Uses watchdog to hook OS-level file system events (ReadDirectoryChangesW on Windows).
Filters incoming events so ONLY modifications, renames, or deletions of
canary decoy files trigger process attribution and containment.

Equipped with real-world enterprise capabilities:
- Layered VSS Anti-Recovery Guard (monitors destructive backup wiping).
- Self-Healing Tripwires: Automatically restores tripped decoys.
- Log file rotation (RotatingFileHandler) to protect disk health.
- Asynchronous alerting and forensic telemetry dispatch.
"""

import os
import time
import logging
from logging.handlers import RotatingFileHandler
from typing import Set, Iterable, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from config import (
    get_watched_directories,
    LOG_FILE,
    print_target_path,
    AUTO_RESTORE_CANARIES,
)
from process_id import find_offending_pid, get_last_attribution_record, start_process_cache, stop_process_cache
from contain import kill_process
from decoy import restore_canary
from vss_guard import VSSGuard

logger = logging.getLogger("canary_shield.monitor")


def _normalize_path(path: str) -> str:
    """Normalize filesystem path for Windows case-insensitive comparisons."""
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


class CanaryEventHandler(FileSystemEventHandler):
    """
    Watches file system events and filters them strictly to registered canary files.
    """
    def __init__(self, canary_paths: Iterable[str]):
        super().__init__()
        # Store paths as normalized lowercase strings for exact matching on Windows
        self.canary_paths: Set[str] = {_normalize_path(p) for p in canary_paths}
        # Debounce dictionary: {norm_path: last_trigger_timestamp}
        self._recent_triggers: dict[str, float] = {}
        # Grace period for startup flush (ignore any NTFS events from deployment for first 1.0 second)
        self._arm_time: float = time.time() + 1.0

    def suppress_canary(self, path: str, duration: float = 3.0) -> None:
        """Temporarily suppress event processing while self-healing restores a canary."""
        self._recent_triggers[_normalize_path(path)] = time.time() + duration

    def _should_debounce(self, path: str, cooldown_seconds: float = 0.5) -> bool:
        """Prevent redundant attribution cycles if the OS fires multiple events for one action."""
        now = time.time()
        last_time = self._recent_triggers.get(path, 0.0)
        if last_time > now or (now - last_time) < cooldown_seconds:
            return True
        self._recent_triggers[path] = now
        return False

    def _handle_event(self, event_type: str, raw_path: str) -> None:
        norm_path = _normalize_path(raw_path)

        # STRICT FILTER: Only canary paths trip the wire
        if norm_path not in self.canary_paths:
            return

        # Ignore delayed file system notifications from initial decoy deployment
        if time.time() < self._arm_time:
            return

        if self._should_debounce(norm_path):
            return

        t_event_received = time.time()
        detected_at = t_event_received
        logger.critical(
            "*** CANARY TRIPWIRE TRIGGERED *** Event=%s | Path=%s",
            event_type, norm_path
        )
        print(f"\n[ALERT] CANARY TRIGGERED: {event_type} on {norm_path}")

        # Step 1: Attribute the offending process PID
        t_attr_start = time.time()
        offending_pid = find_offending_pid(norm_path)
        t_attr_end = time.time()

        record = get_last_attribution_record() or {}
        confidence = record.get("confidence", "NONE")
        method = record.get("attempt_method", "unknown")
        latency = record.get("latency_ms", round((time.time() - detected_at) * 1000, 2))

        if offending_pid is None:
            logger.info(
                "Detection fired for %s — offending process already neutralized or allowlisted.",
                norm_path
            )
            print(f"[Canary Shield] Threat already neutralized: no active attacker process on {os.path.basename(norm_path)}.")
            return

        print(
            f"[Canary Shield] Attributed PID: {offending_pid} | Method: {method} | "
            f"Confidence: {confidence} | Latency: {latency:.2f} ms"
        )

        # Step 2: Contain the threat (Instant suspension + process tree termination + quarantine + alert)
        terminated = kill_process(
            offending_pid,
            confidence=confidence,
            method=method,
            target_path=norm_path,
            latency_ms=latency,
            t_event_received=t_event_received,
            t_attr_start=t_attr_start,
            t_attr_end=t_attr_end,
        )

        if terminated:
            print(f"[Canary Shield] >>> CONTAINMENT ACTIVE: Process {offending_pid} TERMINATED <<<\n")

            # Step 3: Self-Healing Decoy Tripwire
            if AUTO_RESTORE_CANARIES:
                self.suppress_canary(norm_path, duration=3.0)
                restore_canary(norm_path)
        else:
            print(f"[Canary Shield] >>> CONTAINMENT HELD: Process {offending_pid} NOT terminated <<<\n")

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._handle_event("MODIFIED", event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        # Ransomware encryption often renames: file.docx -> file.docx.locked
        if not event.is_directory:
            self._handle_event("RENAMED", event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        # Some ransomware variants delete then recreate files
        if not event.is_directory:
            self._handle_event("DELETED", event.src_path)


def start_monitoring(
    canary_paths: list[str],
    block: bool = True
) -> tuple[Observer, Optional[VSSGuard]]:
    """
    Start the watchdog observer and concurrent VSS guard.
    
    Args:
        canary_paths: List of canary file paths to guard.
        block: If True, blocks until KeyboardInterrupt. If False, returns (Observer, VSSGuard).
    """
    # Configure root logger with RotatingFileHandler (10MB max, 5 backups)
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            file_handler,
            logging.StreamHandler(),
        ],
    )

    watched_dirs = get_watched_directories()
    for d in watched_dirs:
        print_target_path(f"Monitor Watching -> {d}")

    handler = CanaryEventHandler(canary_paths)
    observer = Observer()

    for directory in watched_dirs:
        if os.path.isdir(directory):
            observer.schedule(handler, directory, recursive=True)
            logger.info("Watchdog scheduled for directory: %s", directory)
        else:
            logger.warning("Target directory not found: %s", directory)

    # Start filesystem observer
    observer.start()
    logger.info("Canary Shield Monitor is running. %d canaries active.", len(canary_paths))

    # Start incremental process cache (Phase 2 optimization)
    start_process_cache()

    # Start concurrent VSS anti-recovery guard
    vss_guard = VSSGuard(check_interval=0.5)
    vss_guard.start()

    if block:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping Canary Shield Monitor (Ctrl+C received)...")
            vss_guard.stop()
            observer.stop()
            stop_process_cache()
        observer.join()
        stop_process_cache()
        logger.info("Canary Shield Monitor stopped.")

    return observer, vss_guard
