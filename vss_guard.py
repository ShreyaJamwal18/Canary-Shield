"""
Canary Shield — Volume Shadow Copy (VSS) & Anti-Recovery Guard.

Detects and neutralizes malicious attempts to inhibit system recovery (MITRE ATT&CK T1490):
- Intercepts invocations of vssadmin, wbadmin, wmic, bcdedit aimed at wiping shadow copies.
- Operates concurrently alongside filesystem tripwires for layered defense-in-depth.
- Freezes offending processes executing backup deletion commands and alerts operators.
"""

import time
import threading
import logging
from typing import Optional
import psutil

from config import VSS_PROTECTION_ENABLED, get_active_allowlist
from contain import kill_process

logger = logging.getLogger("canary_shield.vss_guard")

# Known signatures of ransomware anti-recovery commands
SUSPICIOUS_RECOVERY_COMMANDS = [
    "vssadmin delete shadows",
    "vssadmin.exe delete shadows",
    "wmic shadowcopy delete",
    "wbadmin delete catalog",
    "wbadmin.exe delete catalog",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit.exe /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
]


class VSSGuard:
    """Monitors running processes for unauthorized attempts to delete backups or shadow copies."""
    def __init__(self, check_interval: float = 0.5):
        self.check_interval = check_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background VSS guard thread."""
        if not VSS_PROTECTION_ENABLED:
            logger.info("VSS Guard is disabled in configuration.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="VSSGuardThread")
        self._thread.start()
        logger.info("VSS Anti-Recovery Guard is active.")

    def stop(self) -> None:
        """Stop the background VSS guard thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        logger.info("VSS Anti-Recovery Guard stopped.")

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._check_processes()
            except Exception as exc:
                logger.debug("VSS Guard loop exception: %s", exc)
            self._stop_event.wait(self.check_interval)

    def _check_processes(self) -> None:
        active_allowlist = {name.lower() for name in get_active_allowlist()}

        for p in psutil.process_iter(["pid", "name"]):
            try:
                raw_name = (p.info.get("name") or "").lower()
                pid = p.pid

                # Skip core system processes
                if pid <= 4 or raw_name in active_allowlist:
                    continue

                # Inspect command line
                cmd = p.cmdline()
                if not cmd:
                    continue

                full_cmd = " ".join(cmd).lower()
                for sig in SUSPICIOUS_RECOVERY_COMMANDS:
                    if sig in full_cmd:
                        logger.critical(
                            "*** VSS ANTI-RECOVERY ATTACK DETECTED *** PID=%d (%s) Cmd='%s'",
                            pid, raw_name, full_cmd
                        )
                        print(f"\n[CRITICAL ALERT] Anti-Recovery Attempt: PID {pid} ({raw_name}) executed '{sig}'!")
                        
                        # Immediately contain the threat
                        kill_process(
                            pid=pid,
                            confidence="HIGH",
                            method="vss_signature_interception",
                            target_path=f"Volume Shadow Copy ({sig})",
                        )
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
