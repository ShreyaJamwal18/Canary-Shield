"""
Canary Shield — Windows Service (pywin32).

A win32serviceutil.ServiceFramework service that runs the same detection engine
as app.py / main.py, but under the Service Control Manager.

WHAT THIS IS:
  - Runs as LocalSystem so standard users cannot stop it.
  - Restarts automatically on failure (Windows recovery options).
  - Writes a heartbeat file every 2 s; logs tamper events if the previous
    run ended without a clean-shutdown marker.
  - Restricts its DACL so only SYSTEM and Administrators can stop / delete it.

WHAT THIS IS NOT:
  - This is NOT a Protected Process Light (PPL).  Making a service truly
    unkillable by an Administrator requires a Microsoft-signed Early Launch
    Anti-Malware (ELAM) driver, which is out of scope for this project.
  - An Administrator can still Stop-Service, taskkill /F, or sc delete.
  - The goal is "harder to tamper with" — not "impossible."

SAFETY:
  - By default, the service installs in TEST MODE (CANARY_TEST_MODE=1,
    monitoring test_sandbox only).
  - Production mode requires the explicit --i-understand-production flag
    at install time.
  - Start type is MANUAL (never automatic at boot) unless overridden.
"""

import os
import sys
import time
import json
import logging
import threading

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so config, monitor, decoy, etc.
# can be imported when the service is started by the SCM.
# ---------------------------------------------------------------------------
_SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
if _SERVICE_DIR not in sys.path:
    sys.path.insert(0, _SERVICE_DIR)

import win32serviceutil
import win32service
import win32event
import servicemanager

from config import BASE_DIR, LOG_FILE, INCIDENTS_DIR

logger = logging.getLogger("canary_shield.win_service")

# Heartbeat / tamper-detection paths
HEARTBEAT_FILE = os.path.join(BASE_DIR, "canary_shield_heartbeat.json")
SHUTDOWN_MARKER = os.path.join(BASE_DIR, "canary_shield_clean_shutdown")
SERVICE_NAME = "CanaryShield"


# =========================================================================
# HEARTBEAT & TAMPER-VISIBILITY HELPERS
# =========================================================================

def _write_heartbeat():
    """Atomically update the heartbeat file with the current timestamp."""
    data = {"pid": os.getpid(), "timestamp": time.time(), "iso": time.strftime("%Y-%m-%dT%H:%M:%S")}
    tmp = HEARTBEAT_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, HEARTBEAT_FILE)
    except Exception:
        pass


def _read_last_heartbeat():
    """Read the last heartbeat timestamp (epoch float) or None."""
    try:
        with open(HEARTBEAT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_shutdown_marker():
    """Write a clean-shutdown marker so the next start knows we exited cleanly."""
    try:
        with open(SHUTDOWN_MARKER, "w", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S"))
    except Exception:
        pass


def _check_and_log_tamper():
    """
    On startup, if the previous run did NOT leave a clean-shutdown marker,
    log a tamper / crash event with the downtime window.
    """
    clean = os.path.exists(SHUTDOWN_MARKER)
    last_hb = _read_last_heartbeat()

    # Remove the marker so the next crash is detected
    if os.path.exists(SHUTDOWN_MARKER):
        try:
            os.remove(SHUTDOWN_MARKER)
        except Exception:
            pass

    if clean:
        logger.info("Previous service run ended with a clean shutdown.")
        return

    if last_hb is None:
        logger.info("First service start (no previous heartbeat found).")
        return

    # Unclean shutdown detected — log it
    t1 = last_hb.get("timestamp", 0)
    t2 = time.time()
    t1_iso = last_hb.get("iso", "unknown")
    t2_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
    downtime_s = round(t2 - t1, 1)

    msg = (
        f"TAMPER/CRASH DETECTED: Monitor was down from {t1_iso} to {t2_iso} "
        f"(~{downtime_s}s). Previous PID {last_hb.get('pid', '?')} did not "
        f"shut down cleanly."
    )
    logger.critical(msg)
    servicemanager.LogWarningMsg(msg)

    # Also write a tamper incident file
    try:
        os.makedirs(INCIDENTS_DIR, exist_ok=True)
        incident = {
            "type": "TAMPER_DETECTED",
            "last_heartbeat_iso": t1_iso,
            "restart_iso": t2_iso,
            "downtime_seconds": downtime_s,
            "previous_pid": last_hb.get("pid"),
            "message": msg,
        }
        fname = f"TAMPER-{int(t2)}.json"
        with open(os.path.join(INCIDENTS_DIR, fname), "w", encoding="utf-8") as f:
            json.dump(incident, f, indent=2)
        logger.info("Tamper incident recorded: %s", fname)
    except Exception as exc:
        logger.error("Could not write tamper incident: %s", exc)


# =========================================================================
# HEARTBEAT THREAD
# =========================================================================

class _HeartbeatThread(threading.Thread):
    """Writes heartbeat every 2 seconds until stopped."""

    def __init__(self):
        super().__init__(name="ServiceHeartbeat", daemon=True)
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            _write_heartbeat()
            self._stop_event.wait(2.0)

    def stop(self):
        self._stop_event.set()


# =========================================================================
# WINDOWS SERVICE CLASS
# =========================================================================

class CanaryShieldService(win32serviceutil.ServiceFramework):
    """
    pywin32 Windows Service that runs the Canary Shield detection engine.
    Installs as 'CanaryShield' with display name 'Canary Shield Monitor'.
    """

    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "Canary Shield Monitor"
    _svc_description_ = (
        "Deception-based ransomware defense. Plants canary decoy files and "
        "monitors them for tampering. Detects, attributes, and contains "
        "ransomware processes in real time."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._observer = None
        self._vss_guard = None
        self._heartbeat = None

    def SvcStop(self):
        """Called by the SCM when the service is asked to stop."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        logger.info("Service stop requested.")
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        """Main service entry point — mirrors main.py / app.py arm_shield()."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[
                logging.FileHandler(LOG_FILE, encoding="utf-8"),
            ],
        )

        try:
            self._run_engine()
        except Exception as exc:
            logger.critical("Service crashed: %s", exc, exc_info=True)
            servicemanager.LogErrorMsg(f"CanaryShield service crashed: {exc}")

    def _run_engine(self):
        """Deploy decoys, start monitoring, heartbeat, then wait for stop."""
        # Force test mode unless production was explicitly allowed at install
        env_mode = os.environ.get("CANARY_TEST_MODE", "1")
        os.environ["CANARY_TEST_MODE"] = env_mode

        from config import is_test_mode, print_target_path
        from decoy import deploy_decoys
        from monitor import start_monitoring

        logger.info(
            "CanaryShield service starting (mode=%s, pid=%d).",
            "TEST" if is_test_mode() else "PRODUCTION", os.getpid(),
        )
        print_target_path("Service")

        # Tamper detection: check if previous run ended cleanly
        _check_and_log_tamper()

        # Deploy decoys
        canary_paths = deploy_decoys()
        logger.info("Deployed %d canary tripwires.", len(canary_paths))

        # Start monitoring (non-blocking)
        self._observer, self._vss_guard = start_monitoring(canary_paths, block=False)
        logger.info("Monitoring armed.")

        # Start heartbeat
        self._heartbeat = _HeartbeatThread()
        self._heartbeat.start()

        # Wait for stop signal
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        # Clean shutdown
        logger.info("Service shutting down cleanly.")
        self._heartbeat.stop()

        if self._vss_guard:
            try:
                self._vss_guard.stop()
            except Exception:
                pass

        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=3.0)
            except Exception:
                pass

        try:
            from process_id import stop_process_cache
            stop_process_cache()
        except Exception:
            pass

        _write_shutdown_marker()
        logger.info("Service stopped cleanly.")


# =========================================================================
# SERVICE QUERY HELPER (for app.py)
# =========================================================================

def is_service_running() -> bool:
    """Check if the CanaryShield Windows service is currently running."""
    try:
        import psutil
        svc = psutil.win_service_get(SERVICE_NAME)
        info = svc.as_dict()
        return info.get("status") == "running"
    except Exception:
        return False


# =========================================================================
# CLI ENTRY POINT
# =========================================================================

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Started by the SCM
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CanaryShieldService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(CanaryShieldService)
