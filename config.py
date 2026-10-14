"""
Canary Shield — Configuration Module.

Central configuration for Canary Shield deception-based ransomware mitigation.
Enforces Hard Rule 1 (strict sandbox targeting in test mode) and Hard Rule 2 (frozen production allowlist).
Equipped with real-world enterprise capabilities:
- Dynamic JSON configuration loading (canary_shield_config.json).
- Multi-directory production protection (Documents, Desktop, Downloads, custom shares).
- Malware quarantine and forensic incident directory management.
- Real-time VSS anti-recovery protection settings.
- Desktop alerting and process tree containment toggles.
"""

import os
import sys
import json
from typing import List, Dict, Any

# --- Project & Base Paths ------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Dedicated sandbox directory created strictly INSIDE this project repository (HARD RULE 1).
# Never points to ~/Documents, Desktop, or any real user directories during testing.
TEST_SANDBOX_DIR = os.path.join(BASE_DIR, "test_sandbox")
os.makedirs(TEST_SANDBOX_DIR, exist_ok=True)

# Enterprise Forensic & Quarantine Directories
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
INCIDENTS_DIR = os.path.join(BASE_DIR, "incidents")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(INCIDENTS_DIR, exist_ok=True)

CONFIG_FILE_PATH = os.path.join(BASE_DIR, "canary_shield_config.json")

def print_target_path(caller_name: str = "Canary Shield") -> None:
    """Explicitly print the full target sandbox directory path (HARD RULE 1)."""
    print(f"[{caller_name}] TARGET SANDBOX PATH: {TEST_SANDBOX_DIR}")


# --- JSON Configuration Loader ------------------------------------------
def load_config() -> Dict[str, Any]:
    """Loads configuration settings from canary_shield_config.json if available."""
    default_cfg: Dict[str, Any] = {
        "mode": "test",
        "production_watch_directories": ["~/Documents", "~/Desktop", "~/Downloads"],
        "canary_count_per_directory": 10,
        "auto_restore_canaries": True,
        "instant_thread_freeze": True,
        "terminate_process_tree": True,
        "quarantine_malware": True,
        "desktop_alerts": True,
        "vss_protection_enabled": False,
        "log_file": "canary_shield.log",
        "quarantine_dir": "quarantine",
        "incidents_dir": "incidents",
        "lookup_window_seconds": 0.35,
    }
    if os.path.exists(CONFIG_FILE_PATH):
        try:
            with open(CONFIG_FILE_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                default_cfg.update(loaded)
        except Exception as exc:
            print(f"[Warning] Failed to read {CONFIG_FILE_PATH}: {exc}. Using default configuration.")
    return default_cfg

_CONFIG = load_config()


# --- Execution Mode & Directory Resolution ------------------------------
def is_test_mode() -> bool:
    """
    Returns True if CANARY_TEST_MODE environment variable is active or config is set to test mode.
    Environment variable takes absolute precedence.
    """
    env_mode = os.environ.get("CANARY_TEST_MODE")
    if env_mode is not None:
        return env_mode == "1"
    return _CONFIG.get("mode", "test").lower() == "test"


def get_watched_directories() -> List[str]:
    """
    Returns the directories actively monitored by Canary Shield.
    In Test Mode: Strictly returns [TEST_SANDBOX_DIR] (HARD RULE 1).
    In Production Mode: Returns real-world configured user directories.
    """
    if is_test_mode():
        return [TEST_SANDBOX_DIR]

    raw_dirs = _CONFIG.get("production_watch_directories", ["~/Documents", "~/Desktop"])
    resolved: List[str] = []
    for d in raw_dirs:
        expanded = os.path.normpath(os.path.abspath(os.path.expanduser(d)))
        if os.path.isdir(expanded):
            resolved.append(expanded)
        else:
            try:
                os.makedirs(expanded, exist_ok=True)
                resolved.append(expanded)
            except Exception:
                pass

    if not resolved:
        return [TEST_SANDBOX_DIR]
    return resolved

WATCHED_DIRECTORIES = get_watched_directories()


# --- Decoy (Canary) Deployment Settings ----------------------------------
CANARY_COUNT_PER_DIR = _CONFIG.get("canary_count_per_directory", 10)

# Alphabet-leading prefixes ('!', '00_', '~$') trap sequential A-Z ransomware traversals
CANARY_PREFIXES = ["!_confidential_", "~$q4_financial_", "00_audit_", "!_passwords_"]
CANARY_EXTENSIONS = [".docx", ".xlsx", ".pdf", ".jpg", ".txt"]
CANARY_FILL_SIZE_BYTES = 8192

AUTO_RESTORE_CANARIES = _CONFIG.get("auto_restore_canaries", True)
INSTANT_THREAD_FREEZE = _CONFIG.get("instant_thread_freeze", True)
TERMINATE_PROCESS_TREE = _CONFIG.get("terminate_process_tree", True)
QUARANTINE_MALWARE = _CONFIG.get("quarantine_malware", True)
DESKTOP_ALERTS = _CONFIG.get("desktop_alerts", True)
VSS_PROTECTION_ENABLED = _CONFIG.get("vss_protection_enabled", False)


# --- Process Safety & Allowlist (HARD RULE 2) -----------------------------
# HARD RULE 2: The PRODUCTION PROCESS_ALLOWLIST is FROZEN and NEVER weakened.
# It protects critical Windows OS core components, services, security agents, and sync clients.
PRODUCTION_PROCESS_ALLOWLIST = frozenset({
    # Windows Core Operating System Processes
    "system",
    "system idle process",
    "registry",
    "memcompression",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "winlogon.exe",
    "dwm.exe",
    "explorer.exe",
    "sihost.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "conhost.exe",
    "spoolsv.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "runtimebroker.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "msmpeng.exe",
    "nissrv.exe",
    "audiodg.exe",
    "wudfhost.exe",
    "wmiprvse.exe",
    "searchindexer.exe",
    "searchfilterhost.exe",
    "searchprotocolhost.exe",
    "dashost.exe",
    "aggregatorhost.exe",
    "lockapp.exe",
    "shellhost.exe",
    "textinputhost.exe",
    "useroobebroker.exe",
    "unsecapp.exe",
    "servicehost.exe",
    "mmsshost.exe",
    "uihost.exe",
    "defendersessionhelper.exe",
    "mpdefendercoreservice.exe",
    "crossdeviceservice.exe",
    "crossdeviceresume.exe",
    "phoneexperiencehost.exe",
    "widgetservice.exe",
    "widgetboard.exe",
    "dllhost.exe",
    "backgroundtaskhost.exe",
    "helppane.exe",
    "appactions.exe",
    "mousocoreworker.exe",
    "acrocef.exe",
    "acrobat.exe",
    "acrord32.exe",

    # Antivirus, Endpoint Detection & Security Services
    "mcshield.exe",
    "mfeavsvc.exe",
    "mfemms.exe",
    "mccspservicehost.exe",
    "mcuicnt.exe",
    "mfevtps.exe",
    "expressvpnd.exe",

    # System Drivers, Hardware & Diagnostic Services
    "diagscap.exe",
    "apphelpercap.exe",
    "networkcap.exe",
    "sysinfocap.exe",
    "hp-one-agent-service.exe",
    "hpcommrecovery.exe",
    "hpprintscandoctorservice.exe",
    "oneapp.igcc.winservice.exe",
    "intelaudioservice.exe",
    "userawarenessservice.exe",
    "userawarenesshelper.exe",
    "gameinputredistservice.exe",
    "gameinputsvc.exe",
    "gamingservicesnet.exe",
    "gamingservices.exe",
    "jhi_service.exe",
    "etdservice.exe",
    "etdctrl.exe",
    "esif_uf.exe",
    "rstmwservice.exe",
    "rtkauduservice64.exe",
    "rtkbtmanserv.exe",
    "modulecoreservice.exe",
    "secomn64.exe",
    "wmiregistrationservice.exe",
    "hpsystemeventutilitybackground.exe",
    "hpsystemeventutilityhost.exe",
    "hpmedianetwork.exe",
    "intelcphdcpsvc.exe",
    "igfxemn.exe",
    "igfxcuiservicen.exe",
    "pefservice.exe",

    # Shells, System Terminals & IDEs
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "code.exe",
    "antigravity.exe",
    "antigravity ide.exe",

    # Cloud Sync, Productivity & Backup Clients
    "onedrive.exe",
    "onedrive.sync.service.exe",
    "dropbox.exe",
    "googledrivesync.exe",
    "backup.exe",
    "adobecollabsync.exe",
    "wps.exe",
    "wpscloudsvr.exe",
    "wsnativepushservice.exe",
    "wstoastnotification.exe",
    "officeclicktorun.exe",

    # Web Browsers & Heavy Desktop Apps (prevents handle scanning latency)
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "firefox.exe",
    "opera.exe",
    "brave.exe",
    "bravecrashhandler.exe",
    "bravecrashhandler64.exe",
    "crashpad_handler.exe",
    "claude.exe",
    "whatsapp.root.exe",
    "spotifylauncher.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "steamservice.exe",
    "hpprinterhealthmonitor.exe",
    "systemsettings.exe",
    "notepad.exe",
    "applicationframehost.exe",

    # Developer & Enterprise Automation Background Services (reduces attribution scan noise)
    "uipath.robotjs.userhost.exe",
    "uipath.robotjs.servicehost.exe",
    "uipath.updateservice.agent.exe",
    "uipath.updateservice.worker.exe",
    "jusched.exe",
    "language_server.exe",
    "promecefpluginhost.exe",

    # Python runtime (protected in production to prevent killing legitimate scripts)
    "python.exe",
    "pythonw.exe",
    "python3.exe",
})

# Backward compatibility alias
PROCESS_ALLOWLIST = PRODUCTION_PROCESS_ALLOWLIST

# SEPARATE test-only allowlist: used ONLY when CANARY_TEST_MODE=1.
# All critical OS components remain protected, but python.exe is omitted
# so simulate_attack.py (a Python test harness) can be attributed and contained.
TEST_PROCESS_ALLOWLIST = frozenset(
    PRODUCTION_PROCESS_ALLOWLIST - {"python.exe", "pythonw.exe", "python3.exe"}
)

def get_active_allowlist() -> frozenset[str]:
    """
    Returns the effective process allowlist.
    In production: returns the full PRODUCTION_PROCESS_ALLOWLIST (including python.exe).
    In test mode: returns TEST_PROCESS_ALLOWLIST so simulate_attack.py can be tested.
    """
    if is_test_mode():
        return TEST_PROCESS_ALLOWLIST
    return PRODUCTION_PROCESS_ALLOWLIST


# --- Detection & Latency Tuning -------------------------------------------
PID_LOOKUP_WINDOW_SECONDS = float(_CONFIG.get("lookup_window_seconds", 0.35))
LOG_FILE = os.path.join(BASE_DIR, _CONFIG.get("log_file", "canary_shield.log"))
