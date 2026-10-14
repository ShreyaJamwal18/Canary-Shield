"""
Canary Shield — Real-Time Alerting & Notification Module.

Dispatches instant desktop notifications when zero-day ransomware is intercepted:
- Native Windows Toast Notification (Action Center).
- Fallback balloon or non-blocking system alert dialog.
- Asynchronous non-blocking dispatch so alerting never slows containment down.
"""

import os
import sys
import subprocess
import threading
import logging
from typing import Optional

from config import DESKTOP_ALERTS

logger = logging.getLogger("canary_shield.notify")


def _send_windows_toast_powershell(title: str, message: str) -> None:
    """Send a native Windows Toast notification via lightweight PowerShell snippet."""
    # Escape quotes for PowerShell
    safe_title = title.replace('"', '`"')
    safe_message = message.replace('"', '`"').replace("\n", " ")

    ps_script = f"""
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $textNodes = $template.GetElementsByTagName("text")
    $textNodes.Item(0).AppendChild($template.CreateTextNode("{safe_title}")) > $null
    $textNodes.Item(1).AppendChild($template.CreateTextNode("{safe_message}")) > $null
    $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Canary Shield EDR").Show($toast)
    """

    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_script],
            capture_output=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        logger.debug("PowerShell toast notification fallback: %s", exc)


def send_threat_alert(
    pid: int,
    proc_name: str,
    latency_ms: float,
    confidence: str = "HIGH",
    method: str = "direct_handle"
) -> None:
    """
    Trigger a high-priority desktop alert warning that ransomware was neutralized.
    Runs asynchronously in a background thread to prevent blocking core defense loops.
    """
    if not DESKTOP_ALERTS:
        return

    title = "🛡️ Canary Shield: Ransomware Attack Blocked!"
    message = (
        f"Threat Neutralized!\n"
        f"Offending Process: {proc_name} (PID: {pid})\n"
        f"Containment Latency: {latency_ms:.1f}ms ({confidence} Confidence)\n"
        f"Your files were protected before encryption."
    )

    def _worker():
        try:
            if sys.platform == "win32":
                _send_windows_toast_powershell(title, message)
            else:
                logger.info("ALERT: %s — %s", title, message)
        except Exception as exc:
            logger.warning("Could not dispatch desktop alert: %s", exc)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
