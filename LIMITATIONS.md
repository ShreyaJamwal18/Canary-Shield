# Canary Shield — Prototype Limitations & Technical Constraints

*Honest evaluation points for capstone project defense, oral examination, and report documentation.*

---

While Canary Shield effectively demonstrates deception-based ransomware containment in userland, evaluators should be aware of the following fundamental limitations of this prototype:

1. **Handle-Closure Race Condition on Ultra-Fast Writes**:
   If a ransomware binary opens a canary file, writes encrypted payload, and immediately closes the file handle within a fraction of a millisecond, the OS file handle is released before `watchdog`'s user-space event callback triggers `psutil.open_files()`. In such scenarios, direct handle matching cannot find the active handle, forcing reliance on the directory activity fallback heuristic.

2. **Absence of Kernel-Level (Minifilter / ETW) Tracing**:
   Canary Shield operates entirely in userland via the Python `watchdog` library (which wraps the Win32 `ReadDirectoryChangesW` API). It lacks a Windows Kernel Filesystem Minifilter driver or Event Tracing for Windows (ETW) provider (`Microsoft-Windows-Kernel-File`). Consequently, it cannot intercept I/O synchronously *before* the filesystem write completes, nor can it inspect the caller's thread token directly at the kernel driver layer.

3. **Lack of Automated Cryptographic Rollback**:
   Canary Shield is an **interception and containment** mechanism, not a data recovery tool. Decoys are designed to be sacrificed to trip the alarm early. Any user files that were accessed and encrypted *prior* to the ransomware tripping a canary remain encrypted. Canary Shield does not implement Volume Shadow Copy (VSS) restoration or automated filesystem snapshot rollbacks.

4. **Heuristic PID Attribution Ambiguity Under Concurrent Activity**:
   When falling back to the directory heuristic (if direct handle matching yields no match), Canary Shield aggregates non-allowlisted processes with open files or active working directories near the target path. In high-traffic environments where multiple background applications are actively reading or writing files in the same directory simultaneously, the heuristic can misattribute the offending PID or suffer reduced confidence.

5. **Single-OS Specialization (Windows Focus)**:
   While Python and `psutil` are cross-platform, this prototype is engineered around Windows filesystem semantics (case-insensitive path resolution, Windows `FILE_ATTRIBUTE_HIDDEN` flags, Windows process name conventions, and `TerminateProcess` semantics). It does not currently implement Linux fanotify, macOS FSEvents, or POSIX extended permission monitoring.

6. **Process Termination Race on Multi-Threaded / Distributed Ransomware**:
   Modern sophisticated ransomware families (e.g., LockBit 3.0, BlackCat) employ multi-threaded encryption pools or spawn separate helper child processes per drive or directory. Terminating the single parent PID that tripped the canary may allow already-spawned asynchronous worker threads or subprocesses to briefly continue encryption unless the entire process tree is recursively identified and suspended.

7. **Decoy Signature & Evasion Vulnerability**:
   This prototype plants canaries based on specific naming patterns (`!_`, `00_`, `~$`) and file headers. Sophisticated zero-day ransomware specifically programmed with anti-canary heuristics (e.g., detecting hidden file attributes, checking file creation timestamps against system uptime, or cross-referencing recent user activity logs) could theoretically identify and avoid touching the decoy files.
