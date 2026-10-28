# Canary Shield — Prototype Limitations & Technical Constraints

*Honest evaluation points for capstone project defense, oral examination, and report documentation.*

---

While Canary Shield effectively demonstrates deception-based ransomware containment, evaluators should understand the following fundamental constraints of this prototype:

1. **Attribution is Heuristic and Simulator-Tested**:
   PID attribution relies on heuristic signals (directory match, command-line arguments, or direct open file handles when available) and is reported with an explicit confidence level (`HIGH`, `MEDIUM`, `LOW`, or `NONE`). It has only been evaluated against the bundled benign simulator, not real-world weaponized ransomware.

2. **Detection is Not Prevention (Decoys are Sacrificed)**:
   Canary Shield detects threats only *after* a decoy tripwire is accessed or modified. Consequently, at least one decoy file is typically touched and encrypted before the attacker is identified and stopped. Any genuine user files accessed before the canary is tripped remain encrypted; Canary Shield does not provide automated cryptographic rollback or recovery.

3. **Simulator Handle-Holding vs. Real Malware**:
   The bundled attack simulator holds open file handles briefly (e.g., 0.4 seconds in the test harness) to demonstrate direct handle attribution. Real ransomware families often open, encrypt, and close file handles within milliseconds, which makes direct handle matching harder and forces the defense to rely on the directory activity fallback heuristic.

4. **Process Cache Polling Window**:
   The incremental process cache polls `psutil.pids()` approximately every 100 ms to discover newly spawned processes with minimal overhead. If an attacker process launches and completes its malicious actions entirely within that 100 ms polling window, it will not yet be in the pre-warmed cache and the system falls back to a slower fresh scan.

5. **User-Space Architecture and Privilege Constraints**:
   The monitor runs as an ordinary user-space Python process. Any malware executing with administrative or SYSTEM privileges could theoretically terminate or suspend Canary Shield itself. A production-grade implementation would require deployment as an Early Launch Anti-Malware (ELAM) driver, a Windows Protected Service (PPL), or a kernel filesystem minifilter using Event Tracing for Windows (ETW `Microsoft-Windows-Kernel-File`).

6. **VSS Guard Disabled by Default**:
   The Volume Shadow Copy (VSS) anti-recovery guard is disabled by default in configuration because it performs system-wide process scanning that creates unnecessary overhead outside the sandbox scope.

7. **Standalone Executable Scope**:
   The standalone binary bundle in `dist_exe/` was compiled during early packaging tests prior to the process-cache optimization and is not part of the verified demo or benchmark path. The canonical evaluation path is `app.py` via the Desktop shortcut / `CanaryShield.bat` or `python main.py`.

8. **Measured Containment Performance Scope**:
   In 5 consecutive runs of `run_full_e2e_test.py` in test mode (`CANARY_TEST_MODE=1`) after process-cache optimization, the median time-to-contain was about **260 ms**, and the worst run was about **950 ms** (typically about a quarter of a second, under a second in the worst test run). Before optimization, the median was about 930 ms and the worst run was about 2450 ms. Typically 1 decoy is touched before containment (before optimization: 1 to 4). Note that all benchmark numbers were measured strictly against the bundled benign simulator in a local sandbox on one Windows machine.
