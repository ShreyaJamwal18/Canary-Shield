# Canary Shield — False Alarm Test Results

**Date:** 2026-11-18 15:02

**Sandbox:** `C:\Users\91700\Documents\MDC\test_sandbox`

**Runs per activity:** 3

**contain.kill_process:** Monkeypatched stub (never kills)


## Results Table


| Activity | Tripwire Fired | Event Type(s) | Attributed Process | Would Contain? |
|----------|---------------|---------------|-------------------|----------------|
| a. robocopy /E (read-only copy) | 0/3 | — | — | 0/3 |
| b. robocopy /M (reset archive bit) | 0/3 | — | — | 0/3 |
| c. Compress-Archive (zip) | 0/3 | — | — | 0/3 |
| d. Get-FileHash + Python read | 2/3 ⚠️ | MODIFIED | — | 0/3 |
| e. Windows Defender custom scan | 0/3 | — | — | 0/3 |
| f. Touch timestamps + attrib | 3/3 ⚠️ | MODIFIED | — | 0/3 |
| g. Copy-Item -Recurse | 0/3 | — | — | 0/3 |
| h. CONTROL: simulate_attack.py | 3/3 ✅ | DELETED, MODIFIED, RENAMED | python.exe (direct_handle, HIGH), python.exe (directory_heuristic, MEDIUM) | 2/3 ✅ |

## Summary

**5 false alarm(s) detected across benign activities.**

The following benign activities triggered the tripwire:

- **d. Get-FileHash + Python read**: fired 2/3 times (events: MODIFIED)
- **f. Touch timestamps + attrib**: fired 3/3 times (events: MODIFIED)

**Control test:** simulate_attack.py was detected in 3/3 runs ✅

## Manual Checks (not automated)

The following activities should be tested manually to verify no false alarms:

- [ ] **Windows Search indexing** the test_sandbox folder (wait for indexer to crawl)
- [ ] **File Explorer preview/thumbnails** — open test_sandbox in Explorer, enable preview pane
- [ ] **Open a decoy in Notepad** and save without changes
- [ ] **Open a decoy in Notepad** and save with minor edit (add a space)
- [ ] **Antivirus quick scan** (full system or targeted at test_sandbox)
- [ ] **OneDrive/File History** sync if enabled on the machine
- [ ] **Windows Backup** if configured to include the project folder
