# Canary Shield — Realism Variant Test Results

**Date:** 2026-11-18 15:25

**Sandbox:** `C:\Users\91700\Documents\MDC\test_sandbox`

**Runs per variant:** 5

**Containment:** Real (not stubbed)


## Summary Table


| Variant | Detected | PID Correct | Method | Confidence | Containment ms (median) | Decoys Hit (median) | User Files Lost (worst) | Orphans |
|---------|----------|-------------|--------|------------|------------------------|--------------------|-----------------------|---------|
| A: No held handle (--hold-handle 0) | 5/5 | 5/5 | directory_heuristic | MEDIUM | 235.1 | 2 | 0 | 0 |
| B: Maximum speed (no delay) | 5/5 | 0/5 | none | NONE | N/A | 15 | 5 | 0 |
| C: Different working directory | 5/5 | 5/5 | directory_heuristic | MEDIUM | 285.9 | 2 | 0 | 0 |
| D: Multi-process (3 child workers) | 5/5 | 0/5 | none | NONE | N/A | 15 | 5 | 0 |
| E-sorted: Traversal order: alphabetical | 5/5 | 5/5 | directory_heuristic | MEDIUM | 259.3 | 4 | 0 | 0 |
| E-reverse: Traversal order: reverse | 5/5 | 5/5 | directory_heuristic | MEDIUM | 235.2 | 3 | 5 | 0 |
| E-random: Traversal order: random | 5/5 | 5/5 | directory_heuristic | MEDIUM | 232.6 | 3 | 2 | 0 |
| F: Delete-and-recreate pattern | 5/5 | 5/5 | directory_heuristic | MEDIUM | 240.0 | 2 | 2 | 0 |
| G: Immediate start (<50 ms) | 5/5 | 3/5 | directory_heuristic | MEDIUM | 477.9 | 13 | 5 | 0 |

## Per-Variant Detail

### A: No held handle (--hold-handle 0)

| Run | Detected | PID Correct | Method | Confidence | Containment ms | Decoys Hit | User Lost | Orphans | Error |
|-----|----------|-------------|--------|------------|---------------|------------|-----------|---------|-------|
| 1 | Yes | Yes | directory_heuristic | MEDIUM | 306.8 | 3 | 0 | 0 |  |
| 2 | Yes | Yes | directory_heuristic | MEDIUM | 216.8 | 2 | 0 | 0 |  |
| 3 | Yes | Yes | directory_heuristic | MEDIUM | 238.9 | 2 | 0 | 0 |  |
| 4 | Yes | Yes | directory_heuristic | MEDIUM | 234.1 | 4 | 0 | 0 |  |
| 5 | Yes | Yes | directory_heuristic | MEDIUM | 235.1 | 1 | 0 | 0 |  |

### B: Maximum speed (no delay)

| Run | Detected | PID Correct | Method | Confidence | Containment ms | Decoys Hit | User Lost | Orphans | Error |
|-----|----------|-------------|--------|------------|---------------|------------|-----------|---------|-------|
| 1 | Yes | **No** | none | NONE | N/A | 14 | 5 | 0 |  |
| 2 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |
| 3 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |
| 4 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |
| 5 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |

### C: Different working directory

| Run | Detected | PID Correct | Method | Confidence | Containment ms | Decoys Hit | User Lost | Orphans | Error |
|-----|----------|-------------|--------|------------|---------------|------------|-----------|---------|-------|
| 1 | Yes | Yes | directory_heuristic | MEDIUM | 312.8 | 2 | 0 | 0 |  |
| 2 | Yes | Yes | directory_heuristic | MEDIUM | 285.9 | 2 | 0 | 0 |  |
| 3 | Yes | Yes | directory_heuristic | MEDIUM | 495.5 | 4 | 0 | 0 |  |
| 4 | Yes | Yes | directory_heuristic | MEDIUM | 218.1 | 1 | 0 | 0 |  |
| 5 | Yes | Yes | directory_heuristic | MEDIUM | 220.4 | 3 | 0 | 0 |  |

### D: Multi-process (3 child workers)

| Run | Detected | PID Correct | Method | Confidence | Containment ms | Decoys Hit | User Lost | Orphans | Error |
|-----|----------|-------------|--------|------------|---------------|------------|-----------|---------|-------|
| 1 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |
| 2 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |
| 3 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |
| 4 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |
| 5 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |

### E-sorted: Traversal order: alphabetical

| Run | Detected | PID Correct | Method | Confidence | Containment ms | Decoys Hit | User Lost | Orphans | Error |
|-----|----------|-------------|--------|------------|---------------|------------|-----------|---------|-------|
| 1 | Yes | Yes | directory_heuristic | MEDIUM | 824.1 | 6 | 0 | 0 |  |
| 2 | Yes | Yes | directory_heuristic | MEDIUM | 650.3 | 6 | 0 | 0 |  |
| 3 | Yes | Yes | directory_heuristic | MEDIUM | 259.3 | 4 | 0 | 0 |  |
| 4 | Yes | Yes | directory_heuristic | MEDIUM | 211.4 | 2 | 0 | 0 |  |
| 5 | Yes | Yes | directory_heuristic | MEDIUM | 223.6 | 1 | 0 | 0 |  |

### E-reverse: Traversal order: reverse

| Run | Detected | PID Correct | Method | Confidence | Containment ms | Decoys Hit | User Lost | Orphans | Error |
|-----|----------|-------------|--------|------------|---------------|------------|-----------|---------|-------|
| 1 | Yes | Yes | directory_heuristic | MEDIUM | 573.3 | 3 | 2 | 0 |  |
| 2 | Yes | Yes | directory_heuristic | MEDIUM | 225.2 | 1 | 1 | 0 |  |
| 3 | Yes | Yes | directory_heuristic | MEDIUM | 235.2 | 2 | 1 | 0 |  |
| 4 | Yes | Yes | directory_heuristic | MEDIUM | 222.2 | 7 | 5 | 0 |  |
| 5 | Yes | Yes | directory_heuristic | MEDIUM | 478.4 | 3 | 0 | 0 |  |

### E-random: Traversal order: random

| Run | Detected | PID Correct | Method | Confidence | Containment ms | Decoys Hit | User Lost | Orphans | Error |
|-----|----------|-------------|--------|------------|---------------|------------|-----------|---------|-------|
| 1 | Yes | Yes | directory_heuristic | MEDIUM | 260.0 | 3 | 2 | 0 |  |
| 2 | Yes | Yes | directory_heuristic | MEDIUM | 225.9 | 3 | 0 | 0 |  |
| 3 | Yes | Yes | directory_heuristic | MEDIUM | 232.6 | 4 | 2 | 0 |  |
| 4 | Yes | Yes | directory_heuristic | MEDIUM | 371.0 | 2 | 1 | 0 |  |
| 5 | Yes | Yes | directory_heuristic | MEDIUM | 228.0 | 3 | 1 | 0 |  |

### F: Delete-and-recreate pattern

| Run | Detected | PID Correct | Method | Confidence | Containment ms | Decoys Hit | User Lost | Orphans | Error |
|-----|----------|-------------|--------|------------|---------------|------------|-----------|---------|-------|
| 1 | Yes | Yes | directory_heuristic | MEDIUM | 257.5 | 3 | 0 | 0 |  |
| 2 | Yes | Yes | directory_heuristic | MEDIUM | 240.0 | 2 | 0 | 0 |  |
| 3 | Yes | Yes | directory_heuristic | MEDIUM | 214.8 | 2 | 0 | 0 |  |
| 4 | Yes | Yes | directory_heuristic | MEDIUM | 1398.7 | 10 | 2 | 0 |  |
| 5 | Yes | Yes | directory_heuristic | MEDIUM | 234.1 | 2 | 0 | 0 |  |

### G: Immediate start (<50 ms)

| Run | Detected | PID Correct | Method | Confidence | Containment ms | Decoys Hit | User Lost | Orphans | Error |
|-----|----------|-------------|--------|------------|---------------|------------|-----------|---------|-------|
| 1 | Yes | Yes | directory_heuristic | MEDIUM | 477.9 | 13 | 5 | 0 |  |
| 2 | Yes | Yes | directory_heuristic | MEDIUM | 383.9 | 13 | 5 | 0 |  |
| 3 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |
| 4 | Yes | **No** | none | NONE | N/A | 15 | 5 | 0 |  |
| 5 | Yes | Yes | directory_heuristic | MEDIUM | 746.3 | 9 | 1 | 0 |  |

## Analysis

**Issues found:**

- **B: Maximum speed (no delay)**: Attribution wrong in 5/5 detected runs.
- **B: Maximum speed (no delay)**: 5 user file(s) lost in worst case.
- **D: Multi-process (3 child workers)**: Attribution wrong in 5/5 detected runs.
- **D: Multi-process (3 child workers)**: 5 user file(s) lost in worst case.
- **E-reverse: Traversal order: reverse**: 5 user file(s) lost in worst case.
- **E-random: Traversal order: random**: 2 user file(s) lost in worst case.
- **F: Delete-and-recreate pattern**: 2 user file(s) lost in worst case.
- **G: Immediate start (<50 ms)**: Attribution wrong in 2/5 detected runs.
- **G: Immediate start (<50 ms)**: 5 user file(s) lost in worst case.

### Where the system works

- Variants that hold file handles open (standard pattern) are reliably detected and attributed via direct handle matching (HIGH confidence).
- The watchdog event filter correctly fires on MODIFIED, RENAMED, and DELETED events affecting canary decoy files.

### Where the system may struggle

- **No handle hold (A, B, G):** When the attacker opens, writes, and closes immediately, the direct_handle method cannot find an open handle. Attribution falls back to directory_heuristic (MEDIUM confidence) or fails entirely.
- **Different working directory (C):** If the attacker process does not `chdir` into the sandbox, the cwd heuristic cannot match it. Attribution relies solely on open file handles or cmdline matching.
- **Multi-process (D):** The parent spawns children that do the actual I/O. Attribution may find a child PID, but the parent (coordinator) may escape.
- **Maximum speed (B) / Immediate start (G):** The process cache polls every 100 ms. A process that starts, encrypts, and exits within that window may not appear in the cache at all, causing attribution failure.

### Why

The core detection (watchdog MODIFIED/RENAMED/DELETED on canary paths) is robust — it fires on any file I/O that changes a canary. The bottleneck is **attribution**: mapping the event back to a PID. The system uses three strategies:

1. **Direct handle match** (HIGH): Checks open file handles on all candidate processes. Only works if the attacker still holds the handle when the scan runs.
2. **Directory heuristic** (MEDIUM): Checks cwd, cmdline, and open files in the same directory. Works when the attacker's process context points to the sandbox.
3. **Process cache**: Background thread polling every 100 ms. New processes that start and exit between polls are invisible.

The variants in this test expose exactly these timing and context gaps.
