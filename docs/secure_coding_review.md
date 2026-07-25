# Secure Coding Review — Basic-Network-Sniffer

**Target:** Basic-Network-Sniffer (Python) — `main.py`, `utils.py`, `raw_sniffer.py`
**Reviewer:** Bayrem Ben Arous
**Date:** 2026-07-25
**Task:** Cyber Security Task 3 — Secure Coding Review

## Methodology

1. **Static analysis** — [Bandit](https://bandit.readthedocs.io/) (industry-standard Python security linter) run against all three source files.
2. **Manual review** — line-by-line inspection focused on input validation, resource management, and privilege boundaries, since this tool parses untrusted network data while running as root.
3. **Proof of concept** — every finding below was reproduced with a runnable test before being reported, and every fix was re-tested afterward to confirm it actually resolves the issue without breaking existing behavior.

## Summary

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Unhandled parsing exceptions crash the sniffer on malformed input | **High** | Fixed |
| 2 | Unbounded memory growth in detection state (`PortScanDetector`, `TLSRecordTracker`) | **Medium** | Fixed |
| 3 | Entire tool requires root, widening the impact of any bug | **Medium** | Documented (design constraint) |
| 4 | Credential-detection pattern is easily missed/evaded | **Low** | Documented |
| 5 | `--pcap` output path is unvalidated | **Low** | Documented |

Bandit itself reported **zero issues** across 490 lines — expected, since this codebase doesn't touch the classic patterns Bandit checks for (`eval`, `subprocess`, hardcoded secrets, weak crypto, etc.). That result is included for completeness, but a clean Bandit run does not mean a clean audit: the real findings here are logic-level issues specific to a packet parser, which static analysis tools generally can't detect.

---

## Finding 1 — Unhandled parsing exceptions (High)

**File:** `raw_sniffer.py`
**Type:** CWE-20 (Improper Input Validation) → Denial of Service

### The problem

`raw_sniffer.py` reads raw bytes directly off the network with `recvfrom()` and immediately unpacks them with fixed-size `struct.unpack()` calls (`unpack_ethernet`, `unpack_ipv4`, `unpack_tcp`, etc.). None of these were length-checked, and the only exception handler in the whole program (`except KeyboardInterrupt`) doesn't catch parsing errors.

**Why it matters:** this program runs as root (a raw socket requires it) and processes packets from *any* device that can reach it on the network segment — packets it has no control over and did not request. A single truncated or malformed frame is enough to end the process.

### Proof

```python
>>> import raw_sniffer
>>> raw_sniffer.unpack_ethernet(b'\x00\x01\x02\x03\x04')  # 5 bytes, needs 14
struct.error: unpack requires a buffer of 14 bytes
```

This crashed the entire sniffer with no handling anywhere in the call stack — confirmed by tracing the exception up through `main()`.

### Fix

Wrapped each parsing stage (Ethernet, IPv4, transport-layer) in its own `try/except struct.error`, printing a warning and `continue`-ing to the next packet instead of letting the exception propagate and kill the process.

```python
try:
    eth_proto, dest_mac, src_mac, eth_data = unpack_ethernet(raw_data)
except struct.error:
    print("[!] Skipped a malformed/truncated Ethernet frame")
    continue
```
(Same pattern applied at the IPv4 and transport-layer stages.)

### Verification

Re-ran `main()` end-to-end with a mocked socket feeding it the same malformed packet followed by a valid one: the malformed packet was skipped with a warning, and the program continued processing the next packet normally. No crash.

---

## Finding 2 — Unbounded memory growth in detection state (Medium)

**File:** `utils.py`
**Type:** CWE-400 (Uncontrolled Resource Consumption)

### The problem

`PortScanDetector` and `TLSRecordTracker` both keep a dictionary keyed by source IP / connection tuple, and neither ever removed old entries. On a long-running capture — or facing an attacker who opens many short-lived connections or spoofs many source addresses — these dictionaries grow without limit, eventually exhausting memory on a tool meant to run continuously in the background.

### Proof

```python
det = PortScanDetector()
for i in range(500):
    det.check(<SYN packet from a unique fake source IP>)
len(det._syn_ports)  # -> 500, and climbing forever with no cap
```

### Fix

Converted both dictionaries to `collections.OrderedDict` with a hard cap (`MAX_TRACKED_HOSTS` / `MAX_TRACKED_CONNECTIONS`, default 5000). Every access moves the entry to the "most recently used" end; once the cap is exceeded, the least-recently-used entry is evicted. This bounds memory while keeping the entries that matter (active/recent hosts) — a standard LRU eviction pattern.

### Verification

- With the cap artificially lowered to 100 for a fast test, feeding 500 distinct hosts left exactly 100 tracked — confirmed bounded.
- Re-ran the original port-scan detection test (10 SYNs from one host) and the original multi-packet TLS false-positive regression test — both still pass, confirming the fix didn't change existing behavior for legitimate traffic.

---

## Finding 3 — Root privilege widens blast radius (Medium, design constraint)

**Files:** `main.py`, `raw_sniffer.py`

Both sniffer implementations require root to open a raw socket — this is unavoidable for the tool's core purpose, not a coding mistake. It's flagged here because it changes the *severity* of any other bug: Finding 1, for example, would only be a minor annoyance in an unprivileged script, but as a crash in a root process it's a more meaningful denial-of-service.

**Recommendation:** no code change needed, but worth stating explicitly in documentation (already partially covered in the README) that this tool should only be run for the duration of active investigation, not left running persistently as root, and that `--pcap` output should be reviewed before sharing (see Finding 5).

## Finding 4 — Credential detection is pattern-shallow (Low)

**File:** `utils.py` — `check_plaintext_credentials()`

The check matches literal byte sequences (`password=`, `login=`, etc.), which catches classic URL-encoded form submissions but misses common real-world formats: JSON bodies (`"password":"..."`), Basic-Auth headers (base64-encoded, won't match at all), and any credential field name not in the fixed list (`pass`, `pwd`, `secret`, `token`, `api_key`, etc.).

**Recommendation:** this is a teaching-level heuristic and documented as such in the README already; if extended for more serious use, widen the keyword list and add a JSON-aware check (parse payloads that look like JSON and inspect keys, rather than raw substring matching).

## Finding 5 — `--pcap` output path is unvalidated (Low)

**File:** `main.py`

`PcapWriter(args.pcap, ...)` passes the user-supplied filename straight through with no validation. Since this is a CLI tool the user runs against their own machine with sudo they already invoked, this isn't a privilege-escalation path (the user already has root) — but it's worth noting as a defense-in-depth gap: no check prevents accidentally overwriting an unintended file, and no confirmation prompt exists if the target path already contains a capture.

**Recommendation:** consider adding a check for an existing file at the target path and prompting before overwrite, since `append=False` currently overwrites silently.

---

## Recommendations for future secure-coding practice

1. **Never trust network input, even at the parsing level.** Every `struct.unpack()` against externally-supplied bytes needs a length/format check or a `try/except` — Finding 1 is the single most important lesson from this review.
2. **Any long-lived in-memory state needs a bound.** If a dictionary is keyed by something an outside party can influence (an IP, a connection tuple), it needs an eviction policy from the start, not added later.
3. **Root/elevated-privilege tools deserve stricter error handling than user-space scripts**, because the cost of a crash or resource exhaustion is higher.
4. **A clean static-analyzer run is necessary but not sufficient.** Bandit found nothing here, yet the two most important findings in this report were both logic-level issues a linter can't see. Manual review, especially of code that parses untrusted bytes, remains essential.

## Files changed

- `raw_sniffer.py` — added per-stage exception handling around all `struct.unpack` calls (Finding 1)
- `utils.py` — bounded `PortScanDetector` and `TLSRecordTracker` state with LRU eviction (Finding 2)