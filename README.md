# Hollowing & Injection Detector

A user-mode Windows security tool, written in C++, that inspects every running process on a machine and asks a single question: **is the code executing inside this process the same code that was loaded from disk?**

Windows binds a process's identity to a file on disk at creation time, but its behaviour comes from bytes in memory — and nothing re-checks that those two still agree. Process hollowing exploits exactly this gap. An attacker launches a legitimate executable suspended, unmaps its image from memory, writes a payload into the space it occupied, redirects the thread, and resumes. Task Manager still reports `svchost.exe`. The file on disk is genuinely Microsoft's, genuinely signed, byte-for-byte untouched. Only the memory was replaced.

This tool refuses to trust a process's self-description. It reads the PE headers out of live memory, independently parses the same headers from the file on disk, and reports where they disagree.

## Detection strategies

Two independent sweeps, deliberately overlapping as little as possible:

**Header comparison.** For each process, locate the image base via the PEB, parse the in-memory PE headers, parse the on-disk headers, and compare entry point RVA, `SizeOfImage`, section count, and section names. A missing MZ or PE signature at the image base is the loudest possible signal — it means a loader unmapped the original image and never reconstructed a plausible header.

**Page protection sweep.** Walk every committed memory region and flag any page that is simultaneously writable and executable. Compiled code never needs that combination; injected payloads frequently have it, because the allocating loader took the shortcut of `PAGE_EXECUTE_READWRITE`.

Neither is sufficient alone. Header comparison catches full hollowing but is blind to shellcode injected into an otherwise intact process. The protection sweep catches that injection but says nothing about a careful hollowing loader that restored plausible headers and correct page protections. Together they cover substantially more of the attack surface.

The tool reports **graded severities, not a binary verdict**, because most differences it finds are legitimate. ASLR relocates nearly every modern binary. Packers unpack themselves at runtime. JIT runtimes allocate writable-executable memory as a matter of course. A tool that calls these attacks is a tool nobody runs twice.

---

## Code flow

```
main()
  │
  ├─ PrivilegeManager::EnablePrivilege(SE_DEBUG_NAME)   acquire access, once
  ├─ PrivilegeManager::IsElevated()                     record it for the report
  │
  ├─ ProcessEnumerator::Enumerate()                     → vector<ProcessInfo>
  │
  └─ for each ProcessInfo:  DetectionEngine::AnalyzeProcess()
        │
        ├─ OpenProcess(QUERY_LIMITED_INFORMATION | VM_READ)  → ScopedHandle
        │     └─ on failure: count as inaccessible, continue
        │
        ├─ LiveImage::Load(handle)          headers as they exist in memory
        │     └─ RemoteMemory               every cross-process read goes through here
        │
        ├─ DiskImage::Load(imagePath)       headers as they exist on disk
        │
        ├─ CompareHeaders(live, disk)       → Findings   (entry point, size, sections)
        │
        ├─ RegionScanner::Scan(handle)      → vector<SuspiciousRegion>
        └─ EvaluateRegions(regions)         → Findings   (WX pages, JIT suppressed)
        
  └─ ConsoleReporter                        sort by severity, print, export JSON
```

Every layer below `DetectionEngine` reports facts. `DetectionEngine` is the only component permitted to decide that a fact is suspicious. `ConsoleReporter` is the only component that knows a human exists.

---

## Components

### `core/`

**`ScopedHandle`** — Ownership of exactly one Win32 kernel handle, expressed so the compiler enforces cleanup. Movable but not copyable: a handle may be transferred but never duplicated, since two owners means two `CloseHandle` calls on the same value. Holds a single raw handle and nothing else. Rejects both failure sentinels — `nullptr` (from `OpenProcess`) and `INVALID_HANDLE_VALUE` (from `CreateFileW` and `CreateToolhelp32Snapshot`).

**`Logger`** — The diagnostic channel, separate from the reporter: the logger is for debugging, the reporter is for results. Holds a severity threshold and filters on it before doing any formatting work — a full scan produces enormous volumes of legitimately boring output (unreadable pages, access-denied processes) that must be switchable off at runtime rather than deleted from the code.

**`Types.h`** — Vocabulary shared across layers: `Level`, `Severity`, `ProcessInfo`, `SuspiciousRegion`, `Finding`. Exists so `scan/` can name a `Finding` without including anything from `system/`.

### `system/`

**`PrivilegeManager`** — The only component that acts on *this* process rather than a target. It exists because a scanner's reach is determined entirely by its own access token, and that token is the only one it can modify. `EnablePrivilege` switches on `SE_DEBUG_NAME`, which is present-but-disabled in an elevated token and absent altogether from a UAC-filtered one. `IsElevated` reports which situation applies, so a clean scan can be qualified honestly rather than mistaken for a clean machine. Stateless; both operations are static.

**`ProcessEnumerator`** — The guest list. Turns "the machine is running things" into an iterable set of targets, each carrying its claimed identity: PID, parent PID, image name, and full disk path. It collects claims and never evaluates them — the rest of the tool exists precisely because those claims can be false. Path resolution uses `QueryFullProcessImageNameW`, which works across the 32/64-bit boundary and needs only `PROCESS_QUERY_LIMITED_INFORMATION`.

**`RemoteMemory`** — A narrow, checked window into another process's address space, and the single place a cross-process read happens. Offers a raw read, a templated typed read returning an optional, and a runtime-sized buffer read. Holds a **non-owning** process handle — several objects read from one process during a single analysis, so ownership stays with the caller. Treats a partial read as failure: a short read that goes unchecked produces a half-filled header full of stack garbage and a confident, entirely fabricated finding.

### `pe/`

**`LiveImage`** — What the process says about itself: the PE header chain as it exists in memory right now. Finds the image base through `NtQueryInformationProcess` (resolved manually from `ntdll.dll`, since it appears in no import library) → `PebBaseAddress` → `ImageBaseAddress`. Records signature validity in a flag rather than failing on it, because a missing MZ is not an error condition — it is the strongest detection the tool can produce, and treating it as a load failure makes a fully hollowed process invisible.

**`DiskImage`** — Ground truth: the same headers, parsed from the file the process was launched from. Maps the file read-only with read sharing (the file is executing, so sharing is mandatory) and exposes the same accessors as `LiveImage` so the comparison can be written once. Also owns `RvaToFileOffset` — sections are padded to `FileAlignment` on disk and `SectionAlignment` in memory, so the two layouts are not linearly related and every RVA must be translated through its containing section.

### `scan/`

**`RegionScanner`** — A walk of the entire user address space that ignores content and asks only about permissions. Iterates `VirtualQueryEx` from address zero, flagging committed regions whose protection includes both write and execute. Records whether each region is image-backed or private: private executable memory is far more suspicious than image-backed, since legitimate code is normally mapped from a file. Pure function over a handle; holds no state.

**`Finding`** — One claim the tool is making, in a form a human can act on. Carries a stable rule identifier (`ENTRYPOINT_MISMATCH`) for grepping and aggregation, *and* concrete evidence with real numbers (`disk EP 0x1240, memory EP 0x8A00`) for convincing a sceptic. A finding with only the first is unactionable; with only the second, unsearchable. A citation, not a verdict.

**`DetectionEngine`** — The judgment layer, and the only place an observation becomes an accusation. The technician measures; the doctor diagnoses. Keeping the two separate means the severity model can be retuned without touching a line that talks to Windows. Holds the enumerator, the JIT suppression list loaded from config, and the scanned / skipped / inaccessible counters — which are output, not bookkeeping.

### `report/`

**`ConsoleReporter`** — The boundary between the tool and whoever consumes it: a human with two seconds of attention, or a pipeline with none. Sorts descending by severity, colours accordingly, exports JSON, and always prints the census line. `Scanned 214, skipped 6, inaccessible 41` is more honest and more useful than `Scan complete` — a reader told that 41 processes were unreadable can re-run elevated; a reader not told assumes the clean result covered everything.

---

## Detection rules

| Rule | Condition | Severity |
|---|---|---|
| `DOS_SIGNATURE_MISSING` | No MZ magic at the live image base | Critical |
| `PE_SIGNATURE_MISSING` | No PE signature at `e_lfanew` | Critical |
| `ENTRYPOINT_MISMATCH` | Live and disk `AddressOfEntryPoint` differ | High |
| `SIZEOFIMAGE_MISMATCH` | Live and disk `SizeOfImage` differ | High |
| `SECTION_COUNT_MISMATCH` | Section counts differ | High |
| `SECTION_NAME_MISMATCH` | Section names differ in order | Medium |
| `WX_PRIVATE_REGION` | Committed private region, writable and executable | Medium |
| `WX_IMAGE_REGION` | Committed image-backed region, writable and executable | Low |

`ImageBase` is deliberately **not** compared. ASLR relocates nearly every modern binary, so that comparison flags the entire system. RVAs are base-independent and therefore correct under relocation.

---

## Known limitations

1. **User-mode only.** A kernel driver hides from this tool entirely.
2. **Hookable.** An attacker who hooks the read path inside this process can feed it clean data. Direct syscalls mitigate but do not solve this.
3. **Race conditions.** The scan is a point-in-time snapshot; memory can change mid-scan.
4. **Packers and self-modifying code** produce legitimate mismatches by design.
5. **JIT runtimes** legitimately allocate writable-executable memory.
6. **Manual mapping.** An attacker who never touches the PEB module list evades header comparison entirely — though the protection sweep may still catch them.
7. **No signature verification.** An attacker who replaces the file on disk makes memory and disk agree while both are malicious. Authenticode checking is the natural extension.
8. **Protected processes.** Some processes (`lsass.exe` under Credential Guard, AV services) refuse `PROCESS_VM_READ` from user mode regardless of privilege. These appear in the inaccessible count and that is correct behaviour, not a bug.

Limitation 7 is the load-bearing one: the entire design rests on the file on disk being trustworthy. That is an assumption inherited from the threat model, not a property of the system.

---

## Building

Windows only. Requires the Windows SDK; 64-bit targets only (32-bit support would need `IsWow64Process` and a parallel `IMAGE_NT_HEADERS32` path).

Run elevated for meaningful results — without `SE_DEBUG`, most processes will be inaccessible and a clean report means nothing.

## Status

Work in progress. See the build order in the project blueprint for the intended sequence.
