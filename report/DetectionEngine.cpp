#include "DetectionEngine.h"
#include "../scan/RegionScanner.h"
#include "../core/ScopedHandle.h"
#include <sstream>
#include <cstring>
#include <cwctype>

// ---- small local helpers ----
static std::string hex(uint64_t v) {
    std::ostringstream o;
    o << std::hex << v;
    return o.str();
}

static Finding make(const ProcessInfo& info, Severity sev, const char* rule,
                    const std::string& msg, const std::string& ev) {
    Finding f;
    f.pid         = info.getProcessId();
    f.processName = info.getExecutableName();
    f.severity    = sev;
    f.ruleId      = rule;
    f.message     = msg;
    f.evidence    = ev;
    return f;
}

static std::wstring toLower(std::wstring s) {
    for (auto& c : s) c = towlower(c);
    return s;
}

// ---- construction: load the JIT suppression list ----
DetectionEngine::DetectionEngine() {
    // TODO: load these from a config file instead of hardcoding.
    for (const wchar_t* name : { L"chrome.exe", L"msedge.exe", L"firefox.exe",
                                 L"node.exe", L"dotnet.exe", L"java.exe",
                                 L"javaw.exe", L"code.exe" }) {
        _jitProcesses.insert(name);
    }
}

bool DetectionEngine::isJitProcess(const std::wstring& name) const {
    return _jitProcesses.count(toLower(name)) > 0;
}

// ---- analyse one process ----
std::vector<Finding> DetectionEngine::analyzeProcess(const ProcessInfo& info) {
    std::vector<Finding> findings;
    _scanned++;

    // NOTE: VirtualQueryEx may need PROCESS_QUERY_INFORMATION on some systems;
    // if the region scan comes back empty everywhere, widen this mask.
    ScopedHandle proc( OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                   FALSE, info.getProcessId()) );
    if (!proc.valid()) {
        _inaccessible++;
        return findings;          // can't open it — count and move on
    }

    bool isJit = isJitProcess(info.getExecutableName());

    // --- the live (in-memory) view ---
    LiveImage live(proc.GetHandle());
    if (!live.isLoaded()) {
        // couldn't read the image at all — still worth a region sweep
        RegionScanner scanner(proc.GetHandle());
        evaluateRegions(scanner.scan(), info, isJit, findings);
        return findings;
    }

    if (live.dosMagic() != IMAGE_DOS_SIGNATURE) {
        findings.push_back(make(info, Severity::Critical, "DOS_SIGNATURE_MISSING",
            "No MZ signature at the live image base",
            "live e_magic 0x" + hex(live.dosMagic())));
    }
    else if (live.ntSignature() != IMAGE_NT_SIGNATURE) {
        findings.push_back(make(info, Severity::Critical, "PE_SIGNATURE_MISSING",
            "No PE signature at e_lfanew in memory",
            "live signature 0x" + hex(live.ntSignature())));
    }
    else if (!info.getPath().empty()) {
        // signatures present → compare against the disk ground truth
        DiskImage disk(info.getPath());
        if (disk.isLoaded() && disk.signaturesValid())
            compareHeaders(live, disk, info, findings);
    }

    // --- the region sweep (always runs) ---
    RegionScanner scanner(proc.GetHandle());
    evaluateRegions(scanner.scan(), info, isJit, findings);

    return findings;
}

// ---- compare memory headers against disk headers ----
void DetectionEngine::compareHeaders(const LiveImage& live, const DiskImage& disk,
                                     const ProcessInfo& info, std::vector<Finding>& out) {
    // RVAs, never ImageBase — ASLR makes the base differ legitimately.
    if (live.entryPointRva() != disk.entryPointRva()) {
        out.push_back(make(info, Severity::High, "ENTRYPOINT_MISMATCH",
            "Entry point differs between memory and disk",
            "disk EP 0x" + hex(disk.entryPointRva()) +
            ", memory EP 0x" + hex(live.entryPointRva())));
    }

    if (live.sizeOfImage() != disk.sizeOfImage()) {
        out.push_back(make(info, Severity::High, "SIZEOFIMAGE_MISMATCH",
            "SizeOfImage differs between memory and disk",
            "disk 0x" + hex(disk.sizeOfImage()) +
            ", memory 0x" + hex(live.sizeOfImage())));
    }

    const auto& ls = live.sections();
    const auto& ds = disk.sections();
    if (ls.size() != ds.size()) {
        out.push_back(make(info, Severity::High, "SECTION_COUNT_MISMATCH",
            "Section count differs between memory and disk",
            "disk " + std::to_string(ds.size()) +
            ", memory " + std::to_string(ls.size())));
    }
    else {
        for (size_t i = 0; i < ls.size(); ++i) {
            // Names are 8 raw bytes — compare the fixed 8, not as strings.
            if (std::memcmp(ls[i].Name, ds[i].Name, 8) != 0) {
                out.push_back(make(info, Severity::Medium, "SECTION_NAME_MISMATCH",
                    "Section names differ in order between memory and disk",
                    "at section index " + std::to_string(i)));
                break;   // one finding is enough to flag it
            }
        }
    }
}

// ---- judge the WX regions ----
void DetectionEngine::evaluateRegions(const std::vector<SuspiciousRegion>& regions,
                                      const ProcessInfo& info, bool isJit,
                                      std::vector<Finding>& out) {
    if (isJit) return;   // known JIT process — WX is normal, suppress

    for (const auto& r : regions) {
        uint64_t base = reinterpret_cast<uint64_t>(r.baseAddress);
        if (r.isPrivate) {
            out.push_back(make(info, Severity::Medium, "WX_PRIVATE_REGION",
                "Committed private memory is writable and executable",
                "base 0x" + hex(base) + ", size " + std::to_string(r.regionSize)));
        } else {
            out.push_back(make(info, Severity::Low, "WX_IMAGE_REGION",
                "Committed image-backed memory is writable and executable",
                "base 0x" + hex(base) + ", size " + std::to_string(r.regionSize)));
        }
    }
}

// ---- drive the whole scan ----
std::vector<Finding> DetectionEngine::analyzeAll() {
    std::vector<Finding> all;
    for (const auto& info : _enumerator.enumerate()) {
        auto f = analyzeProcess(info);
        all.insert(all.end(), f.begin(), f.end());
    }
    return all;
}