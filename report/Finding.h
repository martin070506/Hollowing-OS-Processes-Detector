#pragma once
#include <string>
#include <cstdint>
#include <windows.h>

enum class Severity { Info = 0, Low, Medium, High, Critical };

inline const char* severityName(Severity s) {
    switch (s) {
        case Severity::Info:     return "INFO";
        case Severity::Low:      return "LOW";
        case Severity::Medium:   return "MEDIUM";
        case Severity::High:     return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

struct Finding {
    DWORD        pid = 0;
    std::wstring processName;
    Severity     severity = Severity::Info;
    std::string  ruleId;     // machine-readable, e.g. "ENTRYPOINT_MISMATCH"
    std::string  message;    // human sentence
    std::string  evidence;   // concrete numbers, e.g. "disk EP 0x1240, memory EP 0x8A00"
};