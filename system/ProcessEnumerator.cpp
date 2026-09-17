#include "ProcessEnumerator.h"
#include "ScopedHandle.h"
#include "windows.h"
#include <tlhelp32.h> 
#include "Logger.h"
#include "ProcessInfo.h"

std::vector<ProcessInfo> ProcessEnumerator::enumerate() {
    std::vector<ProcessInfo> results;

    ScopedHandle snap( CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) );
    if (!snap.valid()) {
        DWORD e = GetLastError();
        Logger::getInstance()->log(Level::FAILED, "CreateToolhelp32Snapshot failed. Error: " + std::to_string(e));
        return results;   // empty
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);          // <-- do NOT forget this

    if (Process32FirstW(snap.GetHandle(), &entry)) {
        do {
            ProcessInfo info(entry.th32ProcessID,entry.th32ParentProcessID,entry.szExeFile,L"");
            std::optional<std::wstring> pathOptional=resolvePath(info.getProcessId());
            if(pathOptional.has_value()) {
                info.setPath(pathOptional.value());
            }
            // path resolution comes in step 2
            results.push_back(info);
        } while (Process32NextW(snap.GetHandle(), &entry));
    }

    return results;
}

std::optional<std::wstring> ProcessEnumerator::resolvePath(DWORD pid) {
    ScopedHandle proc( OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) );
    if (!proc.valid())
        return std::nullopt;

    wchar_t buffer[MAX_PATH];
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(proc.GetHandle(), 0, buffer, &size))
        return std::nullopt;

    return std::wstring(buffer, size);
}