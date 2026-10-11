#pragma once
#include <windows.h>
#include <string>

class ProcessInfo {
private:
    DWORD processId_ = 0;
    DWORD parentProcessId_ = 0;
    std::wstring executableName_;
    std::wstring path_;

public:
    ProcessInfo() = default;
    ProcessInfo(DWORD processId, DWORD parentProcessId,
                const std::wstring& executableName, const std::wstring& path);

    DWORD getProcessId()               const;   
    DWORD getParentProcessId()         const;
    const std::wstring& getExecutableName() const;
    const std::wstring& getPath()      const;
    void setPath(const std::wstring& path);     
};