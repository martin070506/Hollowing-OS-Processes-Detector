#pragma once
#include <iostream>
#include "windows.h"
#include <string>
class ProcessInfo {
    private:
        int processId_;
        int parentProcessId_;
        std::wstring executableName_;
        std::wstring path_;

    public:
        ProcessInfo()=default;
        ProcessInfo(DWORD processId, DWORD parentProcessId,   const std::wstring& executableName,  const std::wstring& path);
        DWORD getProcessId() ;
        DWORD getParentProcessId()  ;
        const std::wstring& getExecutableName();
        const std::wstring& getPath() ;
        void setPath(const std::wstring& path);


};