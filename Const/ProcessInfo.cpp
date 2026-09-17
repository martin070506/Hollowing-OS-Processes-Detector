#include "ProcessInfo.h"

ProcessInfo::ProcessInfo(DWORD processId, DWORD parentProcessId,  const std::wstring& executableName,  const std::wstring& path)
    : processId_(processId), parentProcessId_(parentProcessId), executableName_(executableName), path_(path) {}


void ProcessInfo::setPath(const std::wstring& path){
    path_=path;
}

DWORD ProcessInfo::getProcessId()  {
    return processId_;
}

DWORD ProcessInfo::getParentProcessId() {
    return parentProcessId_;
}

 const std::wstring& ProcessInfo::getExecutableName()  {
    return executableName_;
}

 const std::wstring& ProcessInfo::getPath()  {
    return path_;
}

